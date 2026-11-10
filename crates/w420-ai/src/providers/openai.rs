//! OpenAI провайдер: GPT-4o, GPT-4, GPT-3.5 Turbo и др.
//!
//! API документация: https://platform.openai.com/docs/api-reference
//! Эндпоинт: https://api.openai.com/v1
//! Аутентификация: Bearer токен в заголовке `Authorization: Bearer <key>`
//! Формат запроса: OpenAI-совместимый (стандарт индустрии)

use crate::{
    AIError, AIProvider, ChatRequest, ChatResponse, LatencyResult, ProviderType,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, error, warn};

/// OpenAI чат-запрос (нативный формат провайдера).
#[derive(Serialize)]
struct OpenAIChatRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(default)]
    stream: bool,
}

/// Сообщение в формате OpenAI.
#[derive(Serialize, Deserialize)]
struct OpenAIMessage {
    role: String,
    content: String,
}

/// Ответ от OpenAI API.
#[derive(Deserialize)]
struct OpenAIChatResponse {
    id: String,
    object: String,
    created: u64,
    model: String,
    choices: Vec<OpenAIChoice>,
    #[serde(default)]
    usage: Option<OpenAIUsage>,
}

/// Один вариант ответа.
#[derive(Deserialize)]
struct OpenAIChoice {
    index: u32,
    message: OpenAIMessage,
    finish_reason: Option<String>,
}

/// Информация об использовании токенов.
#[derive(Deserialize, Default)]
struct OpenAIUsage {
    prompt_tokens: Option<u32>,
    completion_tokens: Option<u32>,
    total_tokens: Option<u32>,
}

/// Ошибка от OpenAI API.
#[derive(Deserialize)]
struct OpenAIErrorResponse {
    error: OpenAIErrorDetail,
}

#[derive(Deserialize)]
struct OpenAIErrorDetail {
    message: String,
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    code: Option<String>,
}

/// Реализация провайдера OpenAI.
#[derive(Debug, Clone)]
pub struct OpenAIProvider {
    client: Client,
    endpoint: String,
}

impl OpenAIProvider {
    /// Создаёт новый экземпляр провайдера OpenAI.
    ///
    /// `endpoint` — базовый URL API (обычно https://api.openai.com/v1).
    pub fn new(endpoint: &str) -> Self {
        Self {
            client: Client::new(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
        }
    }

    /// Формирует полный URL для чат-запроса.
    fn chat_url(&self) -> String {
        format!("{}/chat/completions", self.endpoint)
    }

    /// Преобразует унифицированный ChatRequest в формат OpenAI.
    fn to_openai_request(req: ChatRequest) -> OpenAIChatRequest {
        OpenAIChatRequest {
            model: req.model,
            messages: req
                .messages
                .into_iter()
                .map(|m| OpenAIMessage {
                    role: m.role,
                    content: m.content,
                })
                .collect(),
            temperature: req.temperature,
            max_tokens: req.max_tokens,
            stream: req.stream,
        }
    }

    /// Преобразует ответ OpenAI в унифицированный ChatResponse.
    fn from_openai_response(
        provider: &str,
        resp: OpenAIChatResponse,
        latency_ms: u64,
    ) -> ChatResponse {
        let content = resp
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        let tokens_used = resp.usage.and_then(|u| u.total_tokens);

        ChatResponse {
            content,
            model: resp.model,
            provider: provider.to_string(),
            tokens_used,
            latency_ms,
        }
    }

    /// Обрабатывает HTTP-ответ от OpenAI: проверяет статус, парсит JSON или ошибку.
    async fn handle_response(
        provider: &str,
        status: reqwest::StatusCode,
        text: String,
    ) -> Result<OpenAIChatResponse, AIError> {
        if status.is_success() {
            serde_json::from_str(&text).map_err(|e| AIError::Parse {
                provider: provider.to_string(),
                message: format!("не удалось распарсить ответ: {e}"),
            })
        } else {
            // Пытаемся извлечь сообщение об ошибке из тела ответа
            let error_detail: Result<OpenAIErrorResponse, _> = serde_json::from_str(&text);
            let message = match error_detail {
                Ok(e) => e.error.message,
                Err(_) => text.clone(),
            };
            Err(AIError::Http {
                provider: provider.to_string(),
                status: Some(status.as_u16().to_string()),
                message,
            })
        }
    }
}

impl AIProvider for OpenAIProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::OpenAI
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn chat_completion(
        &self,
        api_key: &str,
        request: ChatRequest,
    ) -> Result<ChatResponse, AIError> {
        let provider_name = "OpenAI";
        let url = self.chat_url();
        let start = Instant::now();

        debug!("OpenAI chat completion: model={}, messages={}", request.model, request.messages.len());

        let openai_req = Self::to_openai_request(request);

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&openai_req)
            .send()
            .await
            .map_err(|e| AIError::Http {
                provider: provider_name.to_string(),
                status: None,
                message: format!("сетевая ошибка: {e}"),
            })?;

        let status = resp.status();
        let text = resp.text().await.map_err(|e| AIError::Http {
            provider: provider_name.to_string(),
            status: Some(status.as_u16().to_string()),
            message: format!("ошибка чтения тела ответа: {e}"),
        })?;

        let openai_resp = Self::handle_response(provider_name, status, text).await?;
        let latency_ms = start.elapsed().as_millis() as u64;

        Ok(Self::from_openai_response(provider_name, openai_resp, latency_ms))
    }

    async fn test_connection(&self, api_key: &str) -> Result<LatencyResult, AIError> {
        let provider_name = "OpenAI";
        let start = Instant::now();

        // Тестовый запрос с минимальной моделью и коротким текстом
        let test_req = ChatRequest {
            messages: vec![crate::ChatMessage {
                role: "user".to_string(),
                content: "ping".to_string(),
            }],
            model: "gpt-3.5-turbo".to_string(),
            temperature: 0.0,
            max_tokens: Some(5),
            stream: false,
        };

        match self.chat_completion(api_key, test_req).await {
            Ok(resp) => {
                let latency_ms = start.elapsed().as_millis() as u64;
                Ok(LatencyResult {
                    provider: provider_name.to_string(),
                    key_id: "test".to_string(),
                    latency_ms,
                    success: true,
                    error_message: None,
                })
            }
            Err(e) => {
                let latency_ms = start.elapsed().as_millis() as u64;
                error!("OpenAI тест соединения не пройден: {e}");
                Ok(LatencyResult {
                    provider: provider_name.to_string(),
                    key_id: "test".to_string(),
                    latency_ms,
                    success: false,
                    error_message: Some(e.to_string()),
                })
            }
        }
    }

    async fn list_models(&self, _api_key: &str) -> Result<Vec<String>, AIError> {
        // OpenAI поддерживает список моделей через GET /v1/models
        // Здесь возвращаем наиболее распространённые модели как стартовый список
        Ok(vec![
            "gpt-4o".to_string(),
            "gpt-4o-mini".to_string(),
            "gpt-4-turbo".to_string(),
            "gpt-4".to_string(),
            "gpt-3.5-turbo".to_string(),
        ])
    }
}

impl Default for OpenAIProvider {
    fn default() -> Self {
        Self::new("https://api.openai.com/v1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_type_display() {
        assert_eq!(ProviderType::OpenAI.to_string(), "OpenAI");
    }

    #[test]
    fn test_default_endpoint() {
        assert_eq!(
            ProviderType::OpenAI.default_endpoint(),
            Some("https://api.openai.com/v1")
        );
    }

    #[test]
    fn test_chat_request_defaults() {
        let req = ChatRequest {
            messages: vec![crate::ChatMessage {
                role: "user".to_string(),
                content: "test".to_string(),
            }],
            model: "gpt-4o".to_string(),
            temperature: 0.0,
            max_tokens: None,
            stream: false,
        };
        assert_eq!(req.model, "gpt-4o");
        assert_eq!(req.messages.len(), 1);
    }
}

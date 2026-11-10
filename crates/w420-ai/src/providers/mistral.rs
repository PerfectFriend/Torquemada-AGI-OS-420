//! Mistral AI провайдер: Mistral Large, Mistral Nemo, Codestral.
//!
//! API документация: https://docs.mistral.ai
//! Эндпоинт: https://api.mistral.ai/v1
//! Аутентификация: Bearer токен в заголовке Authorization
//! Формат запроса: OpenAI-совместимый (chat/completions)

use crate::{
    AIError, AIProvider, ChatRequest, ChatResponse, LatencyResult, ProviderType,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, error};

// Mistral использует тот же формат запроса/ответа, что и OpenAI,
// поэтому мы переиспользуем структуры из openai.rs через повторное определение
// (чтобы не создавать циклических зависимостей между модулями провайдеров).

#[derive(Serialize)]
struct MistralChatRequest {
    model: String,
    messages: Vec<MistralMessage>,
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(default)]
    stream: bool,
}

#[derive(Serialize, Deserialize)]
struct MistralMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct MistralChatResponse {
    id: String,
    object: String,
    created: u64,
    model: String,
    choices: Vec<MistralChoice>,
    #[serde(default)]
    usage: Option<MistralUsage>,
}

#[derive(Deserialize)]
struct MistralChoice {
    index: u32,
    message: MistralMessage,
    finish_reason: Option<String>,
}

#[derive(Deserialize, Default)]
struct MistralUsage {
    prompt_tokens: Option<u32>,
    completion_tokens: Option<u32>,
    total_tokens: Option<u32>,
}

#[derive(Deserialize)]
struct MistralErrorResponse {
    error: MistralErrorDetail,
}

#[derive(Deserialize)]
struct MistralErrorDetail {
    message: String,
    #[serde(default)]
    r#type: String,
}

#[derive(Debug, Clone)]
pub struct MistralProvider {
    client: Client,
    endpoint: String,
}

impl MistralProvider {
    pub fn new(endpoint: &str) -> Self {
        Self {
            client: Client::new(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
        }
    }

    fn chat_url(&self) -> String {
        format!("{}/chat/completions", self.endpoint)
    }

    fn to_mistral_request(req: ChatRequest) -> MistralChatRequest {
        MistralChatRequest {
            model: req.model,
            messages: req
                .messages
                .into_iter()
                .map(|m| MistralMessage {
                    role: m.role,
                    content: m.content,
                })
                .collect(),
            temperature: req.temperature,
            max_tokens: req.max_tokens,
            stream: req.stream,
        }
    }

    fn from_mistral_response(
        provider: &str,
        resp: MistralChatResponse,
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

    async fn handle_response(
        provider: &str,
        status: reqwest::StatusCode,
        text: String,
    ) -> Result<MistralChatResponse, AIError> {
        if status.is_success() {
            serde_json::from_str(&text).map_err(|e| AIError::Parse {
                provider: provider.to_string(),
                message: format!("не удалось распарсить ответ: {e}"),
            })
        } else {
            let error_detail: Result<MistralErrorResponse, _> = serde_json::from_str(&text);
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

impl AIProvider for MistralProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Mistral
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn chat_completion(
        &self,
        api_key: &str,
        request: ChatRequest,
    ) -> Result<ChatResponse, AIError> {
        let provider_name = "Mistral AI";
        let url = self.chat_url();
        let start = Instant::now();

        debug!("Mistral chat completion: model={}", request.model);

        let mistral_req = Self::to_mistral_request(request);

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&mistral_req)
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

        let mistral_resp = Self::handle_response(provider_name, status, text).await?;
        let latency_ms = start.elapsed().as_millis() as u64;

        Ok(Self::from_mistral_response(
            provider_name,
            mistral_resp,
            latency_ms,
        ))
    }

    async fn test_connection(&self, api_key: &str) -> Result<LatencyResult, AIError> {
        let provider_name = "Mistral AI";
        let start = Instant::now();

        let test_req = ChatRequest {
            messages: vec![crate::ChatMessage {
                role: "user".to_string(),
                content: "ping".to_string(),
            }],
            model: "mistral-small-latest".to_string(),
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
                error!("Mistral тест соединения не пройден: {e}");
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
        Ok(vec![
            "mistral-large-latest".to_string(),
            "mistral-small-latest".to_string(),
            "mistral-embed".to_string(),
            "codestral-latest".to_string(),
        ])
    }
}

impl Default for MistralProvider {
    fn default() -> Self {
        Self::new("https://api.mistral.ai/v1")
    }
}

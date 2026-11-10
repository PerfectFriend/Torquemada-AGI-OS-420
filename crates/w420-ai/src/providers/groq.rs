//! Groq провайдер: быстрый инференс Llama, Mixtral, Gemma.
//!
//! API документация: https://console.groq.com/docs
//! Эндпоинт: https://api.groq.com/openai/v1
//! Аутентификация: Bearer токен в заголовке Authorization
//! Формат запроса: OpenAI-совместимый (chat/completions)

use crate::{
    AIError, AIProvider, ChatRequest, ChatResponse, LatencyResult, ProviderType,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, error};

// Groq использует OpenAI-совместимый формат запроса/ответа.

#[derive(Serialize)]
struct GroqChatRequest {
    model: String,
    messages: Vec<GroqMessage>,
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(default)]
    stream: bool,
}

#[derive(Serialize, Deserialize)]
struct GroqMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct GroqChatResponse {
    id: String,
    object: String,
    created: u64,
    model: String,
    choices: Vec<GroqChoice>,
    #[serde(default)]
    usage: Option<GroqUsage>,
}

#[derive(Deserialize)]
struct GroqChoice {
    index: u32,
    message: GroqMessage,
    finish_reason: Option<String>,
}

#[derive(Deserialize, Default)]
struct GroqUsage {
    prompt_tokens: Option<u32>,
    completion_tokens: Option<u32>,
    total_tokens: Option<u32>,
}

#[derive(Deserialize)]
struct GroqErrorResponse {
    error: GroqErrorDetail,
}

#[derive(Deserialize)]
struct GroqErrorDetail {
    message: String,
    #[serde(default)]
    r#type: String,
}

#[derive(Debug, Clone)]
pub struct GroqProvider {
    client: Client,
    endpoint: String,
}

impl GroqProvider {
    pub fn new(endpoint: &str) -> Self {
        Self {
            client: Client::new(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
        }
    }

    fn chat_url(&self) -> String {
        format!("{}/chat/completions", self.endpoint)
    }

    fn to_groq_request(req: ChatRequest) -> GroqChatRequest {
        GroqChatRequest {
            model: req.model,
            messages: req
                .messages
                .into_iter()
                .map(|m| GroqMessage {
                    role: m.role,
                    content: m.content,
                })
                .collect(),
            temperature: req.temperature,
            max_tokens: req.max_tokens,
            stream: req.stream,
        }
    }

    fn from_groq_response(
        provider: &str,
        resp: GroqChatResponse,
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
    ) -> Result<GroqChatResponse, AIError> {
        if status.is_success() {
            serde_json::from_str(&text).map_err(|e| AIError::Parse {
                provider: provider.to_string(),
                message: format!("не удалось распарсить ответ: {e}"),
            })
        } else {
            let error_detail: Result<GroqErrorResponse, _> = serde_json::from_str(&text);
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

impl AIProvider for GroqProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Groq
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn chat_completion(
        &self,
        api_key: &str,
        request: ChatRequest,
    ) -> Result<ChatResponse, AIError> {
        let provider_name = "Groq";
        let url = self.chat_url();
        let start = Instant::now();

        debug!("Groq chat completion: model={}", request.model);

        let groq_req = Self::to_groq_request(request);

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&groq_req)
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

        let groq_resp = Self::handle_response(provider_name, status, text).await?;
        let latency_ms = start.elapsed().as_millis() as u64;

        Ok(Self::from_groq_response(provider_name, groq_resp, latency_ms))
    }

    async fn test_connection(&self, api_key: &str) -> Result<LatencyResult, AIError> {
        let provider_name = "Groq";
        let start = Instant::now();

        let test_req = ChatRequest {
            messages: vec![crate::ChatMessage {
                role: "user".to_string(),
                content: "ping".to_string(),
            }],
            model: "llama-3.1-8b-instant".to_string(),
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
                error!("Groq тест соединения не пройден: {e}");
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
            "llama-3.1-8b-instant".to_string(),
            "llama-3.1-70b-versatile".to_string(),
            "llama-3.2-1b-preview".to_string(),
            "llama-3.2-3b-preview".to_string(),
            "mixtral-8x7b-32768".to_string(),
            "gemma2-9b-it".to_string(),
        ])
    }
}

impl Default for GroqProvider {
    fn default() -> Self {
        Self::new("https://api.groq.com/openai/v1")
    }
}

//! Anthropic провайдер: Claude 3.5 Sonnet, Claude 3 Opus, Claude 3 Haiku.
//!
//! API документация: https://docs.anthropic.com
//! Эндпоинт: https://api.anthropic.com/v1
//! Аутентификация: x-api-key заголовок
//! Формат запроса: нативный Anthropic (messages API)

use crate::{
    AIError, AIProvider, ChatRequest, ChatResponse, LatencyResult, ProviderType,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, error};

#[derive(Serialize)]
struct AnthropicChatRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<AnthropicMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct AnthropicChatResponse {
    id: String,
    r#type: String,
    role: String,
    content: Vec<AnthropicContentBlock>,
    model: String,
    stop_reason: Option<String>,
    #[serde(default)]
    usage: Option<AnthropicUsage>,
}

#[derive(Deserialize)]
struct AnthropicContentBlock {
    r#type: String,
    text: String,
}

#[derive(Deserialize, Default)]
struct AnthropicUsage {
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
}

#[derive(Deserialize)]
struct AnthropicErrorResponse {
    r#type: String,
    message: String,
}

#[derive(Debug, Clone)]
pub struct AnthropicProvider {
    client: Client,
    endpoint: String,
}

impl AnthropicProvider {
    pub fn new(endpoint: &str) -> Self {
        Self {
            client: Client::new(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
        }
    }

    fn messages_url(&self) -> String {
        format!("{}/messages", self.endpoint)
    }

    fn to_anthropic_request(req: ChatRequest) -> AnthropicChatRequest {
        // Anthropic требует отдельное поле system (не в messages)
        let system = req
            .messages
            .iter()
            .find(|m| m.role == "system")
            .map(|m| m.content.clone());
        let messages: Vec<AnthropicMessage> = req
            .messages
            .into_iter()
            .filter(|m| m.role != "system")
            .map(|m| AnthropicMessage {
                role: m.role,
                content: m.content,
            })
            .collect();

        AnthropicChatRequest {
            model: req.model,
            max_tokens: req.max_tokens.unwrap_or(1024),
            messages,
            system,
            temperature: req.temperature,
            stream: Some(false),
        }
    }

    fn from_anthropic_response(
        provider: &str,
        resp: AnthropicChatResponse,
        latency_ms: u64,
    ) -> ChatResponse {
        let content = resp
            .content
            .iter()
            .filter(|b| b.r#type == "text")
            .map(|b| b.text.clone())
            .collect::<Vec<_>>()
            .join("\n");

        let tokens_used = resp
            .usage
            .and_then(|u| u.input_tokens.zip(u.output_tokens).map(|(i, o)| i + o));

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
    ) -> Result<AnthropicChatResponse, AIError> {
        if status.is_success() {
            serde_json::from_str(&text).map_err(|e| AIError::Parse {
                provider: provider.to_string(),
                message: format!("не удалось распарсить ответ: {e}"),
            })
        } else {
            let error_detail: Result<AnthropicErrorResponse, _> = serde_json::from_str(&text);
            let message = match error_detail {
                Ok(e) => e.message,
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

impl AIProvider for AnthropicProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Anthropic
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn chat_completion(
        &self,
        api_key: &str,
        request: ChatRequest,
    ) -> Result<ChatResponse, AIError> {
        let provider_name = "Anthropic";
        let url = self.messages_url();
        let start = Instant::now();

        debug!("Anthropic chat completion: model={}", request.model);

        let anthropic_req = Self::to_anthropic_request(request);

        let resp = self
            .client
            .post(&url)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&anthropic_req)
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

        let anthropic_resp = Self::handle_response(provider_name, status, text).await?;
        let latency_ms = start.elapsed().as_millis() as u64;

        Ok(Self::from_anthropic_response(
            provider_name,
            anthropic_resp,
            latency_ms,
        ))
    }

    async fn test_connection(&self, api_key: &str) -> Result<LatencyResult, AIError> {
        let provider_name = "Anthropic";
        let start = Instant::now();

        let test_req = ChatRequest {
            messages: vec![crate::ChatMessage {
                role: "user".to_string(),
                content: "ping".to_string(),
            }],
            model: "claude-3-haiku-20240307".to_string(),
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
                error!("Anthropic тест соединения не пройден: {e}");
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
            "claude-3-5-sonnet-20241022".to_string(),
            "claude-3-5-haiku-20241022".to_string(),
            "claude-3-opus-20240229".to_string(),
            "claude-3-haiku-20240307".to_string(),
        ])
    }
}

impl Default for AnthropicProvider {
    fn default() -> Self {
        Self::new("https://api.anthropic.com/v1")
    }
}

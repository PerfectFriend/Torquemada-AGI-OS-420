//! Google провайдер: Gemini Pro, Gemini Flash.
//!
//! API документация: https://ai.google.dev
//! Эндпоинт: https://generativelanguage.googleapis.com/v1
//! Аутентификация: API-ключ как параметр запроса ?key=...
//! Формат запроса: нативный Google Generative Language API

use crate::{
    AIError, AIProvider, ChatRequest, ChatResponse, LatencyResult, ProviderType,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, error};

#[derive(Serialize)]
struct GoogleChatRequest {
    contents: Vec<GoogleContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_config: Option<GoogleGenerationConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_instruction: Option<GoogleContent>,
}

#[derive(Serialize, Deserialize)]
struct GoogleContent {
    role: String,
    parts: Vec<GooglePart>,
}

#[derive(Serialize, Deserialize)]
struct GooglePart {
    text: String,
}

#[derive(Serialize, Deserialize)]
struct GoogleGenerationConfig {
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<u32>,
}

#[derive(Deserialize)]
struct GoogleChatResponse {
    candidates: Vec<GoogleCandidate>,
    #[serde(default)]
    usage_metadata: Option<GoogleUsageMetadata>,
}

#[derive(Deserialize)]
struct GoogleCandidate {
    content: GoogleContent,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize, Default)]
struct GoogleUsageMetadata {
    prompt_token_count: Option<u32>,
    candidates_token_count: Option<u32>,
    total_token_count: Option<u32>,
}

#[derive(Deserialize)]
struct GoogleErrorResponse {
    error: GoogleErrorDetail,
}

#[derive(Deserialize)]
struct GoogleErrorDetail {
    code: Option<u32>,
    message: String,
    #[serde(default)]
    status: String,
}

#[derive(Debug, Clone)]
pub struct GoogleProvider {
    client: Client,
    endpoint: String,
}

impl GoogleProvider {
    pub fn new(endpoint: &str) -> Self {
        Self {
            client: Client::new(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
        }
    }

    /// Формирует URL с API-ключом как query-параметром.
    fn generate_content_url(&self, model: &str, api_key: &str) -> String {
        format!(
            "{}/models/{}:generateContent?key={}",
            self.endpoint, model, api_key
        )
    }

    fn to_google_request(req: ChatRequest) -> GoogleChatRequest {
        let system = req
            .messages
            .iter()
            .find(|m| m.role == "system")
            .cloned();

        let contents: Vec<GoogleContent> = req
            .messages
            .into_iter()
            .filter(|m| m.role != "system")
            .map(|m| GoogleContent {
                role: if m.role == "assistant" { "model".to_string() } else { "user".to_string() },
                parts: vec![GooglePart { text: m.content }],
            })
            .collect();

        let generation_config = Some(GoogleGenerationConfig {
            temperature: req.temperature,
            max_output_tokens: req.max_tokens,
        });

        GoogleChatRequest {
            contents,
            generation_config,
            system_instruction: system.map(|m| GoogleContent {
                role: "system".to_string(),
                parts: vec![GooglePart { text: m.content }],
            }),
        }
    }

    fn from_google_response(
        provider: &str,
        resp: GoogleChatResponse,
        latency_ms: u64,
    ) -> ChatResponse {
        let content = resp
            .candidates
            .first()
            .and_then(|c| c.content.parts.first())
            .map(|p| p.text.clone())
            .unwrap_or_default();

        let tokens_used = resp
            .usage_metadata
            .and_then(|u| u.total_token_count);

        ChatResponse {
            content,
            model: "gemini".to_string(), // Google не возвращает модель в ответе generateContent
            provider: provider.to_string(),
            tokens_used,
            latency_ms,
        }
    }

    async fn handle_response(
        provider: &str,
        status: reqwest::StatusCode,
        text: String,
    ) -> Result<GoogleChatResponse, AIError> {
        if status.is_success() {
            serde_json::from_str(&text).map_err(|e| AIError::Parse {
                provider: provider.to_string(),
                message: format!("не удалось распарсить ответ: {e}"),
            })
        } else {
            let error_detail: Result<GoogleErrorResponse, _> = serde_json::from_str(&text);
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

impl AIProvider for GoogleProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Google
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn chat_completion(
        &self,
        api_key: &str,
        request: ChatRequest,
    ) -> Result<ChatResponse, AIError> {
        let provider_name = "Google";
        let start = Instant::now();

        debug!("Google chat completion: model={}", request.model);
        let model = request.model.clone();

        let google_req = Self::to_google_request(request);
        let url = self.generate_content_url(&model, api_key);

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&google_req)
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

        let google_resp = Self::handle_response(provider_name, status, text).await?;
        let latency_ms = start.elapsed().as_millis() as u64;

        Ok(Self::from_google_response(
            provider_name,
            google_resp,
            latency_ms,
        ))
    }

    async fn test_connection(&self, api_key: &str) -> Result<LatencyResult, AIError> {
        let provider_name = "Google";
        let start = Instant::now();

        let test_req = ChatRequest {
            messages: vec![crate::ChatMessage {
                role: "user".to_string(),
                content: "ping".to_string(),
            }],
            model: "gemini-1.5-flash".to_string(),
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
                error!("Google тест соединения не пройден: {e}");
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
            "gemini-1.5-pro".to_string(),
            "gemini-1.5-flash".to_string(),
            "gemini-1.0-pro".to_string(),
        ])
    }
}

impl Default for GoogleProvider {
    fn default() -> Self {
        Self::new("https://generativelanguage.googleapis.com/v1")
    }
}

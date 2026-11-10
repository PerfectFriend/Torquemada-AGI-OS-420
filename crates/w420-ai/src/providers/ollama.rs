//! Ollama провайдер: локальные модели (self-hosted), не требует API-ключа.
//!
//! API документация: https://github.com/ollama/ollama/blob/main/docs/api.md
//! Эндпоинт: http://127.0.0.1:11434 (настраиваемый)
//! Аутентификация: не требуется (локальный хост)
//! Формат запроса: нативный Ollama API (/api/chat)

use crate::{
    AIError, AIProvider, ChatRequest, ChatResponse, LatencyResult, ProviderType,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, error};

#[derive(Serialize)]
struct OllamaChatRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaOptions>,
    stream: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct OllamaMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct OllamaOptions {
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_predict: Option<u32>,
}

#[derive(Deserialize)]
struct OllamaChatResponse {
    model: String,
    created_at: String,
    message: OllamaMessage,
    done: bool,
    #[serde(default)]
    total_duration: Option<u64>,
    #[serde(default)]
    prompt_eval_count: Option<u32>,
    #[serde(default)]
    eval_count: Option<u32>,
}

#[derive(Deserialize)]
struct OllamaErrorResponse {
    error: String,
}

#[derive(Deserialize)]
struct OllamaModel {
    name: String,
}

#[derive(Deserialize)]
struct OllamaListResponse {
    models: Vec<OllamaModel>,
}

#[derive(Debug, Clone)]
pub struct OllamaProvider {
    client: Client,
    endpoint: String,
}

impl OllamaProvider {
    pub fn new(endpoint: &str) -> Self {
        Self {
            client: Client::new(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
        }
    }

    fn chat_url(&self) -> String {
        format!("{}/api/chat", self.endpoint)
    }

    fn list_url(&self) -> String {
        format!("{}/api/tags", self.endpoint)
    }

    fn to_ollama_request(req: ChatRequest) -> OllamaChatRequest {
        OllamaChatRequest {
            model: req.model,
            messages: req
                .messages
                .into_iter()
                .map(|m| OllamaMessage {
                    role: m.role,
                    content: m.content,
                })
                .collect(),
            options: Some(OllamaOptions {
                temperature: req.temperature,
                num_predict: req.max_tokens,
            }),
            stream: false,
        }
    }

    fn from_ollama_response(
        provider: &str,
        resp: OllamaChatResponse,
        latency_ms: u64,
    ) -> ChatResponse {
        let tokens_used = resp.eval_count.or_else(|| {
            resp.prompt_eval_count
                .and_then(|p| resp.eval_count.map(|e| p + e))
        });

        ChatResponse {
            content: resp.message.content,
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
    ) -> Result<OllamaChatResponse, AIError> {
        if status.is_success() {
            serde_json::from_str(&text).map_err(|e| AIError::Parse {
                provider: provider.to_string(),
                message: format!("не удалось распарсить ответ: {e}"),
            })
        } else {
            let error_detail: Result<OllamaErrorResponse, _> = serde_json::from_str(&text);
            let message = match error_detail {
                Ok(e) => e.error,
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

impl AIProvider for OllamaProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Ollama
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn chat_completion(
        &self,
        _api_key: &str,
        request: ChatRequest,
    ) -> Result<ChatResponse, AIError> {
        let provider_name = "Ollama (локально)";
        let url = self.chat_url();
        let start = Instant::now();

        debug!("Ollama chat completion: model={}", request.model);

        let ollama_req = Self::to_ollama_request(request);

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&ollama_req)
            .send()
            .await
            .map_err(|e| AIError::Http {
                provider: provider_name.to_string(),
                status: None,
                message: format!("сетевая ошибка (проверьте, запущен ли Ollama): {e}"),
            })?;

        let status = resp.status();
        let text = resp.text().await.map_err(|e| AIError::Http {
            provider: provider_name.to_string(),
            status: Some(status.as_u16().to_string()),
            message: format!("ошибка чтения тела ответа: {e}"),
        })?;

        let ollama_resp = Self::handle_response(provider_name, status, text).await?;
        let latency_ms = start.elapsed().as_millis() as u64;

        Ok(Self::from_ollama_response(
            provider_name,
            ollama_resp,
            latency_ms,
        ))
    }

    async fn test_connection(&self, _api_key: &str) -> Result<LatencyResult, AIError> {
        let provider_name = "Ollama (локально)";
        let start = Instant::now();

        let test_req = ChatRequest {
            messages: vec![crate::ChatMessage {
                role: "user".to_string(),
                content: "ping".to_string(),
            }],
            model: "llama3.1:8b".to_string(),
            temperature: 0.0,
            max_tokens: Some(5),
            stream: false,
        };

        match self.chat_completion("", test_req).await {
            Ok(resp) => {
                let latency_ms = start.elapsed().as_millis() as u64;
                Ok(LatencyResult {
                    provider: provider_name.to_string(),
                    key_id: "local".to_string(),
                    latency_ms,
                    success: true,
                    error_message: None,
                })
            }
            Err(e) => {
                let latency_ms = start.elapsed().as_millis() as u64;
                error!("Ollama тест соединения не пройден: {e}");
                Ok(LatencyResult {
                    provider: provider_name.to_string(),
                    key_id: "local".to_string(),
                    latency_ms,
                    success: false,
                    error_message: Some(e.to_string()),
                })
            }
        }
    }

    async fn list_models(&self, _api_key: &str) -> Result<Vec<String>, AIError> {
        let url = self.list_url();
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| AIError::Http {
                provider: "Ollama (локально)".to_string(),
                status: None,
                message: format!("сетевая ошибка при получении списка моделей: {e}"),
            })?;

        let status = resp.status();
        if !status.is_success() {
            return Err(AIError::Http {
                provider: "Ollama (локально)".to_string(),
                status: Some(status.as_u16().to_string()),
                message: format!("Ollama вернул статус {}", status.as_u16()),
            });
        }

        let list: OllamaListResponse = resp.json().await.map_err(|e| AIError::Parse {
            provider: "Ollama (локально)".to_string(),
            message: format!("не удалось распарсить список моделей: {e}"),
        })?;

        Ok(list.models.into_iter().map(|m| m.name).collect())
    }
}

impl Default for OllamaProvider {
    fn default() -> Self {
        Self::new("http://127.0.0.1:11434")
    }
}

//! NVIDIA провайдер: NVIDIA NIM (NVIDIA Inference Microservices) и build.nvidia.com.
//! API документация: https://docs.nvidia.com/nim
//! Эндпоинт: https://integrate.api.nvidia.com/v1
//! Аутентификация: Bearer токен в заголовке Authorization
//! Формат запроса: OpenAI-совместимый (chat/completions)

use crate::{
    AIError, AIProvider, ChatRequest, ChatResponse, LatencyResult, ProviderType,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, error};

// NVIDIA NIM использует OpenAI-совместимый формат запроса/ответа.

#[derive(Serialize)]
struct NvidiaChatRequest {
    model: String,
    messages: Vec<NvidiaMessage>,
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(default)]
    stream: bool,
}

#[derive(Serialize, Deserialize)]
struct NvidiaMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct NvidiaChoice {
    index: u32,
    message: NvidiaResponseMessage,
    finish_reason: Option<String>,
}

/// Сообщение в ОТВЕТЕ NVIDIA. У reasoning-моделей (Mistral Large 4 и др.)
/// поле `content` бывает null, а текст идёт в `reasoning_content`.
#[derive(Deserialize)]
struct NvidiaResponseMessage {
    role: Option<String>,
    content: Option<String>,
    /// Reasoning-вывод модели (у reasoning-моделей); используем как fallback для content.
    reasoning_content: Option<String>,
}

/// Usage-статистика из ответа NVIDIA (если присутствует).
#[derive(Deserialize)]
struct NvidiaUsage {
    total_tokens: Option<u32>,
}

#[derive(Deserialize)]
struct NvidiaChatResponse {
    id: String,
    object: String,
    created: u64,
    model: String,
    choices: Vec<NvidiaChoice>,
    usage: Option<NvidiaUsage>,
}

#[derive(Deserialize)]
struct NvidiaModelsResponse {
    data: Vec<NvidiaModelInfo>,
}

#[derive(Deserialize)]
struct NvidiaModelInfo {
    id: String,
}

/// Реализация провайдера NVIDIA (NIM / build.nvidia.com).
///
/// NVIDIA предоставляет доступ к своим моделям (Nemotron, Llama, Mistral и др.)
/// через API, совместимый с OpenAI chat/completions.
/// Требуется API-ключ, полученный на build.nvidia.com.
#[derive(Debug, Clone)]
pub struct NvidiaProvider {
    client: Client,
    endpoint: String,
}

impl NvidiaProvider {
    /// Создаёт нового провайдера NVIDIA с заданным эндпоинтом.
    pub fn new(endpoint: &str) -> Self {
        Self {
            client: Client::new(),
            endpoint: endpoint.to_string(),
        }
    }

    /// Формирует URL для chat/completions.
    fn chat_url(&self) -> String {
        format!("{}/chat/completions", self.endpoint.trim_end_matches('/'))
    }

    /// Формирует URL для списка моделей.
    fn models_url(&self) -> String {
        format!("{}/models", self.endpoint.trim_end_matches('/'))
    }

    /// Преобразует унифицированный ChatRequest в формат NVIDIA.
    fn to_nvidia_request(request: ChatRequest) -> NvidiaChatRequest {
        NvidiaChatRequest {
            model: request.model,
            messages: request
                .messages
                .into_iter()
                .map(|m| NvidiaMessage {
                    role: m.role,
                    content: m.content,
                })
                .collect(),
            temperature: request.temperature,
            max_tokens: request.max_tokens,
            stream: false,
        }
    }

    /// Обрабатывает HTTP-ответ от NVIDIA API.
    async fn handle_response(
        provider: &str,
        status: reqwest::StatusCode,
        text: String,
    ) -> Result<ChatResponse, AIError> {
        if status.is_success() {
            let nvidia_resp: NvidiaChatResponse =
                serde_json::from_str(&text).map_err(|e| AIError::Parse {
                    provider: provider.to_string(),
                    message: format!("не удалось распарсить ответ: {e}"),
                })?;

            // У reasoning-моделей content может быть null — тогда берём reasoning_content
            let first = nvidia_resp.choices.first();
            let content = first
                .and_then(|c| c.message.content.clone())
                .or_else(|| first.and_then(|c| c.message.reasoning_content.clone()))
                .unwrap_or_default();

            Ok(ChatResponse {
                content,
                model: nvidia_resp.model,
                provider: provider.to_string(),
                tokens_used: nvidia_resp.usage.and_then(|u| u.total_tokens),
                latency_ms: 0,
            })
        } else {
            let error_detail: Result<serde_json::Value, _> = serde_json::from_str(&text);
            let message = match error_detail {
                Ok(e) => e
                    .get("error")
                    .and_then(|v| v.get("message"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(&text)
                    .to_string(),
                Err(_) => text,
            };
            Err(AIError::Http {
                provider: provider.to_string(),
                status: Some(status.as_u16().to_string()),
                message,
            })
        }
    }
}

impl AIProvider for NvidiaProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Nvidia
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn chat_completion(
        &self,
        api_key: &str,
        request: ChatRequest,
    ) -> Result<ChatResponse, AIError> {
        let provider_name = "NVIDIA";
        let start = Instant::now();

        debug!("NVIDIA chat completion: model={}", request.model);

        let nvidia_req = Self::to_nvidia_request(request);
        let url = self.chat_url();

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Content-Type", "application/json")
            .json(&nvidia_req)
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
            status: None,
            message: format!("ошибка чтения ответа: {e}"),
        })?;

        let elapsed = start.elapsed().as_millis() as u64;
        let _ = elapsed;

        Self::handle_response(provider_name, status, text).await
    }

    async fn test_connection(&self, api_key: &str) -> Result<LatencyResult, AIError> {
        let provider_name = "NVIDIA";
        let start = Instant::now();

        let test_req = ChatRequest {
            model: "meta/llama-3.1-8b-instruct".to_string(),
            messages: vec![crate::ChatMessage {
                role: "user".to_string(),
                content: "Hello".to_string(),
            }],
            temperature: 0.1,
            max_tokens: Some(5),
            stream: false,
        };

        let nvidia_req = Self::to_nvidia_request(test_req);
        let url = self.chat_url();

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Content-Type", "application/json")
            .json(&nvidia_req)
            .send()
            .await
            .map_err(|e| AIError::Http {
                provider: provider_name.to_string(),
                status: None,
                message: format!("сетевая ошибка (проверьте API-ключ NVIDIA): {e}"),
            })?;

        let status = resp.status();
        let latency_ms = start.elapsed().as_millis() as u64;

        if status.is_success() {
            Ok(LatencyResult {
                provider: provider_name.to_string(),
                key_id: "test".to_string(),
                latency_ms,
                success: true,
                error_message: None,
            })
        } else {
            let text = resp.text().await.unwrap_or_default();
            Ok(LatencyResult {
                provider: provider_name.to_string(),
                key_id: "test".to_string(),
                latency_ms,
                success: false,
                error_message: Some(format!("NVIDIA вернул статус {}: {}", status, text)),
            })
        }
    }

    async fn list_models(&self, api_key: &str) -> Result<Vec<String>, AIError> {
        let provider_name = "NVIDIA";

        let resp = self
            .client
            .get(&self.models_url())
            .header("Authorization", format!("Bearer {api_key}"))
            .send()
            .await
            .map_err(|e| AIError::Http {
                provider: provider_name.to_string(),
                status: None,
                message: format!("сетевая ошибка при запросе моделей: {e}"),
            })?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(AIError::Http {
                provider: provider_name.to_string(),
                status: Some(status.as_u16().to_string()),
                message: text,
            });
        }

        let models_resp: NvidiaModelsResponse = resp.json().await.map_err(|e| AIError::Parse {
            provider: provider_name.to_string(),
            message: format!("не удалось распарсить список моделей: {e}"),
        })?;

        Ok(models_resp.data.into_iter().map(|m| m.id).collect())
    }

    fn is_retriable_error(&self, error: &crate::AIError) -> bool {
        matches!(
            error,
            AIError::Http { status: Some(s), .. }
                if s == "429" || s == "502" || s == "503" || s == "504"
        ) || matches!(error, AIError::Http { status: None, .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_type_display() {
        let p = NvidiaProvider::new("https://integrate.api.nvidia.com/v1");
        assert_eq!(p.provider_type(), ProviderType::Nvidia);
        assert_eq!(p.endpoint(), "https://integrate.api.nvidia.com/v1");
    }

    #[test]
    fn test_chat_request_defaults() {
        let req = NvidiaChatRequest {
            model: "meta/llama-3.1-8b-instruct".to_string(),
            messages: vec![NvidiaMessage {
                role: "user".to_string(),
                content: "test".to_string(),
            }],
            temperature: 0.7,
            max_tokens: None,
            stream: false,
        };
        assert_eq!(req.model, "meta/llama-3.1-8b-instruct");
        assert_eq!(req.messages.len(), 1);
        assert_eq!(req.temperature, 0.7);
    }
}

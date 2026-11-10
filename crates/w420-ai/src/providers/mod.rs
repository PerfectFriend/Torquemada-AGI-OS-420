//! Модуль провайдеров: конкретные реализации `AIProvider` для каждого supported провайдера.
//!
//! Каждый провайдер инкапсулирует:
//!   - Свой базовый эндпоинт API
//!   - Способ аутентификации (Bearer token, x-api-key, query param key, без аутентификации)
//!   - Формат запроса chat/completions (OpenAI-совместимый или нативный)
//!   - Формат парсинга ответа
//!
//! Список реализованных провайдеров:
//!   - OpenAI  (openai.rs)
//!   - Anthropic (anthropic.rs)
//!   - Google (google.rs)
//!   - Mistral (mistral.rs)
//!   - Groq (groq.rs)
//!   - Together (together.rs)
//!   - OpenRouter (openrouter.rs)
//!   - Ollama (ollama.rs) — локальные модели без API-ключа
//!
//! `AnyProvider` — enum-обёртка над всеми конкретными провайдерами.
//! Используется вместо `Box<dyn AIProvider>`, так как async-методы в трейте
//! делают его не объектно-безопасным для использования с `dyn` в стабильном Rust.

mod anthropic;
mod google;
mod groq;
mod mistral;
mod nvidia;
mod openai;
mod ollama;
mod openrouter;
mod together;

pub use anthropic::AnthropicProvider;
pub use google::GoogleProvider;
pub use groq::GroqProvider;
pub use mistral::MistralProvider;
pub use nvidia::NvidiaProvider;
pub use openai::OpenAIProvider;
pub use ollama::OllamaProvider;
pub use openrouter::OpenRouterProvider;
pub use together::TogetherProvider;

/// Enum-обёртка над всеми конкретными провайдерами.
///
/// Реализует `AIProvider` путем делегирования вызовов соответствующему варианту.
/// Это позволяет избежать использования `Box<dyn AIProvider>`, что невозможно
/// из-за async-методов в трейте (не объектно-безопасно в стабильном Rust).
#[derive(Clone)]
pub enum AnyProvider {
    OpenAI(OpenAIProvider),
    Anthropic(AnthropicProvider),
    Google(GoogleProvider),
    Mistral(MistralProvider),
    Nvidia(NvidiaProvider),
    Groq(GroqProvider),
    Together(TogetherProvider),
    OpenRouter(OpenRouterProvider),
    Ollama(OllamaProvider),
}

impl AnyProvider {
    /// Создаёт `AnyProvider` из конфигурации провайдера.
    pub fn from_config(config: &crate::ProviderConfig) -> Self {
        match config.provider_type {
            crate::ProviderType::OpenAI => AnyProvider::OpenAI(OpenAIProvider::new(&config.endpoint)),
            crate::ProviderType::Anthropic => AnyProvider::Anthropic(AnthropicProvider::new(&config.endpoint)),
            crate::ProviderType::Google => AnyProvider::Google(GoogleProvider::new(&config.endpoint)),
            crate::ProviderType::Mistral => AnyProvider::Mistral(MistralProvider::new(&config.endpoint)),
            crate::ProviderType::Nvidia => AnyProvider::Nvidia(NvidiaProvider::new(&config.endpoint)),
            crate::ProviderType::Groq => AnyProvider::Groq(GroqProvider::new(&config.endpoint)),
            crate::ProviderType::Together => AnyProvider::Together(TogetherProvider::new(&config.endpoint)),
            crate::ProviderType::OpenRouter => AnyProvider::OpenRouter(OpenRouterProvider::new(&config.endpoint)),
            crate::ProviderType::Ollama => AnyProvider::Ollama(OllamaProvider::new(&config.endpoint)),
            crate::ProviderType::Custom => AnyProvider::OpenAI(OpenAIProvider::new(&config.endpoint)),
        }
    }
}

impl crate::AIProvider for AnyProvider {
    fn provider_type(&self) -> crate::ProviderType {
        match self {
            AnyProvider::OpenAI(p) => p.provider_type(),
            AnyProvider::Anthropic(p) => p.provider_type(),
            AnyProvider::Google(p) => p.provider_type(),
            AnyProvider::Mistral(p) => p.provider_type(),
            AnyProvider::Nvidia(p) => p.provider_type(),
            AnyProvider::Groq(p) => p.provider_type(),
            AnyProvider::Together(p) => p.provider_type(),
            AnyProvider::OpenRouter(p) => p.provider_type(),
            AnyProvider::Ollama(p) => p.provider_type(),
        }
    }

    fn endpoint(&self) -> &str {
        match self {
            AnyProvider::OpenAI(p) => p.endpoint(),
            AnyProvider::Anthropic(p) => p.endpoint(),
            AnyProvider::Google(p) => p.endpoint(),
            AnyProvider::Mistral(p) => p.endpoint(),
            AnyProvider::Nvidia(p) => p.endpoint(),
            AnyProvider::Groq(p) => p.endpoint(),
            AnyProvider::Together(p) => p.endpoint(),
            AnyProvider::OpenRouter(p) => p.endpoint(),
            AnyProvider::Ollama(p) => p.endpoint(),
        }
    }

    async fn chat_completion(
        &self,
        api_key: &str,
        request: crate::ChatRequest,
    ) -> Result<crate::ChatResponse, crate::AIError> {
        match self {
            AnyProvider::OpenAI(p) => p.chat_completion(api_key, request).await,
            AnyProvider::Anthropic(p) => p.chat_completion(api_key, request).await,
            AnyProvider::Google(p) => p.chat_completion(api_key, request).await,
            AnyProvider::Mistral(p) => p.chat_completion(api_key, request).await,
            AnyProvider::Nvidia(p) => p.chat_completion(api_key, request).await,
            AnyProvider::Groq(p) => p.chat_completion(api_key, request).await,
            AnyProvider::Together(p) => p.chat_completion(api_key, request).await,
            AnyProvider::OpenRouter(p) => p.chat_completion(api_key, request).await,
            AnyProvider::Ollama(p) => p.chat_completion(api_key, request).await,
        }
    }

    async fn test_connection(&self, api_key: &str) -> Result<crate::LatencyResult, crate::AIError> {
        match self {
            AnyProvider::OpenAI(p) => p.test_connection(api_key).await,
            AnyProvider::Anthropic(p) => p.test_connection(api_key).await,
            AnyProvider::Google(p) => p.test_connection(api_key).await,
            AnyProvider::Mistral(p) => p.test_connection(api_key).await,
            AnyProvider::Nvidia(p) => p.test_connection(api_key).await,
            AnyProvider::Groq(p) => p.test_connection(api_key).await,
            AnyProvider::Together(p) => p.test_connection(api_key).await,
            AnyProvider::OpenRouter(p) => p.test_connection(api_key).await,
            AnyProvider::Ollama(p) => p.test_connection(api_key).await,
        }
    }

    async fn list_models(&self, api_key: &str) -> Result<Vec<String>, crate::AIError> {
        match self {
            AnyProvider::OpenAI(p) => p.list_models(api_key).await,
            AnyProvider::Anthropic(p) => p.list_models(api_key).await,
            AnyProvider::Google(p) => p.list_models(api_key).await,
            AnyProvider::Mistral(p) => p.list_models(api_key).await,
            AnyProvider::Nvidia(p) => p.list_models(api_key).await,
            AnyProvider::Groq(p) => p.list_models(api_key).await,
            AnyProvider::Together(p) => p.list_models(api_key).await,
            AnyProvider::OpenRouter(p) => p.list_models(api_key).await,
            AnyProvider::Ollama(p) => p.list_models(api_key).await,
        }
    }

    fn is_retriable_error(&self, error: &crate::AIError) -> bool {
        match self {
            AnyProvider::OpenAI(p) => p.is_retriable_error(error),
            AnyProvider::Anthropic(p) => p.is_retriable_error(error),
            AnyProvider::Google(p) => p.is_retriable_error(error),
            AnyProvider::Mistral(p) => p.is_retriable_error(error),
            AnyProvider::Nvidia(p) => p.is_retriable_error(error),
            AnyProvider::Groq(p) => p.is_retriable_error(error),
            AnyProvider::Together(p) => p.is_retriable_error(error),
            AnyProvider::OpenRouter(p) => p.is_retriable_error(error),
            AnyProvider::Ollama(p) => p.is_retriable_error(error),
        }
    }
}

//! w420-ai — публичный API crate для абстракции AI-провайдеров.
//!
//! Этот модуль предоставляет:
//!   - `AIProvider` — трейт, который должен реализовать каждый провайдер
//!   - `AIError` — единый тип ошибок для всех операций с провайдерами
//!   - `ProviderType` — перечисление поддерживаемых провайдеров
//!   - `ChatRequest` / `ChatResponse` — унифицированные структуры запроса/ответа
//!   - `ProviderConfig` — конфигурация провайдера (ключи, эндпоинты, модели)
//!   - `ProviderKeyConfig` — конфигурация API-ключа провайдера
//!   - `LatencyResult` — результат измерения задержки при тестировании ключа
//!   - `RotationStrategy` — стратегия выбора ключа для ротации
//!   - `RotatedChatResponse` — ответ с информацией о использованном ключе
//!   - `ProviderFactory` — фабрика кэшированных провайдеров
//!   - `KeyRotation` — система ротации ключей
//!   - `AIProviderDB` — база данных SQLite для провайдеров и ключей
//!   - `TestingManager` — менеджер автотестирования ключей
//!   - `encrypt_api_key` / `decrypt_api_key` — шифрование ключей на диске
//!
//! Все публичные типы подробно документированы комментариями на русском языке,
//! чтобы любой разработчик мог продолжить эволюцию проекта.

pub mod db;
pub mod encryption;
pub mod providers;
pub mod rotation;
pub mod testing;

// Реэкспорт провайдеров
pub use crate::providers::{
    AnthropicProvider, GoogleProvider, GroqProvider, MistralProvider, NvidiaProvider, OllamaProvider,
    OpenAIProvider, OpenRouterProvider, TogetherProvider,
};

// Реэкспорт инфраструктурных компонентов
pub use crate::db::AIProviderDB;
pub use crate::encryption::{decrypt_api_key, encrypt_api_key};
pub use crate::rotation::KeyRotation;
pub use crate::testing::{KeyStatusInfo, TestingManager};

// ============================================================================
// Основные типы (определены здесь, в корне модуля)
// ============================================================================

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Перечисление всех поддерживаемых AI-провайдеров.
///
/// Каждый вариант соответствует конкретному провайдеру со своим API-эндпоинтом,
/// способом аутентификации и форматом запросов.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProviderType {
    /// OpenAI — GPT-4o, GPT-4, GPT-3.5 Turbo и др.
    /// Эндпоинт: https://api.openai.com/v1
    OpenAI,
    /// Anthropic — Claude 3.5 Sonnet, Claude 3 Opus, Claude 3 Haiku
    /// Эндпоинт: https://api.anthropic.com/v1
    Anthropic,
    /// Google — Gemini Pro, Gemini Flash
    /// Эндпоинт: https://generativelanguage.googleapis.com/v1
    Google,
    /// Mistral AI — Mistral Large, Mistral Nemo, Codestral
    /// Эндпоинт: https://api.mistral.ai/v1
    Mistral,
    /// Groq — быстрый инференс Llama, Mixtral, Gemma
    /// Эндпоинт: https://api.groq.com/openai/v1
    Groq,
    /// Together AI — открытые модели (Llama, Mixtral, Stable Diffusion)
    /// Эндпоинт: https://api.together.xyz/v1
    Together,
    /// OpenRouter — агрегатор множества моделей через один ключ
    /// Эндпоинт: https://openrouter.ai/api/v1
    OpenRouter,
    /// Ollama — локальные модели (self-hosted), не требует API-ключа
    /// Эндпоинт: http://127.0.0.1:11434 (настраиваемый)
    Ollama,
    /// NVIDIA NIM / build.nvidia.com — модели NVIDIA (Nemotron, Llama, Mistral и др.)
    /// через API, совместимый с OpenAI. Требуется API-ключ с build.nvidia.com.
    /// Эндпоинт: https://integrate.api.nvidia.com/v1
    Nvidia,
    /// Кастомный провайдер — пользователь может указать любой OpenAI-совместимый эндпоинт
    Custom,
}

impl fmt::Display for ProviderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProviderType::OpenAI => write!(f, "OpenAI"),
            ProviderType::Anthropic => write!(f, "Anthropic"),
            ProviderType::Google => write!(f, "Google"),
            ProviderType::Mistral => write!(f, "Mistral AI"),
            ProviderType::Groq => write!(f, "Groq"),
            ProviderType::Together => write!(f, "Together AI"),
            ProviderType::OpenRouter => write!(f, "OpenRouter"),
            ProviderType::Ollama => write!(f, "Ollama (локально)"),
            ProviderType::Nvidia => write!(f, "NVIDIA NIM"),
            ProviderType::Custom => write!(f, "Кастомный провайдер"),
        }
    }
}

impl ProviderType {
    /// Возвращает базовый URL эндпоинта для данного типа провайдера.
    ///
    /// Для `Ollama` и `Custom` эндпоинт не фиксирован — пользователь задаёт его в конфигурации.
    pub fn default_endpoint(&self) -> Option<&'static str> {
        match self {
            ProviderType::OpenAI => Some("https://api.openai.com/v1"),
            ProviderType::Anthropic => Some("https://api.anthropic.com/v1"),
            ProviderType::Google => Some("https://generativelanguage.googleapis.com/v1"),
            ProviderType::Mistral => Some("https://api.mistral.ai/v1"),
            ProviderType::Groq => Some("https://api.groq.com/openai/v1"),
            ProviderType::Together => Some("https://api.together.xyz/v1"),
            ProviderType::OpenRouter => Some("https://openrouter.ai/api/v1"),
            ProviderType::Ollama => None, // пользователь задаёт вручную (обычно http://127.0.0.1:11434)
            ProviderType::Nvidia => Some("https://integrate.api.nvidia.com/v1"),
            ProviderType::Custom => None, // пользователь задаёт вручную
        }
    }

    /// Возвращает человекочитаемое описание способа аутентификации.
    pub fn auth_description(&self) -> &'static str {
        match self {
            ProviderType::OpenAI => "Bearer токен в заголовке Authorization",
            ProviderType::Anthropic => "x-api-key заголовок",
            ProviderType::Google => "API-ключ как параметр запроса ?key=...",
            ProviderType::Mistral => "Bearer токен в заголовке Authorization",
            ProviderType::Groq => "Bearer токен в заголовке Authorization",
            ProviderType::Together => "Bearer токен в заголовке Authorization",
            ProviderType::OpenRouter => "Bearer токен в заголовке Authorization",
            ProviderType::Ollama => "Аутентификация не требуется (локальный хост)",
            ProviderType::Nvidia => "Bearer токен в заголовке Authorization",
            ProviderType::Custom => "Bearer токен в заголовке Authorization (OpenAI-совместимый)",
        }
    }
}

/// Единый тип ошибок для всех операций с AI-провайдерами.
///
/// Используется вместо раздельных ошибок каждого провайдера, чтобы верхний
/// уровень (Tauri команды, логи ротации) мог обрабатывать ошибки Uniform.
#[derive(Debug, Error, Clone)]
pub enum AIError {
    /// Ошибка конфигурации провайдера (отсутствует ключ, некорректный URL)
    #[error("Ошибка конфигурации провайдера: {0}")]
    Config(String),

    /// Ошибка шифрования/расшифрования API-ключа
    #[error("Ошибка шифрования ключа: {0}")]
    Encryption(String),

    /// Ошибка базы данных (SQLite)
    #[error("Ошибка базы данных: {0}")]
    Database(String),

    /// Ошибка HTTP-запроса к провайдеру (сеть, таймаут, код ответа)
    #[error("HTTP ошибка провайдера {provider}: {status:?} {message}")]
    Http {
        provider: String,
        status: Option<String>,
        message: String,
    },

    /// Ошибка десериализации ответа от провайдера
    #[error("Ошибка разбора ответа провайдера {provider}: {message}")]
    Parse {
        provider: String,
        message: String,
    },

    /// Все ключи провайдера исчерпаны (все временно заблокированы backoff'ом)
    #[error("Все ключи провайдера {provider} временно недоступны (rate limit или ошибки)")]
    AllKeysExhausted { provider: String },

    /// Провайдер не найден в конфигурации
    #[error("Провайдер не найден: {0}")]
    ProviderNotFound(String),

    /// Ключ не найден для данного провайдера
    #[error("Ключ не найден для провайдера: {0}")]
    KeyNotFound(String),

    /// Внутренняя ошибка логики ротации
    #[error("Ошибка ротации ключей: {0}")]
    Rotation(String),

    /// Отмена операции (требуется завершить запрос досрочно)
    #[error("Операция отменена")]
    Cancelled,
}

// Реализации From для автоматического конвертирования ошибок через `?`
impl From<reqwest::Error> for AIError {
    fn from(e: reqwest::Error) -> Self {
        AIError::Http {
            provider: "неизвестный".to_string(),
            status: e.status().map(|s| s.as_u16().to_string()),
            message: e.to_string(),
        }
    }
}

impl From<rusqlite::Error> for AIError {
    fn from(e: rusqlite::Error) -> Self {
        AIError::Database(e.to_string())
    }
}

impl From<std::io::Error> for AIError {
    fn from(e: std::io::Error) -> Self {
        AIError::Encryption(e.to_string())
    }
}

impl From<serde_json::Error> for AIError {
    fn from(e: serde_json::Error) -> Self {
        AIError::Parse {
            provider: "неизвестный".to_string(),
            message: e.to_string(),
        }
    }
}

impl From<base64::DecodeError> for AIError {
    fn from(e: base64::DecodeError) -> Self {
        AIError::Encryption(e.to_string())
    }
}

/// Унифицированный запрос чата к любому провайдеру.
///
/// Поля `messages`, `model`, `temperature`, `max_tokens` поддерживаются
/// большинством провайдеров. Провайдеры с иным форматом (Anthropic, Google)
/// преобразуют эту структуру в свой нативный формат внутри своей реализации.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    /// Сообщения беседы (роль system/user/assistant + текст)
    pub messages: Vec<ChatMessage>,
    /// Модель для генерации (например, "gpt-4o", "claude-3-5-sonnet-20241022")
    pub model: String,
    /// Температура генерации (0.0 = детерминированно, 1.0 = креативно)
    #[serde(default = "default_temperature")]
    pub temperature: f32,
    /// Максимальное количество токенов в ответе (None = по умолчанию провайдера)
    pub max_tokens: Option<u32>,
    /// Потоковая передача (streaming) — пока не реализована, всегда false
    #[serde(default)]
    pub stream: bool,
}

fn default_temperature() -> f32 {
    0.7
}

/// Одно сообщение в чате.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Роль: "system", "user", "assistant"
    pub role: String,
    /// Текст сообщения
    pub content: String,
}

/// Унифицированный ответ от любого провайдера.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    /// Текст ответа от модели
    pub content: String,
    /// Использованная модель
    pub model: String,
    /// Провайдер, который вернул ответ
    pub provider: String,
    /// Количество использованных токенов (вход + выход, если известно)
    pub tokens_used: Option<u32>,
    /// Задержка ответа в миллисекундах (измеряется на стороне клиента)
    pub latency_ms: u64,
}

/// Конфигурация одного провайдера с набором ключей.
///
/// Хранится в базе данных и загружается при старте приложения.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub id: String,
    pub provider_type: ProviderType,
    pub name: String,
    pub endpoint: String,
    /// Доступные модели (JSON-массив строк, заполняется после автотестирования)
    pub models: Vec<String>,
    pub is_enabled: bool,
    pub created_at: String,
}

/// Конфигурация одного API-ключа внутри провайдера.
///
/// Ключ хранится зашифрованным (AES-256-GCM) в базе данных.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderKeyConfig {
    pub id: String,
    pub provider_id: String,
    /// Пользовательское название ключа (для удобства админа)
    pub nickname: Option<String>,
    /// Зашифрованный ключ (base64-строка)
    pub encrypted_key: String,
    pub is_active: bool,
    /// Последний успешный тест (ISO-8601 строка)
    pub last_tested: Option<String>,
    /// Средняя задержка в мс (измеряется при автотестировании)
    pub avg_latency_ms: Option<u64>,
    /// Количество последовательных ошибок (для backoff'а)
    pub error_count: u32,
    /// Ключ временно заблокирован до этого времени (ISO-8601)
    pub blocked_until: Option<String>,
    pub created_at: String,
}

/// Результат измерения задержки при тестировании ключа.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyResult {
    pub provider: String,
    pub key_id: String,
    pub latency_ms: u64,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Стратегия выбора ключа для ротации.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RotationStrategy {
    /// Самый быстрый ключ с наименьшим avg_latency_ms
    FastestFirst,
    /// Round-robin (последовательный перебор ключей)
    RoundRobin,
    /// Случайный выбор из активных ключей
    Random,
}

impl Default for RotationStrategy {
    fn default() -> Self {
        RotationStrategy::FastestFirst
    }
}

/// Трейт, который должен реализовать каждый AI-провайдер.
///
/// Каждая реализация инкапсулирует специфику эндпоинта, заголовков аутентификации
/// и формата запроса/ответа конкретного провайдера.
pub trait AIProvider: Send + Sync {
    /// Возвращает тип провайдера (для идентификации в БД и UI)
    fn provider_type(&self) -> ProviderType;

    /// Возвращает базовый URL эндпоинта API
    fn endpoint(&self) -> &str;

    /// Выполняет запрос чата к провайдеру.
    ///
    /// `api_key` — расшифрованный ключ (уже готовый к использованию).
    /// Возвращает унифицированный `ChatResponse`.
    async fn chat_completion(
        &self,
        api_key: &str,
        request: ChatRequest,
    ) -> Result<ChatResponse, AIError>;

    /// Проверяет работоспособность ключа, отправляя тестовый запрос.
    ///
    /// Возвращает задержку и признак успеха. Используется при автотестировании
    /// и для заполнения `avg_latency_ms` в конфигурации ключа.
    async fn test_connection(&self, api_key: &str) -> Result<LatencyResult, AIError>;

    /// Возвращает список доступных моделей для данного провайдера.
    /// Может вернуть пустой список, если провайдер не поддерживает такой запрос.
    async fn list_models(&self, api_key: &str) -> Result<Vec<String>, AIError>;

    /// Проверяет, является ли ошибка повторимой (rate limit, временный сбой сети).
    /// Используется логикой ротации для решения, переходить ли к следующему ключу.
    fn is_retriable_error(&self, error: &AIError) -> bool {
        matches!(
            error,
            AIError::Http { status: Some(s), .. }
                if s == "429" || s == "502" || s == "503" || s == "504"
        ) || matches!(error, AIError::Http { status: None, .. })
    }
}

/// Результат выполнения чат-запроса через ротацию ключей.
///
/// Содержит ответ и информацию о том, какой ключ был использован.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotatedChatResponse {
    pub response: ChatResponse,
    pub provider_type: ProviderType,
    pub provider_name: String,
    pub key_id: String,
    pub keys_tried: usize,
}

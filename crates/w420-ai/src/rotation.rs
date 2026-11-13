//! Модуль ротации ключей: выбор лучшего доступного ключа, backoff при ошибках,
//! сортировка по latency, автоматическое переключение провайдеров.
//!
//! Логика работы:
//!   1. Для каждого провайдера извлекаются активные ключи (не заблокированные backoff'ом)
//!   2. Ключи сортируются по стратегии (FastestFirst по умолчанию: сначала наименьший avg_latency_ms)
//!   3. При запросе выбирается первый ключ из отсортированного списка
//!   4. При ошибке (retriable) ключ получает +1 к error_count, и переходим к следующему
//!   5. Если все ключи провайдера исчерпаны — переходим к следующему провайдеру
//!   6. Ключи с ошибками временно блокируются на время backoff (экспоненциально растёт)
//!
//! Провайдеры создаются напрямую без кэширующей фабрики, что избавляет от
//! проблем с объектно-безопасностью трейта с async-методами в стабильном Rust.

use crate::{
    AIError, AIProvider, ChatRequest, LatencyResult, ProviderConfig, ProviderKeyConfig,
    ProviderType, RotationStrategy, RotatedChatResponse,
};
use crate::providers::AnyProvider;
use chrono::{Utc, DateTime, Duration};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Длительность блокировки ключа после ошибки (в секундах).
///
/// 429 (rate limit) — фиксированные 15 минут, как в пуле ключей Hermes.
/// 5xx / сетевая ошибка — экспоненциальный backoff: 60s, 120s, 240s … максимум 30 минут.
/// Прочие retriable — 60 секунд.
pub fn backoff_secs(error_count: u32, status: Option<&str>) -> u64 {
    match status {
        Some("429") => 15 * 60,
        Some(s) if s.starts_with('5') => {
            let n = error_count.max(1);
            60u64.saturating_mul(2u64.saturating_pow(n.saturating_sub(1))).min(30 * 60)
        }
        None => {
            let n = error_count.max(1);
            60u64.saturating_mul(2u64.saturating_pow(n.saturating_sub(1))).min(30 * 60)
        }
        _ => 60,
    }
}

/// Извлекает HTTP-статус из ошибки провайдера (если это HTTP-ошибка).
pub fn status_of(e: &AIError) -> Option<String> {
    match e {
        AIError::Http { status, .. } => status.clone(),
        _ => None,
    }
}

/// Создаёт экземпляр провайдера по конфигурации.
///
/// Возвращает `AnyProvider` (enum-обёртку), а не `Box<dyn AIProvider>`,
/// так как async-методы в трейте делают его не объектно-безопасным.
pub(crate) fn create_provider(config: &ProviderConfig) -> AnyProvider {
    AnyProvider::from_config(config)
}

/// Система ротации ключей: управляет всеми провайдерами и их ключами.
///
/// Основной метод `chat_completion_with_rotation` выполняет запрос с автоматическим
/// перебором ключей и провайдеров при ошибках.
pub struct KeyRotation {
    /// Все конфигурации провайдеров
    providers: Arc<RwLock<Vec<ProviderConfig>>>,
    /// Все ключи (по ID ключа)
    keys: Arc<RwLock<HashMap<String, ProviderKeyConfig>>>,
    /// Стратегия ротации
    strategy: RotationStrategy,
}

impl KeyRotation {
    pub fn new() -> Self {
        Self {
            providers: Arc::new(RwLock::new(Vec::new())),
            keys: Arc::new(RwLock::new(HashMap::new())),
            strategy: RotationStrategy::default(),
        }
    }

    /// Загружает конфигурацию провайдеров и ключей из базы данных.
    pub async fn load_from_db(&self, db: &crate::db::AIProviderDB) -> Result<(), AIError> {
        let provs = db.list_providers().map_err(|e| AIError::Database(e.to_string()))?;
        let all_keys = db.list_all_keys().map_err(|e| AIError::Database(e.to_string()))?;

        *self.providers.write().await = provs.clone();

        let mut keys_map = HashMap::new();
        for key in &all_keys {
            keys_map.insert(key.id.clone(), key.clone());
        }
        *self.keys.write().await = keys_map;

        info!("Загружено {} провайдеров и {} ключей из БД", provs.len(), all_keys.len());
        Ok(())
    }

    /// Добавляет провайдер в активную конфигурацию.
    pub async fn add_provider(&self, config: ProviderConfig) {
        self.providers.write().await.push(config);
    }

    /// Добавляет ключ в активную конфигурацию.
    pub async fn add_key(&self, key: ProviderKeyConfig) {
        self.keys.write().await.insert(key.id.clone(), key);
    }

    /// Возвращает список всех провайдеров.
    pub async fn list_providers(&self) -> Vec<ProviderConfig> {
        self.providers.read().await.clone()
    }

    /// Сохраняет обновлённую статистику ключей (error_count / blocked_until / avg_latency_ms)
    /// в БД провайдеров — чтобы backoff после 429/5xx действовал и между вызовами чата.
    /// Синхронная (try_read), т.к. rusqlite Connection не Send и не может висеть в async-контексте.
    pub fn persist_stats(&self, db: &crate::db::AIProviderDB) -> Result<(), String> {
        let keys = self.keys.try_read().map_err(|e| format!("блокировка ключей: {e}"))?;
        for k in keys.values() {
            if let Err(e) = db.update_key_stats(&k.id, k.avg_latency_ms, k.error_count, k.blocked_until.as_deref()) {
                warn!("не удалось сохранить статистику ключа {}: {e}", k.id);
            }
        }
        Ok(())
    }

    /// Возвращает список ключей для указанного провайдера.
    pub async fn list_keys_for_provider(&self, provider_id: &str) -> Vec<ProviderKeyConfig> {
        self.keys
            .read()
            .await
            .values()
            .filter(|k| k.provider_id == provider_id)
            .cloned()
            .collect()
    }

    /// Выполняет чат-запрос с автоматической ротацией ключей и провайдеров.
    ///
    /// Алгоритм:
    ///   1. Сортирует провайдеров (включённые сначала)
    ///   2. Для каждого провайдера сортирует ключи по стратегии
    ///   3. Пробует каждый ключ до первого успеха
    ///   4. При retriable ошибке — переходит к следующему ключу
    ///   5. При успехе — возвращает ответ с информацией о использованном ключе
    ///
    /// Если все ключи всех провайдеров исчерпаны — возвращает `AIError::AllKeysExhausted`.
    pub async fn chat_completion_with_rotation(
        &self,
        request: ChatRequest,
        preferred_provider: Option<ProviderType>,
    ) -> Result<RotatedChatResponse, AIError> {
        let provs = self.providers.read().await;
        let mut keys = self.keys.read().await.clone(); // клон: будем обновлять статистику ошибок

        // Фильтруем включённые провайдеры
        let mut active_providers: Vec<&ProviderConfig> = provs
            .iter()
            .filter(|p| p.is_enabled)
            .collect();

        // Если указан предпочитаемый провайдер — ставим его первым
        if let Some(pref) = &preferred_provider {
            active_providers.sort_by(|a, b| {
                let a_pref = a.provider_type == *pref;
                let b_pref = b.provider_type == *pref;
                b_pref.cmp(&a_pref)
            });
        }

        let mut total_keys_tried = 0;
        let mut last_error: Option<AIError> = None;

        for provider_config in active_providers.iter() {
            // Получаем ключи для этого провайдера (клонируем, чтобы потом мутировать статистику в `keys`)
            let mut provider_keys: Vec<ProviderKeyConfig> = keys
                .values()
                .filter(|k| k.provider_id == provider_config.id && k.is_active)
                .cloned()
                .collect();

            // Фильтруем ключи, которые не заблокированы backoff'ом
            let now = Utc::now();
            provider_keys.retain(|k| {
                match &k.blocked_until {
                    Some(blocked_until) => {
                        let blocked_time: Option<DateTime<Utc>> =
                            blocked_until.parse().ok();
                        match blocked_time {
                            Some(t) => t <= now,
                            None => true, // не удалось распарсить — считаем не заблокированным
                        }
                    }
                    None => true,
                }
            });

            if provider_keys.is_empty() {
                debug!(
                    "Провайдер {} не имеет доступных ключей, пропускаем",
                    provider_config.name
                );
                continue;
            }

            // Сортируем ключи по стратегии
            match self.strategy {
                RotationStrategy::FastestFirst => {
                    provider_keys.sort_by(|a, b| {
                        let a_lat = a.avg_latency_ms.unwrap_or(u64::MAX);
                        let b_lat = b.avg_latency_ms.unwrap_or(u64::MAX);
                        a_lat.cmp(&b_lat)
                    });
                }
                RotationStrategy::RoundRobin => {
                    // Round-robin не требует сортировки (порядок вставки)
                }
                RotationStrategy::Random => {
                    // Для случайного порядка можно перемешать, но для детерминизма оставляем как есть
                }
            }

            // Создаём провайдер напрямую (без кэширующей фабрики)
            let ai_provider = create_provider(provider_config);

            // Пробуем каждый ключ этого провайдера
            for key_config in provider_keys.iter() {
                total_keys_tried += 1;

                // Расшифровываем ключ
                let api_key = match crate::encryption::decrypt_api_key(&key_config.encrypted_key) {
                    Ok(k) => k,
                    Err(e) => {
                        error!("Не удалось расшифровать ключ {}: {}", key_config.id, e);
                        continue;
                    }
                };

                debug!(
                    "Пробуем ключ {} провайдера {} (latency={:?} ms, errors={})",
                    key_config.id,
                    provider_config.name,
                    key_config.avg_latency_ms,
                    key_config.error_count
                );

                let start = std::time::Instant::now();
                let result = ai_provider.chat_completion(&api_key, request.clone()).await;
                let _elapsed = start.elapsed().as_millis() as u64;

                match result {
                    Ok(response) => {
                        // Успех — сбрасываем счётчик ошибок и запоминаем latency ключа
                        if let Some(k) = keys.get_mut(&key_config.id) {
                            k.error_count = 0;
                            k.blocked_until = None;
                            k.avg_latency_ms = Some(_elapsed);
                        }
                        *self.keys.write().await = keys.clone();
                        info!(
                            "Успешный ответ от провайдера {}, ключ {}",
                            provider_config.name, key_config.id
                        );
                        return Ok(RotatedChatResponse {
                            response,
                            provider_type: provider_config.provider_type.clone(),
                            provider_name: provider_config.name.clone(),
                            key_id: key_config.id.clone(),
                            keys_tried: total_keys_tried,
                        });
                    }
                    Err(e) => {
                        last_error = Some(e.clone());

                        // Если ошибка не retriable (например, 401 неверный ключ) — пропускаем ключ
                        if !ai_provider.is_retriable_error(&e) {
                            warn!(
                                "Ключ {} провайдера {} вернул не-retriable ошибку: {}. Ключ пропущен.",
                                key_config.id, provider_config.name, e
                            );
                            continue;
                        }

                        // Retriable ошибка (429, 5xx, сеть) — блокируем ключ на backoff и идём дальше.
                        // Блокировка видна и при следующем вызове: ключ с blocked_until в будущем отфильтровывается.
                        let status = status_of(&e);
                        if let Some(k) = keys.get_mut(&key_config.id) {
                            k.error_count = k.error_count.saturating_add(1);
                            let secs = backoff_secs(k.error_count, status.as_deref());
                            k.blocked_until = Some((Utc::now() + Duration::seconds(secs as i64)).to_rfc3339());
                            warn!(
                                "Ключ {} провайдера {}: ошибка {:?} (статус {:?}) → блокировка на {} с (error_count={})",
                                key_config.id, provider_config.name, e, status, secs, k.error_count
                            );
                        }
                        continue;
                    }
                }
            }

            debug!(
                "Все ключи провайдера {} исчерпаны, переходим к следующему провайдеру",
                provider_config.name
            );
        }

        // Все провайдеры и ключи исчерпаны — сохраняем обновлённую статистику ошибок
        *self.keys.write().await = keys;
        Err(match last_error {
            Some(e) => AIError::AllKeysExhausted {
                provider: format!("все провайдеры (последняя ошибка: {e})"),
            },
            None => AIError::AllKeysExhausted {
                provider: "нет доступных ключей".to_string(),
            },
        })
    }

    /// Автотестирование всех ключей всех провайдеров.
    ///
    /// Отправляет тестовый запрос к каждому ключу, измеряет latency,
    /// обновляет `avg_latency_ms` и `error_count` в конфигурации ключа.
    ///
    /// Возвращает результаты тестирования для каждого ключа.
    pub async fn test_all_keys(&self, db: &crate::db::AIProviderDB) -> Vec<LatencyResult> {
        let _ = db; // БД в теле не используется — для совместимости сигнатуры
        self.test_all_keys_owned().await
    }

    /// Тест всех активных ключей по in-memory состоянию ротации (без borrowing БД
    /// через .await — это важно для Send-фьючер Tauri-команд).
    pub async fn test_all_keys_owned(&self) -> Vec<LatencyResult> {
        let provs = self.providers.read().await.clone();
        let keys = self.keys.read().await.clone();
        let mut results = Vec::new();

        for provider_config in &provs {
            if !provider_config.is_enabled {
                continue;
            }

            let ai_provider = create_provider(provider_config);

            let provider_keys: Vec<&ProviderKeyConfig> = keys
                .values()
                .filter(|k| k.provider_id == provider_config.id && k.is_active)
                .collect();

            for key_config in provider_keys {
                let api_key = match crate::encryption::decrypt_api_key(&key_config.encrypted_key) {
                    Ok(k) => k,
                    Err(e) => {
                        results.push(LatencyResult {
                            provider: provider_config.name.clone(),
                            key_id: key_config.id.clone(),
                            latency_ms: 0,
                            success: false,
                            error_message: Some(format!("ошибка расшифрования: {e}")),
                        });
                        continue;
                    }
                };

                match ai_provider.test_connection(&api_key).await {
                    Ok(latency) => {
                        results.push(latency.clone());
                        debug!(
                            "Ключ {} ({}): success={}, latency={} ms",
                            key_config.id,
                            provider_config.name,
                            latency.success,
                            latency.latency_ms
                        );
                    }
                    Err(e) => {
                        results.push(LatencyResult {
                            provider: provider_config.name.clone(),
                            key_id: key_config.id.clone(),
                            latency_ms: 0,
                            success: false,
                            error_message: Some(e.to_string()),
                        });
                    }
                }
            }
        }

        results
    }

    /// Устанавливает стратегию ротации.
    pub fn set_strategy(&mut self, strategy: RotationStrategy) {
        self.strategy = strategy;
    }

    /// Возвращает текущую стратегию ротации.
    pub fn strategy(&self) -> RotationStrategy {
        self.strategy.clone()
    }
}

impl Default for KeyRotation {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotation_strategy_default() {
        let rotation = KeyRotation::new();
        assert_eq!(rotation.strategy(), RotationStrategy::FastestFirst);
    }

    #[test]
    fn test_backoff_429_fixed_15min() {
        assert_eq!(backoff_secs(1, Some("429")), 15 * 60);
        assert_eq!(backoff_secs(9, Some("429")), 15 * 60); // не зависит от счётчика
    }

    #[test]
    fn test_backoff_5xx_exponential_capped() {
        assert_eq!(backoff_secs(1, Some("503")), 60);
        assert_eq!(backoff_secs(2, Some("503")), 120);
        assert_eq!(backoff_secs(3, Some("502")), 240);
        assert_eq!(backoff_secs(10, Some("500")), 30 * 60); // cap 30 минут
        assert_eq!(backoff_secs(5, None), 960); // 60 * 2^4
        assert_eq!(backoff_secs(6, None), 30 * 60); // cap 30 минут
    }

    #[test]
    fn test_backoff_other_retriable_60s() {
        assert_eq!(backoff_secs(1, Some("408")), 60);
    }

    #[test]
    fn test_status_of_http_error() {
        let e = AIError::Http { provider: "nvidia".into(), status: Some("429".into()), message: "rl".into() };
        assert_eq!(status_of(&e), Some("429".to_string()));
        let e2 = AIError::Config("x".into());
        assert_eq!(status_of(&e2), None);
    }
}

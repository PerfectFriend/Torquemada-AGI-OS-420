//! Модуль автотестирования ключей: проверка работоспособности всех ключей,
//! измерение latency, обновление статистики в БД.
//!
//! Тестирование выполняет:
//!   1. Для каждого включённого провайдера и каждого активного ключа
//!   2. Отправляет тестовый запрос ("ping")
//!   3. Измеряет время до первого ответа (latency)
//!   4. Обновляет avg_latency_ms и error_count в конфигурации ключа
//!   5. Записывает результат в таблицу key_stats

use crate::db::AIProviderDB;
use crate::{AIError, AIProvider, LatencyResult, ProviderKeyConfig};
use crate::rotation::KeyRotation;
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Менеджер тестирования: координирует проверку всех ключей всех провайдеров.
pub struct TestingManager {
    rotation: Arc<RwLock<KeyRotation>>,
    db: Arc<AIProviderDB>,
}

impl TestingManager {
    pub fn new(rotation: KeyRotation, db: AIProviderDB) -> Self {
        Self {
            rotation: Arc::new(RwLock::new(rotation)),
            db: Arc::new(db),
        }
    }

    /// Запускает полное тестирование всех ключей всех провайдеров.
    ///
    /// Возвращает векторы результатов для каждого ключа.
    /// После тестирования обновляет БД: avg_latency_ms, error_count, blocked_until.
    pub async fn test_all_providers(&self) -> Result<Vec<LatencyResult>, AIError> {
        info!("Начало автотестирования всех ключей провайдеров");

        let rotation = self.rotation.read().await;
        let results = rotation.test_all_keys(&*self.db).await;

        // Обновляем БД результатами тестирования
        for result in &results {
            // Находим ключ по ID, чтобы обновить статистику
            let keys = self.db.list_all_keys().map_err(|e| AIError::Database(e.to_string()))?;
            if let Some(key) = keys.iter().find(|k| k.id == result.key_id) {
                let now = Utc::now().to_rfc3339();

                if result.success {
                    // Успешно — обновляем latency, сбрасываем ошибки, убираем блокировку
                    self.db.update_key_stats(
                        &result.key_id,
                        Some(result.latency_ms),
                        0,
                        None,
                    ).map_err(|e| { error!("не удалось обновить статистику ключа {}: {}", result.key_id, e); AIError::Database(e.to_string()) })?;

                    self.db.mark_key_tested(&result.key_id, &now)
                        .map_err(|e| { error!("не удалось отметить тестирование ключа {}: {}", result.key_id, e); AIError::Database(e.to_string()) })?;

                    self.db.record_test_result(
                        &result.key_id,
                        &key.provider_id,
                        result.latency_ms,
                        true,
                        None,
                    ).map_err(|e| { error!("не удалось записать результат теста: {}", e); AIError::Database(e.to_string()) })?;

                    info!(
                        "Ключ {} ({}) прошёл тест: {} мс",
                        result.key_id, result.provider, result.latency_ms
                    );
                } else {
                    // Ошибка — увеличиваем error_count, возможная блокировка
                    let new_error_count = key.error_count + 1;
                    let blocked_until = if new_error_count >= 3 {
                        // Блокируем на 30 минут при 3+ последовательных ошибках
                        let blocked = Utc::now() + chrono::Duration::minutes(30);
                        Some(blocked.to_rfc3339())
                    } else {
                        None
                    };

                    self.db.update_key_stats(
                        &result.key_id,
                        None,
                        new_error_count,
                        blocked_until.as_deref(),
                    ).map_err(|e| { error!("не удалось обновить статистику ключа {}: {}", result.key_id, e); AIError::Database(e.to_string()) })?;

                    self.db.mark_key_tested(&result.key_id, &now)
                        .map_err(|e| { error!("не удалось отметить тестирование ключа {}: {}", result.key_id, e); AIError::Database(e.to_string()) })?;

                    self.db.record_test_result(
                        &result.key_id,
                        &key.provider_id,
                        0,
                        false,
                        result.error_message.as_deref(),
                    ).map_err(|e| { error!("не удалось записать результат теста: {}", e); AIError::Database(e.to_string()) })?;

                    warn!(
                        "Ключ {} ({}) не прошёл тест: {}, ошибок: {}, заблокирован до: {:?}",
                        result.key_id,
                        result.provider,
                        result.error_message.as_deref().unwrap_or("неизвестно"),
                        new_error_count,
                        blocked_until
                    );
                }
            }
        }

        info!("Автотестирование завершено: протестировано {} ключей", results.len());
        Ok(results)
    }

    /// Тестирует один конкретный ключ.
    pub async fn test_single_key(&self, key_id: &str) -> Result<LatencyResult, AIError> {
        let rotation = self.rotation.read().await;
        let keys = self.db.list_all_keys().map_err(|e| AIError::Database(e.to_string()))?;

        let key = keys.iter().find(|k| k.id == key_id)
            .ok_or_else(|| AIError::KeyNotFound(key_id.to_string()))?;

        // Находим конфигурацию провайдера для этого ключа
        let providers = rotation.list_providers().await;
        let provider_config = providers.iter().find(|p| p.id == key.provider_id)
            .ok_or_else(|| AIError::ProviderNotFound(key.provider_id.clone()))?;

        let ai_provider = crate::rotation::create_provider(provider_config);
        let api_key = crate::encryption::decrypt_api_key(&key.encrypted_key)?;

        let result = ai_provider.test_connection(&api_key).await?;

        // Обновляем БД
        let now = Utc::now().to_rfc3339();
        if result.success {
            self.db.update_key_stats(&key_id, Some(result.latency_ms), 0, None)?;
            self.db.mark_key_tested(&key_id, &now)?;
            self.db.record_test_result(&key_id, &key.provider_id, result.latency_ms, true, None)?;
        } else {
            self.db.update_key_stats(&key_id, None, key.error_count + 1, None)?;
            self.db.mark_key_tested(&key_id, &now)?;
            self.db.record_test_result(&key_id, &key.provider_id, 0, false, result.error_message.as_deref())?;
        }

        info!("Ключ {} протестирован: success={}, latency={} мс", key_id, result.success, result.latency_ms);
        Ok(result)
    }

    /// Возвращает статистику по всем ключам (для отображения в UI).
    pub async fn get_all_keys_status(&self) -> Result<Vec<KeyStatusInfo>, AIError> {
        let keys = self.db.list_all_keys().map_err(|e| AIError::Database(e.to_string()))?;
        let providers = self.db.list_providers().map_err(|e| AIError::Database(e.to_string()))?;

        let mut statuses = Vec::new();
        for key in keys {
            let provider = providers.iter().find(|p| p.id == key.provider_id);
            statuses.push(KeyStatusInfo {
                key_id: key.id.clone(),
                provider_id: key.provider_id.clone(),
                provider_name: provider.map(|p| p.name.clone()).unwrap_or_default(),
                provider_type: provider.map(|p| format!("{:?}", p.provider_type)).unwrap_or_default(),
                nickname: key.nickname.clone(),
                is_active: key.is_active,
                last_tested: key.last_tested.clone(),
                avg_latency_ms: key.avg_latency_ms,
                error_count: key.error_count,
                blocked_until: key.blocked_until.clone(),
                is_blocked: key.blocked_until.as_ref().map_or(false, |bu| {
                    bu.parse::<chrono::DateTime<chrono::Utc>>()
                        .map_or(false, |dt| dt > chrono::Utc::now())
                }),
            });
        }

        Ok(statuses)
    }

    /// Запускает периодическое автотестирование в фоновом режиме.
    ///
    /// `interval_secs` — интервал между проверками (по умолчанию 3600 сек = 1 час).
    /// Функция не возвращается (бесконечный цикл), должна запускаться в отдельной задаче tokio.
    pub async fn run_periodic_testing(&self, interval_secs: u64) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

        info!("Фоновое автотестирование запущено: интервал {} сек", interval_secs);

        loop {
            interval.tick().await;
            debug!("Запланированное автотестирование ключей");

            if let Err(e) = self.test_all_providers().await {
                error!("Ошибка фонового автотестирования: {e}");
            }
        }
    }
}

/// Информация о статусе ключа для отображения в UI.
#[derive(Debug, Clone)]
pub struct KeyStatusInfo {
    pub key_id: String,
    pub provider_id: String,
    pub provider_name: String,
    pub provider_type: String,
    pub nickname: Option<String>,
    pub is_active: bool,
    pub last_tested: Option<String>,
    pub avg_latency_ms: Option<u64>,
    pub error_count: u32,
    pub blocked_until: Option<String>,
    pub is_blocked: bool,
}

impl TestingManager {
    /// Создаёт TestingManager из существующих компонентов.
    pub async fn from_components(
        providers: Vec<crate::ProviderConfig>,
        keys: Vec<ProviderKeyConfig>,
        db: AIProviderDB,
    ) -> Self {
        let mut rotation = KeyRotation::new();
        for p in providers {
            rotation.add_provider(p).await;
        }
        for k in keys {
            rotation.add_key(k).await;
        }

        Self {
            rotation: Arc::new(tokio::sync::RwLock::new(rotation)),
            db: Arc::new(db),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_status_info_creation() {
        let status = KeyStatusInfo {
            key_id: "key-1".to_string(),
            provider_id: "prov-1".to_string(),
            provider_name: "OpenAI".to_string(),
            provider_type: "OpenAI".to_string(),
            nickname: Some("Основной ключ".to_string()),
            is_active: true,
            last_tested: None,
            avg_latency_ms: Some(150),
            error_count: 0,
            blocked_until: None,
            is_blocked: false,
        };

        assert_eq!(status.key_id, "key-1");
        assert!(status.is_active);
        assert!(!status.is_blocked);
        assert_eq!(status.avg_latency_ms, Some(150));
    }
}

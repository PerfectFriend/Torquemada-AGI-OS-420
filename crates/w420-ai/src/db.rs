//! Модуль базы данных: хранение конфигурации AI-провайдеров и ключей в SQLite.
//!
//! База данных хранится в ~/.w420/ai_providers.db.
//!
//! Схема:
//!   - providers: список провайдеров (OpenAI, Anthropic, Google и т.д.)
//!   - provider_keys: API-ключи каждого провайдера (зашифрованные)
//!   - key_stats: статистика использования ключей (latency, ошибки, блокировки)

use crate::{
    AIError, ChatResponse, LatencyResult, ProviderConfig, ProviderKeyConfig, ProviderType,
    RotationStrategy,
};
use chrono::{Utc, DateTime};
use rusqlite::{params, Connection, OpenFlags};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Обёртка над соединением SQLite для операций с провайдерами и ключами.
pub struct AIProviderDB {
    conn: Connection,
    db_path: PathBuf,
}

impl AIProviderDB {
    /// Открывает (или создаёт) базу данных и применяет схему.
    pub fn open() -> Result<Self, AIError> {
        let db_path = Self::default_db_path()?;
        let dir = db_path.parent()
            .ok_or_else(|| AIError::Database("не удалось определить директорию БД".into()))?;
        fs_utils::create_dir_all(dir).map_err(|e| AIError::Database(e.to_string()))?;

        let flags = OpenFlags::default()
            | OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE;

        let conn = Connection::open_with_flags(&db_path, flags)
            .map_err(|e| AIError::Database(format!("не удалось открыть БД {db_path:?}: {e}")))?;

        let db = Self { conn, db_path: db_path.clone() };
        db.apply_schema()?;
        info!("База данных AI-провайдеров открыта: {:?}", db_path);
        Ok(db)
    }

    /// Возвращает путь по умолчанию: ~/.w420/ai_providers.db
    fn default_db_path() -> Result<PathBuf, AIError> {
        let home = std::env::var("HOME")
            .map_err(|e| AIError::Database(format!("HOME не задан: {e}")))?;
        Ok(Path::new(&home).join(".w420").join("ai_providers.db"))
    }

    /// Применяет схему базы данных (создаёт таблицы, если не существуют).
    fn apply_schema(&self) -> Result<(), AIError> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS providers (
                id TEXT PRIMARY KEY,
                provider_type TEXT NOT NULL,
                name TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                models TEXT DEFAULT '[]',
                is_enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS provider_keys (
                id TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL REFERENCES providers(id),
                nickname TEXT,
                encrypted_key TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                last_tested TEXT,
                avg_latency_ms INTEGER,
                error_count INTEGER DEFAULT 0,
                blocked_until TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS key_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT NOT NULL REFERENCES provider_keys(id),
                provider_id TEXT NOT NULL,
                latency_ms INTEGER NOT NULL,
                success INTEGER NOT NULL DEFAULT 0,
                error_message TEXT,
                tested_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_provider_keys_provider_id ON provider_keys(provider_id);
            CREATE INDEX IF NOT EXISTS idx_key_stats_key_id ON key_stats(key_id);
            CREATE INDEX IF NOT EXISTS idx_key_stats_tested_at ON key_stats(tested_at);

            -- Результаты тестирования отдельных моделей (для сортировки по скорости)
            CREATE TABLE IF NOT EXISTS model_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_id TEXT NOT NULL,
                model TEXT NOT NULL,
                success INTEGER NOT NULL DEFAULT 0,
                latency_ms INTEGER NOT NULL DEFAULT 0,
                tokens_used INTEGER,
                tokens_per_sec REAL,
                response_preview TEXT,
                error_message TEXT,
                tested_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_model_stats_provider ON model_stats(provider_id, model);
        "#,
        ).map_err(|e| AIError::Database(format!("ошибка применения схемы: {e}")))?;

        Ok(())
    }

    /// Возвращает путь к файлу БД.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    // ==================== ПРОВАЙДЕРЫ ====================

    /// Добавляет нового провайдера в БД.
    pub fn add_provider(&self, config: &ProviderConfig) -> Result<(), AIError> {
        let models_json = serde_json::to_string(&config.models)
            .map_err(|e| AIError::Database(format!("ошибка сериализации моделей: {e}")))?;

        self.conn.execute(
            "INSERT INTO providers (id, provider_type, name, endpoint, models, is_enabled, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                config.id,
                serde_json::to_string(&config.provider_type).map_err(|e| AIError::Database(e.to_string()))?,
                config.name,
                config.endpoint,
                models_json,
                config.is_enabled as i32,
                config.created_at,
            ],
        ).map_err(|e| AIError::Database(format!("ошибка вставки провайдера: {e}")))?;

        debug!("Провайдер {} добавлен в БД", config.name);
        Ok(())
    }

    /// Возвращает список всех провайдеров.
    pub fn list_providers(&self) -> Result<Vec<ProviderConfig>, AIError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, provider_type, name, endpoint, models, is_enabled, created_at FROM providers"
        ).map_err(|e| AIError::Database(format!("ошибка подготовки запроса: {e}")))?;

        let rows = stmt.query_map([], |row| {
            let provider_type_str: String = row.get(1)?;
            let provider_type: ProviderType = serde_json::from_str(&provider_type_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e)))?;

            let models_json: String = row.get(4)?;
            let models: Vec<String> = serde_json::from_str(&models_json)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e)))?;

            Ok(ProviderConfig {
                id: row.get(0)?,
                provider_type,
                name: row.get(2)?,
                endpoint: row.get(3)?,
                models,
                is_enabled: row.get::<_, i32>(5)? != 0,
                created_at: row.get(6)?,
            })
        }).map_err(|e| AIError::Database(format!("ошибка выполнения запроса: {e}")))?;

        let mut providers = Vec::new();
        for row in rows {
            providers.push(row.map_err(|e| AIError::Database(format!("ошибка чтения строки: {e}")))?);
        }

        Ok(providers)
    }

    /// Обновляет провайдера (включён/выключен, модели, эндпоинт).
    pub fn update_provider(&self, config: &ProviderConfig) -> Result<(), AIError> {
        let models_json = serde_json::to_string(&config.models)
            .map_err(|e| AIError::Database(format!("ошибка сериализации моделей: {e}")))?;

        self.conn.execute(
            "UPDATE providers SET provider_type = ?2, name = ?3, endpoint = ?4, models = ?5, is_enabled = ?6 WHERE id = ?1",
            params![
                config.id,
                serde_json::to_string(&config.provider_type).map_err(|e| AIError::Database(e.to_string()))?,
                config.name,
                config.endpoint,
                models_json,
                config.is_enabled as i32,
            ],
        ).map_err(|e| AIError::Database(format!("ошибка обновления провайдера: {e}")))?;

        Ok(())
    }

    /// Удаляет провайдера и все его ключи.
    pub fn remove_provider(&self, provider_id: &str) -> Result<(), AIError> {
        self.conn.execute(
            "DELETE FROM provider_keys WHERE provider_id = ?1",
            params![provider_id],
        ).map_err(|e| AIError::Database(format!("ошибка удаления ключей: {e}")))?;

        self.conn.execute(
            "DELETE FROM providers WHERE id = ?1",
            params![provider_id],
        ).map_err(|e| AIError::Database(format!("ошибка удаления провайдера: {e}")))?;

        Ok(())
    }

    // ==================== КЛЮЧИ ====================

    /// Добавляет новый ключ к провайдеру.
    pub fn add_key(&self, key: &ProviderKeyConfig) -> Result<(), AIError> {
        self.conn.execute(
            "INSERT INTO provider_keys (id, provider_id, nickname, encrypted_key, is_active, last_tested, avg_latency_ms, error_count, blocked_until, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                key.id,
                key.provider_id,
                key.nickname,
                key.encrypted_key,
                key.is_active as i32,
                key.last_tested,
                key.avg_latency_ms,
                key.error_count,
                key.blocked_until,
                key.created_at,
            ],
        ).map_err(|e| AIError::Database(format!("ошибка вставки ключа: {e}")))?;

        debug!("Ключ {} добавлен для провайдера {}", key.id, key.provider_id);
        Ok(())
    }

    /// Возвращает все ключи для указанного провайдера.
    pub fn list_keys_for_provider(&self, provider_id: &str) -> Result<Vec<ProviderKeyConfig>, AIError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, provider_id, nickname, encrypted_key, is_active, last_tested, avg_latency_ms, error_count, blocked_until, created_at
             FROM provider_keys WHERE provider_id = ?1"
        ).map_err(|e| AIError::Database(format!("ошибка подготовки запроса: {e}")))?;

        let rows = stmt.query_map(params![provider_id], |row| {
            Ok(ProviderKeyConfig {
                id: row.get(0)?,
                provider_id: row.get(1)?,
                nickname: row.get(2)?,
                encrypted_key: row.get(3)?,
                is_active: row.get::<_, i32>(4)? != 0,
                last_tested: row.get(5)?,
                avg_latency_ms: row.get(6)?,
                error_count: row.get::<_, i32>(7)? as u32,
                blocked_until: row.get(8)?,
                created_at: row.get(9)?,
            })
        }).map_err(|e| AIError::Database(format!("ошибка выполнения запроса: {e}")))?;

        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(|e| AIError::Database(format!("ошибка чтения строки: {e}")))?);
        }

        Ok(keys)
    }

    /// Возвращает все ключи всех провайдеров (для загрузки в память при старте).
    pub fn list_all_keys(&self) -> Result<Vec<ProviderKeyConfig>, AIError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, provider_id, nickname, encrypted_key, is_active, last_tested, avg_latency_ms, error_count, blocked_until, created_at
             FROM provider_keys"
        ).map_err(|e| AIError::Database(format!("ошибка подготовки запроса: {e}")))?;

        let rows = stmt.query_map([], |row| {
            Ok(ProviderKeyConfig {
                id: row.get(0)?,
                provider_id: row.get(1)?,
                nickname: row.get(2)?,
                encrypted_key: row.get(3)?,
                is_active: row.get::<_, i32>(4)? != 0,
                last_tested: row.get(5)?,
                avg_latency_ms: row.get(6)?,
                error_count: row.get::<_, i32>(7)? as u32,
                blocked_until: row.get(8)?,
                created_at: row.get(9)?,
            })
        }).map_err(|e| AIError::Database(format!("ошибка выполнения запроса: {e}")))?;

        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(|e| AIError::Database(format!("ошибка чтения строки: {e}")))?);
        }

        Ok(keys)
    }

    /// Обновляет статистику ключа после тестирования или использования.
    pub fn update_key_stats(
        &self,
        key_id: &str,
        avg_latency_ms: Option<u64>,
        error_count: u32,
        blocked_until: Option<&str>,
    ) -> Result<(), AIError> {
        self.conn.execute(
            "UPDATE provider_keys SET avg_latency_ms = ?2, error_count = ?3, blocked_until = ?4 WHERE id = ?1",
            params![key_id, avg_latency_ms, error_count, blocked_until],
        ).map_err(|e| AIError::Database(format!("ошибка обновления статистики ключа: {e}")))?;

        Ok(())
    }

    /// Помечает ключ как протестированный (обновляет last_tested).
    pub fn mark_key_tested(&self, key_id: &str, tested_at: &str) -> Result<(), AIError> {
        self.conn.execute(
            "UPDATE provider_keys SET last_tested = ?2 WHERE id = ?1",
            params![key_id, tested_at],
        ).map_err(|e| AIError::Database(format!("ошибка отметки тестирования ключа: {e}")))?;

        Ok(())
    }

    /// Активирует или деактивирует ключ.
    pub fn set_key_active(&self, key_id: &str, is_active: bool) -> Result<(), AIError> {
        self.conn.execute(
            "UPDATE provider_keys SET is_active = ?2 WHERE id = ?1",
            params![key_id, is_active as i32],
        ).map_err(|e| AIError::Database(format!("ошибка изменения статуса ключа: {e}")))?;

        Ok(())
    }

    /// Удаляет ключ.
    pub fn remove_key(&self, key_id: &str) -> Result<(), AIError> {
        self.conn.execute(
            "DELETE FROM provider_keys WHERE id = ?1",
            params![key_id],
        ).map_err(|e| AIError::Database(format!("ошибка удаления ключа: {e}")))?;

        Ok(())
    }

    // ==================== СТАТИСТИКА ТЕСТИРОВАНИЯ ====================

    /// Записывает результат тестирования ключа.
    pub fn record_test_result(
        &self,
        key_id: &str,
        provider_id: &str,
        latency_ms: u64,
        success: bool,
        error_message: Option<&str>,
    ) -> Result<(), AIError> {
        let tested_at = Utc::now().to_rfc3339();
        let success_int: i32 = if success { 1 } else { 0 };

        self.conn.execute(
            "INSERT INTO key_stats (key_id, provider_id, latency_ms, success, error_message, tested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![key_id, provider_id, latency_ms, success_int, error_message, tested_at],
        ).map_err(|e| AIError::Database(format!("ошибка записи результата теста: {e}")))?;

        Ok(())
    }

    /// Возвращает историю тестирования для ключа (последние N записей).
    pub fn get_test_history(&self, key_id: &str, limit: i32) -> Result<Vec<TestResultRecord>, AIError> {
        let mut stmt = self.conn.prepare(
            "SELECT provider_id, latency_ms, success, error_message, tested_at FROM key_stats WHERE key_id = ?1 ORDER BY tested_at DESC LIMIT ?2"
        ).map_err(|e| AIError::Database(format!("ошибка подготовки запроса: {e}")))?;

        let rows = stmt.query_map(params![key_id, limit], |row| {
            Ok(TestResultRecord {
                provider_id: row.get(0)?,
                latency_ms: row.get(1)?,
                success: row.get::<_, i32>(2)? != 0,
                error_message: row.get(3)?,
                tested_at: row.get(4)?,
            })
        }).map_err(|e| AIError::Database(format!("ошибка выполнения запроса: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| AIError::Database(format!("ошибка чтения строки: {e}")))?);
        }

        Ok(results)
    }

    /// Записывает результат теста одной модели (latency + скорость генерации).
    pub fn record_model_test(
        &self,
        provider_id: &str,
        model: &str,
        success: bool,
        latency_ms: u64,
        tokens_used: Option<u32>,
        tokens_per_sec: Option<f64>,
        response_preview: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<(), AIError> {
        let tested_at = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO model_stats (provider_id, model, success, latency_ms, tokens_used, tokens_per_sec, response_preview, error_message, tested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                provider_id,
                model,
                if success { 1 } else { 0 },
                latency_ms,
                tokens_used,
                tokens_per_sec,
                response_preview,
                error_message,
                tested_at,
            ],
        ).map_err(|e| AIError::Database(format!("ошибка записи статистики модели: {e}")))?;
        Ok(())
    }

    /// Последние результаты тестов моделей провайдера (по одной записи на модель — самая свежая).
    pub fn list_model_stats(&self, provider_id: &str) -> Result<Vec<ModelStatRecord>, AIError> {
        let mut stmt = self.conn.prepare(
            "SELECT model, success, latency_ms, tokens_used, tokens_per_sec, response_preview, error_message, tested_at
             FROM model_stats WHERE provider_id = ?1
             AND id IN (SELECT MAX(id) FROM model_stats WHERE provider_id = ?1 GROUP BY model)
             ORDER BY model",
        ).map_err(|e| AIError::Database(format!("ошибка подготовки запроса: {e}")))?;
        let rows = stmt.query_map(params![provider_id], |row| {
            Ok(ModelStatRecord {
                model: row.get(0)?,
                success: row.get::<_, i32>(1)? != 0,
                latency_ms: row.get(2)?,
                tokens_used: row.get(3)?,
                tokens_per_sec: row.get(4)?,
                response_preview: row.get(5)?,
                error_message: row.get(6)?,
                tested_at: row.get(7)?,
            })
        }).map_err(|e| AIError::Database(format!("ошибка выполнения запроса: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| AIError::Database(format!("ошибка чтения строки: {e}")))?);
        }
        Ok(out)
    }

    /// Закрывает соединение с БД.
    pub fn close(self) -> Result<(), AIError> {
        self.conn.close().map_err(|_e| AIError::Database("ошибка закрытия БД".to_string()))?;
        Ok(())
    }
}

/// Запись результата тестирования ключа.
#[derive(Debug, Clone)]
pub struct TestResultRecord {
    pub provider_id: String,
    pub latency_ms: u64,
    pub success: bool,
    pub error_message: Option<String>,
    pub tested_at: String,
}

/// Последний результат теста одной модели (для UI и сортировки по скорости).
#[derive(Debug, Clone)]
pub struct ModelStatRecord {
    pub model: String,
    pub success: bool,
    pub latency_ms: u64,
    pub tokens_used: Option<u32>,
    pub tokens_per_sec: Option<f64>,
    pub response_preview: Option<String>,
    pub error_message: Option<String>,
    pub tested_at: String,
}

/// Вспомогательный модуль для создания директорий (rusqlite не экспортирует fs).
mod fs_utils {
    use std::fs;
    use std::path::Path;

    pub fn create_dir_all(path: &Path) -> Result<(), String> {
        fs::create_dir_all(path).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProviderType;
    use chrono::Utc;

    #[test]
    fn test_db_create_and_list_providers() {
        // Используем временную БД в памяти для тестирования схемы
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE providers (
                id TEXT PRIMARY KEY,
                provider_type TEXT NOT NULL,
                name TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                models TEXT DEFAULT '[]',
                is_enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL
            );
        "#,
        ).unwrap();

        let config = ProviderConfig {
            id: "test-provider-1".to_string(),
            provider_type: ProviderType::OpenAI,
            name: "Test OpenAI".to_string(),
            endpoint: "https://api.openai.com/v1".to_string(),
            models: vec!["gpt-4o".to_string()],
            is_enabled: true,
            created_at: Utc::now().to_rfc3339(),
        };

        let models_json = serde_json::to_string(&config.models).unwrap();
        conn.execute(
            "INSERT INTO providers (id, provider_type, name, endpoint, models, is_enabled, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                config.id,
                serde_json::to_string(&config.provider_type).unwrap(),
                config.name,
                config.endpoint,
                models_json,
                config.is_enabled as i32,
                config.created_at,
            ],
        ).unwrap();

        let mut stmt = conn.prepare("SELECT id, name FROM providers").unwrap();
        let rows = stmt
            .query_map([], |row| Ok(row.get::<_, String>(1)?))
            .unwrap()
            .map(|row| row.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], "Test OpenAI");
    }
}

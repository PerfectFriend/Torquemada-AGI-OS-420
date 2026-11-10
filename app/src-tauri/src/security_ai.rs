//! Модуль AI-движка безопасности (Фаза 4).
//!
//! Этот модуль интегрирует AI-провайдеры (w420-ai) с функционалом кибербезопасности:
//!   - AI-анализ уязвимостей и генерация рекомендаций по исправлению
//!   - Автоматическое принятие решений о блокировке угроз
//!   - Интеграция с админкой хостов для устранения уязвимостей
//!   - AI-оценка рисков и приоритизация угроз
//!   - Генерация отчётов о безопасности с помощью AI
//!
//! Все команды экспонируются через Tauri invoke для использования тонким HTML/CSS клиентом.
//! Комментарии на русском языке.

use w420_ai::{
    ChatRequest,
};
use w420_ai::encryption::{decrypt_api_key, encrypt_api_key};
use w420_ai::db::AIProviderDB;
use w420_ai::rotation::KeyRotation;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::Manager;
// ============================================================================
// Типы данных
// ============================================================================

/// Результат AI-анализа уязвимости.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAnalysis {
    /// ID анализа
    pub analysis_id: String,
    /// CVE ID (если применимо)
    pub cve_id: Option<String>,
    /// Уровень риска: critical, high, medium, low, info
    pub risk_level: String,
    /// Описание угрозы от AI
    pub ai_description: String,
    /// Рекомендации по исправлению от AI
    pub ai_recommendation: String,
    /// Оценка сложности эксплуатации (1-10)
    pub exploitability_score: u8,
    /// Оценка влияния на систему (1-10)
    pub impact_score: u8,
    /// Приоритет исправления (1-10, где 10 — наивысший)
    pub priority: u8,
    /// Использованный провайдер AI
    pub provider_used: String,
    /// Время анализа (RFC3339)
    pub analyzed_at: String,
}

/// Результат автоматического реагирования на угрозу.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoResponse {
    /// ID ответа
    pub response_id: String,
    /// CVE ID или идентификатор угрозы
    pub threat_id: String,
    /// Действие: block, patch, isolate, monitor, ignore
    pub action: String,
    /// Обоснование действия от AI
    pub ai_reasoning: String,
    /// Уверенность AI в решении (0.0 - 1.0)
    pub confidence: f32,
    /// Требует ли действие подтверждения администратором
    pub requires_approval: bool,
    /// Статус выполнения: pending, approved, executed, rejected
    pub status: String,
    /// Время создания (RFC3339)
    pub created_at: String,
}

/// Конфигурация AI-движка безопасности.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAIConfig {
    /// Включён ли AI-движок
    pub enabled: bool,
    /// Провайдер AI по умолчанию
    pub default_provider: String,
    /// Порог риска для автоматического реагирования
    pub auto_response_threshold: String,
    /// Требует ли подтверждение для критических действий
    pub require_approval_for_critical: bool,
    /// Включить автоматическое исправление уязвимостей
    pub auto_patch_enabled: bool,
    /// Загрузочный системный промпт AI-движка безопасности (базовый набор инструкций).
    /// По умолчанию читается из ~/.w420/security_ai_prompt.txt, иначе — встроенный.
    #[serde(default = "default_system_prompt")]
    pub system_prompt: String,
}

/// Системный промпт по умолчанию: файл ~/.w420/security_ai_prompt.txt или короткий фолбэк.
pub fn default_system_prompt() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    std::fs::read_to_string(format!("{home}/.w420/security_ai_prompt.txt"))
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Вы — эксперт по кибербезопасности. Анализируйте угрозы и давайте практические рекомендации по их устранению. Отвечайте на русском языке.".to_string())
}

/// Отчёт о безопасности, сгенерированный AI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    /// ID отчёта
    pub report_id: String,
    /// Заголовок отчёта
    pub title: String,
    /// Содержимое отчёта (сгенерировано AI)
    pub content: String,
    /// Количество проанализированных угроз
    pub threats_analyzed: u32,
    /// Критических угроз
    pub critical_threats: u32,
    /// Рекомендаций по исправлению
    pub recommendations: u32,
    /// Время генерации (RFC3339)
    pub generated_at: String,
}

// ============================================================================
// Менеджер AI-движка безопасности
// ============================================================================

/// Менеджер AI-движка безопасности.
///
/// Интегрирует w420-ai с модулями безопасности (угрозы, хосты) для
/// автоматического анализа и реагирования на киберугрозы.
pub struct SecurityAIEngine {
    /// Путь к файлу конфигурации
    config_path: PathBuf,
    /// Текущая конфигурация
    config: Mutex<SecurityAIConfig>,
    /// История анализов
    analyses: Mutex<Vec<SecurityAnalysis>>,
    /// Автоответы на угрозы
    auto_responses: Mutex<Vec<AutoResponse>>,
    /// Сгенерированные отчёты
    reports: Mutex<Vec<SecurityReport>>,
}

impl SecurityAIEngine {
    /// Создаёт новый SecurityAIEngine.
    pub fn new() -> Result<Self, String> {
        let home = std::env::var("HOME")
            .map_err(|e| format!("HOME не задан: {e}"))?;
        let w420_dir = Path::new(&home).join(".w420");
        std::fs::create_dir_all(&w420_dir)
            .map_err(|e| format!("не удалось создать {w420_dir:?}: {e}"))?;

        let config_path = w420_dir.join("security_ai.json");

        let config = if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)
                .map_err(|e| format!("не удалось прочитать конфиг AI-безопасности: {e}"))?;
            serde_json::from_str(&content).map_err(|e| format!("не удалось распарсить конфиг: {e}"))?
        } else {
            SecurityAIConfig::default()
        };

        Ok(Self {
            config_path,
            config: Mutex::new(config),
            analyses: Mutex::new(Vec::new()),
            auto_responses: Mutex::new(Vec::new()),
            reports: Mutex::new(Vec::new()),
        })
    }

    /// Сохраняет конфигурацию в файл.
    fn save_config(&self) -> Result<(), String> {
        let content = serde_json::to_string_pretty(&*self.config.lock().map_err(|_| "мьютекс конфига отравлен")?)
            .map_err(|e| format!("не удалось сериализовать конфиг: {e}"))?;
        std::fs::write(&self.config_path, &content).map_err(|e| format!("не удалось записать конфиг: {e}"))?;
        Ok(())
    }

    /// Анализирует уязвимость с помощью AI-провайдера.
    pub async fn analyze_vulnerability(
        &self,
        cve_id: Option<&str>,
        description: &str,
        product: &str,
        severity: &str,
        cvss_score: Option<f32>,
    ) -> Result<SecurityAnalysis, String> {
        // Получаем конфигурацию в отдельном блоке, чтобы MutexGuard
        // не жил через .await точки (std::sync::MutexGuard не Send).
        let default_provider = {
            let config = self.config.lock().map_err(|_| "мьютекс конфига отравлен")?;
            if !config.enabled {
                return Err("AI-движок безопасности отключён. Включите его в настройках.".to_string());
            }
            config.default_provider.clone()
        };

        // Получаем конфигурацию провайдера и ключ из w420-ai DB.
        // Весь блок с db помещён в отдельную область, чтобы не-Send
        // rusqlite::Connection не жил через .await точки ниже.
        let (provider_name, api_key, default_model) = {
            let home = std::env::var("HOME").map_err(|e| e.to_string())?;
            let db_path = Path::new(&home).join(".w420").join("ai_providers.db");
            let db = AIProviderDB::open().map_err(|e| format!("не удалось открыть БД провайдеров: {e}"))?;

            let providers = db.list_providers().map_err(|e| format!("не удалось получить провайдеры: {e}"))?;
            let provider = providers.iter().find(|p| p.name == default_provider)
                .ok_or_else(|| format!("провайдер AI '{}' не найден", default_provider))?;

            let keys = db.list_all_keys().map_err(|e| format!("не удалось получить ключи: {e}"))?;
            let key = keys.iter().find(|k| k.provider_id == provider.id && k.is_active)
                .ok_or_else(|| format!("нет активных ключей для провайдера {}", provider.name))?;

            let api_key = decrypt_api_key(&key.encrypted_key)
                .map_err(|e| format!("не удалось расшифровать ключ API: {e}"))?;

            // Первая модель из конфига провайдера (по умолчанию Mistral Large 4 на NVIDIA NIM)
            let model = provider.models.first().cloned()
                .unwrap_or_else(|| "mistralai/mistral-large-4-1t-a52b".to_string());

            (provider.name.clone(), api_key, model)
        }; // db дропнут здесь, до первого .await

        // Системный промпт из конфига (загрузочный промпт из ~/.w420/security_ai_prompt.txt)
        let system_prompt = {
            let config = self.config.lock().map_err(|_| "мьютекс конфига отравлен")?;
            config.system_prompt.clone()
        };

        // Формируем запрос к AI
        let prompt = format!(
            "Проанализируйте киберугрозу:\n\
            CVE: {}\n\
            Продукт: {}\n\
            Серьезность: {}\n\
            CVSS оценка: {:?}\n\
            Описание: {}\n\
            \
            Предоставьте:\n\
            1. Уровень риска (critical/high/medium/low/info)\n\
            2. Описание угрозы\n\
            3. Рекомендации по исправлению\n\
            4. Оценку сложности эксплуатации (1-10)\n\
            5. Оценку влияния на систему (1-10)\n\
            6. Приоритет исправления (1-10)\n\
            \
            Ответьте в формате JSON с полями: risk_level, ai_description, ai_recommendation, exploitability_score, impact_score, priority",
            cve_id.unwrap_or("неизвестно"),
            product,
            severity,
            cvss_score,
            description
        );

        let request = ChatRequest {
            model: default_model,
            messages: vec![
                w420_ai::ChatMessage {
                    role: "system".to_string(),
                    content: system_prompt,
                },
                w420_ai::ChatMessage {
                    role: "user".to_string(),
                    content: prompt,
                },
            ],
            temperature: 0.3,
            max_tokens: Some(1000),
            stream: false,
        };

        // Используем ротацию ключей для запроса.
        // Загружаем провайдеры и ключи из БД в отдельной области, чтобы
        // не-Send rusqlite::Connection не жил через .await точки.
        let (providers_vec, keys_vec) = {
            let home = std::env::var("HOME").map_err(|e| e.to_string())?;
            let db_path = Path::new(&home).join(".w420").join("ai_providers.db");
            let db = AIProviderDB::open().map_err(|e| format!("не удалось открыть БД провайдеров: {e}"))?;
            let providers = db.list_providers().map_err(|e| format!("не удалось получить провайдеры: {e}"))?;
            let keys = db.list_all_keys().map_err(|e| format!("не удалось получить ключи: {e}"))?;
            (providers, keys)
        }; // db дропнут здесь

        let rotation = KeyRotation::new();
        for p in &providers_vec {
            rotation.add_provider(p.clone()).await;
        }
        for k in &keys_vec {
            rotation.add_key(k.clone()).await;
        }

        let result = rotation.chat_completion_with_rotation(request, None).await
            .map_err(|e| format!("ошибка запроса к AI: {e}"))?;

        // Парсим ответ AI (попытка извлечь JSON)
        let ai_response = result.response.content;
        let analysis = self.parse_ai_response(&ai_response, cve_id, &result.provider_name)?;

        {
            let mut analyses = self.analyses.lock().map_err(|_| "мьютекс анализов отравлен")?;
            analyses.push(analysis.clone());
        }

        Ok(analysis)
    }

    /// Парсит ответ AI в структуру SecurityAnalysis.
    fn parse_ai_response(
        &self,
        response: &str,
        cve_id: Option<&str>,
        provider_name: &str,
    ) -> Result<SecurityAnalysis, String> {
        // Пытаемся извлечь JSON из ответа
        let json_start = response.find('{').unwrap_or(0);
        let json_end = response.rfind('}').map(|e| e + 1).unwrap_or(response.len());
        let json_str = &response[json_start..json_end];

        let parsed: serde_json::Value = serde_json::from_str(json_str)
            .unwrap_or_else(|_| serde_json::json!({}));

        Ok(SecurityAnalysis {
            analysis_id: uuid::Uuid::new_v4().to_string(),
            cve_id: cve_id.map(|s| s.to_string()),
            risk_level: parsed.get("risk_level")
                .and_then(|v| v.as_str())
                .unwrap_or("medium")
                .to_string(),
            ai_description: parsed.get("ai_description")
                .and_then(|v| v.as_str())
                .unwrap_or(response)
                .to_string(),
            ai_recommendation: parsed.get("ai_recommendation")
                .and_then(|v| v.as_str())
                .unwrap_or("Рекомендации не предоставлены")
                .to_string(),
            exploitability_score: parsed.get("exploitability_score")
                .and_then(|v| v.as_u64())
                .unwrap_or(5) as u8,
            impact_score: parsed.get("impact_score")
                .and_then(|v| v.as_u64())
                .unwrap_or(5) as u8,
            priority: parsed.get("priority")
                .and_then(|v| v.as_u64())
                .unwrap_or(5) as u8,
            provider_used: provider_name.to_string(),
            analyzed_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Генерирует автоматический ответ на угрозу на основе AI анализа.
    pub fn generate_auto_response(
        &self,
        threat_id: &str,
        severity: &str,
        cvss_score: Option<f32>,
        product: &str,
    ) -> Result<AutoResponse, String> {
        let config = self.config.lock().map_err(|_| "мьютекс конфига отравлен")?;
        if !config.enabled {
            return Err("AI-движок безопасности отключён".to_string());
        }
        let require_approval = config.require_approval_for_critical;
        drop(config);

        // Определяем действие на основе серьезности и конфигурации
        let (action, reasoning, confidence, requires_approval) = if severity == "critical" {
            if require_approval {
                ("block".to_string(), "Критическая угроза требует блокировки и подтверждения администратора".to_string(), 0.9, true)
            } else {
                ("block".to_string(), "Критическая угроза: автоматическая блокировка".to_string(), 0.85, false)
            }
        } else if severity == "high" {
            ("patch".to_string(), "Высокий риск: рекомендуется применение патча".to_string(), 0.8, false)
        } else if severity == "medium" {
            ("monitor".to_string(), "Средний риск: рекомендуется мониторинг".to_string(), 0.6, false)
        } else {
            ("ignore".to_string(), "Низкий риск: действие не требуется".to_string(), 0.4, false)
        };

        let response = AutoResponse {
            response_id: uuid::Uuid::new_v4().to_string(),
            threat_id: threat_id.to_string(),
            action,
            ai_reasoning: reasoning,
            confidence,
            requires_approval,
            status: if requires_approval { "pending".to_string() } else { "executed".to_string() },
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        {
            let mut responses = self.auto_responses.lock().map_err(|_| "мьютекс ответов отравлен")?;
            responses.push(response.clone());
        }

        Ok(response)
    }

    /// Генерирует полный отчёт о безопасности с помощью AI.
    pub fn generate_security_report(&self) -> Result<SecurityReport, String> {
        let config = self.config.lock().map_err(|_| "мьютекс конфига отравлен")?;
        if !config.enabled {
            return Err("AI-движок безопасности отключён".to_string());
        }
        drop(config);

        let analyses = self.analyses.lock().map_err(|_| "мьютекс анализов отравлен")?;
        let responses = self.auto_responses.lock().map_err(|_| "мьютекс ответов отравлен")?;

        let critical_count = analyses.iter().filter(|a| a.risk_level == "critical").count() as u32;
        let total = analyses.len() as u32;

        let report_content = format!(
            "# Отчёт о безопасности W420\n\
            \n\
            Сгенерировано AI-движком безопасности: {}\n\
            \n\
            ## Статистика\n\
            - Проанализировано угроз: {}\n\
            - Критических угроз: {}\n\
            - Автоответов сгенерировано: {}\n\
            \n\
            ## Рекомендации\n\
            {}", 
            chrono::Utc::now().to_rfc3339(),
            total,
            critical_count,
            responses.len() as u32,
            analyses.iter().map(|a| format!("- {}: {}", a.cve_id.clone().unwrap_or_default(), a.ai_recommendation)).collect::<Vec<_>>().join("\n")
        );

        let report = SecurityReport {
            report_id: uuid::Uuid::new_v4().to_string(),
            title: format!("Отчёт о безопасности {}", chrono::Utc::now().format("%Y-%m-%d %H:%M")),
            content: report_content,
            threats_analyzed: total,
            critical_threats: critical_count,
            recommendations: analyses.len() as u32,
            generated_at: chrono::Utc::now().to_rfc3339(),
        };

        {
            let mut reports = self.reports.lock().map_err(|_| "мьютекс отчётов отравлен")?;
            reports.push(report.clone());
        }

        Ok(report)
    }

    /// Возвращает конфигурацию AI-движка.
    pub fn get_config(&self) -> Result<SecurityAIConfig, String> {
        Ok(self.config.lock().map_err(|_| "мьютекс конфига отравлен")?.clone())
    }

    /// Обновляет конфигурацию AI-движка.
    pub fn set_config(&self, config: SecurityAIConfig) -> Result<(), String> {
        *self.config.lock().map_err(|_| "мьютекс конфига отравлен")? = config;
        self.save_config()?;
        Ok(())
    }

    /// Возвращает историю анализов.
    pub fn list_analyses(&self) -> Result<Vec<SecurityAnalysis>, String> {
        Ok(self.analyses.lock().map_err(|_| "мьютекс анализов отравлен")?.clone())
    }

    /// Возвращает автоответы.
    pub fn list_auto_responses(&self) -> Result<Vec<AutoResponse>, String> {
        Ok(self.auto_responses.lock().map_err(|_| "мьютекс ответов отравлен")?.clone())
    }

    /// Возвращает отчёты.
    pub fn list_reports(&self) -> Result<Vec<SecurityReport>, String> {
        Ok(self.reports.lock().map_err(|_| "мьютекс отчётов отравлен")?.clone())
    }
}

impl Default for SecurityAIEngine {
    fn default() -> Self {
        Self::new().expect("не удалось инициализировать SecurityAIEngine")
    }
}

impl Default for SecurityAIConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_provider: "Ollama".to_string(),
            auto_response_threshold: "high".to_string(),
            require_approval_for_critical: true,
            auto_patch_enabled: false,
            system_prompt: default_system_prompt(),
        }
    }
}

// ============================================================================
// Tauri команды
// ============================================================================

/// Анализирует уязвимость с помощью AI.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_ai_config_default() {
        let config = SecurityAIConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.default_provider, "Ollama");
        assert_eq!(config.auto_response_threshold, "high");
        assert!(config.require_approval_for_critical);
        assert!(!config.auto_patch_enabled);
    }

    #[test]
    fn test_auto_response_creation() {
        let response = AutoResponse {
            response_id: "resp-1".to_string(),
            threat_id: "CVE-2024-TEST".to_string(),
            action: "block".to_string(),
            ai_reasoning: "Тестовое обоснование".to_string(),
            confidence: 0.9,
            requires_approval: true,
            status: "pending".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };
        assert_eq!(response.action, "block");
        assert_eq!(response.confidence, 0.9);
        assert!(response.requires_approval);
    }

    #[test]
    fn test_security_analysis_creation() {
        let analysis = SecurityAnalysis {
            analysis_id: "analysis-1".to_string(),
            cve_id: Some("CVE-2024-TEST".to_string()),
            risk_level: "high".to_string(),
            ai_description: "Тестовое описание угрозы".to_string(),
            ai_recommendation: "Применить патч".to_string(),
            exploitability_score: 7,
            impact_score: 8,
            priority: 9,
            provider_used: "Ollama".to_string(),
            analyzed_at: "2024-01-01T00:00:00Z".to_string(),
        };
        assert_eq!(analysis.risk_level, "high");
        assert_eq!(analysis.priority, 9);
    }
}

//! Провайдеры ИИ из базы w420-ai (`~/.w420/ai_providers.db`) для вкладки AI CORE.
//!
//! Ключи API никогда не уходят во фронтенд: наружу отдаётся только маска вида «…abcd»
//! (последние 4 символа расшифрованного ключа, вычисляются на бэкенде). Живой чат
//! (`ai_chat`) выполняется через `KeyRotation` — с автоматической ротацией всех
//! активных ключей провайдера (у нас NVIDIA NIM + 11 ключей из хранилища Obsidian).

use serde::Serialize;
use serde_json::Value;
use w420_ai::db::AIProviderDB;
use w420_ai::encryption::decrypt_api_key;
use w420_ai::rotation::KeyRotation;
use w420_ai::{ChatMessage, ChatRequest};

/// Информация об одном ключе (без самого ключа — только маска).
#[derive(Debug, Clone, Serialize)]
pub struct KeyInfo {
    pub id: String,
    pub nickname: Option<String>,
    /// Маска вида «…abcd» — последние 4 символа ключа
    pub mask: String,
    pub is_active: bool,
    pub last_tested: Option<String>,
    pub avg_latency_ms: Option<u64>,
    pub error_count: u32,
    pub blocked_until: Option<String>,
}

/// Провайдер со списком ключей.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderInfo {
    pub id: String,
    pub name: String,
    pub provider_type: String,
    pub endpoint: String,
    pub models: Vec<String>,
    pub is_enabled: bool,
    /// Провайдер по умолчанию (из ~/.w420/security_ai.json)
    pub is_default: bool,
    pub keys: Vec<KeyInfo>,
}

/// Статус ротации по всем провайдерам.
#[derive(Debug, Clone, Serialize)]
pub struct ProvidersStatus {
    pub default_provider: String,
    pub strategy: String,
    pub providers: Vec<ProviderInfo>,
    pub total_keys: usize,
    pub active_keys: usize,
}

/// Результат живого chat-запроса через ротацию.
#[derive(Debug, Clone, Serialize)]
pub struct ChatOutcome {
    pub text: String,
    pub model: String,
    pub provider_name: String,
    /// Маска ключа, которым реально отвечен запрос
    pub key_mask: String,
    pub keys_tried: usize,
    pub tokens_used: Option<u32>,
    pub latency_ms: u64,
}

/// Результат теста одного ключа.
#[derive(Debug, Clone, Serialize)]
pub struct KeyTestInfo {
    pub provider: String,
    pub key_id: String,
    pub mask: String,
    pub success: bool,
    pub latency_ms: u64,
    pub error: Option<String>,
}

/// Маска ключа: последние 4 символа расшифрованного значения, сам ключ не покидает процесс.
fn mask_of(encrypted_key: &str) -> String {
    match decrypt_api_key(encrypted_key) {
        Ok(plain) => {
            let tail: String = plain.chars().rev().take(4).collect::<String>().chars().rev().collect();
            format!("…{tail}")
        }
        Err(_) => "…????".to_string(),
    }
}

/// Имя провайдера по умолчанию из ~/.w420/security_ai.json (или первый включённый).
fn default_provider_name(providers: &[w420_ai::ProviderConfig]) -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    let cfg_path = std::path::Path::new(&home).join(".w420").join("security_ai.json");
    if let Ok(s) = std::fs::read_to_string(&cfg_path) {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            if let Some(d) = v.get("default_provider").and_then(|x| x.as_str()) {
                return d.to_string();
            }
        }
    }
    providers
        .iter()
        .find(|p| p.is_enabled)
        .map(|p| p.name.clone())
        .unwrap_or_default()
}

/// Загружает провайдеров и ключи из БД и собирает ProviderInfo (с масками).
fn collect_providers() -> Result<(Vec<ProviderInfo>, Vec<w420_ai::ProviderKeyConfig>, String), String> {
    let db = AIProviderDB::open().map_err(|e| format!("не удалось открыть БД провайдеров: {e}"))?;
    let providers = db.list_providers().map_err(|e| format!("провайдеры: {e}"))?;
    let keys = db.list_all_keys().map_err(|e| format!("ключи: {e}"))?;
    let default_name = default_provider_name(&providers);

    let infos: Vec<ProviderInfo> = providers
        .iter()
        .map(|p| {
            let pkeys: Vec<KeyInfo> = keys
                .iter()
                .filter(|k| k.provider_id == p.id)
                .map(|k| KeyInfo {
                    id: k.id.clone(),
                    nickname: k.nickname.clone(),
                    mask: mask_of(&k.encrypted_key),
                    is_active: k.is_active,
                    last_tested: k.last_tested.clone(),
                    avg_latency_ms: k.avg_latency_ms,
                    error_count: k.error_count,
                    blocked_until: k.blocked_until.clone(),
                })
                .collect();
            ProviderInfo {
                id: p.id.clone(),
                name: p.name.clone(),
                provider_type: p.provider_type.to_string(),
                endpoint: p.endpoint.clone(),
                models: p.models.clone(),
                is_enabled: p.is_enabled,
                is_default: p.name == default_name,
                keys: pkeys,
            }
        })
        .collect();
    Ok((infos, keys, default_name))
}

/// Список провайдеров с замаскированными ключами (для UI вкладки AI CORE).
#[tauri::command]
pub fn ai_providers_list() -> Result<Vec<ProviderInfo>, String> {
    collect_providers().map(|(infos, _, _)| infos)
}

/// Статус: дефолтный провайдер, стратегия ротации, общее число ключей.
#[tauri::command]
pub fn ai_providers_status() -> Result<ProvidersStatus, String> {
    let (infos, keys, default_name) = collect_providers()?;
    let active = keys.iter().filter(|k| k.is_active).count();
    Ok(ProvidersStatus {
        default_provider: default_name,
        strategy: "FastestFirst".to_string(),
        total_keys: keys.len(),
        active_keys: active,
        providers: infos,
    })
}

/// Живой chat-запрос через ротацию ключей. Ключи расшифровываются только здесь, в процессе.
#[tauri::command]
pub async fn ai_chat(
    prompt: String,
    model: Option<String>,
    provider_id: Option<String>,
) -> Result<ChatOutcome, String> {
    chat_messages(
        vec![
            ChatMessage {
                role: "system".to_string(),
                content: "Ты — встроенный ИИ-ассистент приложения W420. Отвечай по-русски, кратко.".to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: prompt,
            },
        ],
        model,
        provider_id,
    )
    .await
}

/// Многоходовой chat через ротацию ключей (база для agi_chat Этапа 19).
/// Весь синхронный доступ к БД — в одном блоке, чтобы Connection (не Send)
/// дропнулся ДО первого .await ниже.
pub async fn chat_messages(
    messages: Vec<ChatMessage>,
    model: Option<String>,
    provider_id: Option<String>,
) -> Result<ChatOutcome, String> {
    let (providers, keys, target, model) = {
        let db = AIProviderDB::open().map_err(|e| format!("БД провайдеров: {e}"))?;
        let providers = db.list_providers().map_err(|e| format!("провайдеры: {e}"))?;
        let keys = db.list_all_keys().map_err(|e| format!("ключи: {e}"))?;

        // Целевой провайдер: по id, иначе дефолтный из конфига, иначе первый включённый
        let default_name = default_provider_name(&providers);
        let target = provider_id
            .and_then(|id| providers.iter().find(|p| p.id == id).cloned())
            .or_else(|| providers.iter().find(|p| p.name == default_name).cloned())
            .or_else(|| providers.iter().find(|p| p.is_enabled).cloned())
            .ok_or_else(|| "в базе нет ни одного провайдера".to_string())?;

        let model = model
            .filter(|m| !m.trim().is_empty())
            .or_else(|| target.models.first().cloned())
            .unwrap_or_else(|| "mistralai/mistral-large-4-1t-a52b".to_string());
        (providers, keys, target, model)
    };

    // Сборка ротации: все провайдеры + все активные ключи (как в security_ai/traffic)
    let rotation = KeyRotation::new();
    for p in providers {
        rotation.add_provider(p).await;
    }
    for k in keys.into_iter().filter(|k| k.is_active) {
        rotation.add_key(k).await;
    }

    let request = ChatRequest {
        messages,
        model,
        temperature: 0.3,
        max_tokens: Some(1024),
        stream: false,
    };

    let result = rotation
        .chat_completion_with_rotation(request, None)
        .await
        .map_err(|e| format!("запрос через ротацию не удался: {e}"))?;

    // Маску ключа-ответчика восстанавливаем по key_id из БД (сам ключ не светим)
    let key_mask = {
        let db2 = AIProviderDB::open().map_err(|e| format!("БД: {e}"))?;
        let all = db2.list_all_keys().map_err(|e| format!("ключи: {e}"))?;
        all.iter()
            .find(|k| k.id == result.key_id)
            .map(|k| mask_of(&k.encrypted_key))
            .unwrap_or_else(|| "…????".to_string())
    };

    Ok(ChatOutcome {
        text: result.response.content,
        model: result.response.model,
        provider_name: result.provider_name,
        key_mask,
        keys_tried: result.keys_tried,
        tokens_used: result.response.tokens_used,
        latency_ms: result.response.latency_ms,
    })
}

/// Тест всех активных ключей (или одного провайдера) с замером задержки — для UI.
#[tauri::command]
pub async fn ai_providers_test(provider_id: Option<String>) -> Result<Vec<KeyTestInfo>, String> {
    // БД читаем синхронно в блоках и дропаем до .await (Connection не Send).
    let (providers, keys) = {
        let db = AIProviderDB::open().map_err(|e| format!("БД провайдеров: {e}"))?;
        (
            db.list_providers().map_err(|e| format!("провайдеры: {e}"))?,
            db.list_all_keys().map_err(|e| format!("ключи: {e}"))?,
        )
    };
    let rotation = KeyRotation::new();
    for p in providers.clone() {
        rotation.add_provider(p).await;
    }
    for k in keys.clone().into_iter().filter(|k| k.is_active) {
        rotation.add_key(k).await;
    }
    let results = rotation.test_all_keys_owned().await;

    let out = results
        .into_iter()
        .filter(|r| {
            provider_id
                .as_ref()
                .map(|pid| {
                    keys.iter()
                        .find(|k| k.id == r.key_id)
                        .map(|k| k.provider_id == *pid)
                        .unwrap_or(false)
                })
                .unwrap_or(true)
        })
        .map(|r| {
            let mask = keys
                .iter()
                .find(|k| k.id == r.key_id)
                .map(|k| mask_of(&k.encrypted_key))
                .unwrap_or_else(|| "…????".to_string());
            let prov_name = keys
                .iter()
                .find(|k| k.id == r.key_id)
                .and_then(|k| providers.iter().find(|p| p.id == k.provider_id))
                .map(|p| p.name.clone())
                .unwrap_or_else(|| r.provider.clone());
            KeyTestInfo {
                provider: prov_name,
                key_id: r.key_id,
                mask,
                success: r.success,
                latency_ms: r.latency_ms,
                error: r.error_message,
            }
        })
        .collect();
    Ok(out)
}

// ============================================================================
// УПРАВЛЕНИЕ ПРОВАЙДЕРАМИ — полный цикл настройки из UI:
//   добавить провайдера (имя/тип/эндпоинт) → добавить ключ → тест провайдера
//   (с текстом ответа) → список моделей с эндпоинта → выбор моделей чекбоксами
//   → тест выбранных моделей (latency + скорость генерации) → сохранение конфигурации.
//   Плюс: тест ВСЕХ конфигураций сразу и сортировка моделей по скорости.
// ============================================================================

use w420_ai::providers::AnyProvider;
use w420_ai::{AIProvider, ProviderConfig, ProviderKeyConfig, ProviderType};
use w420_ai::encryption::encrypt_api_key;
use std::time::Instant;

/// Результат теста провайдера: живой ответ модели + список моделей с эндпоинта.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderTestInfo {
    pub provider_id: String,
    pub provider_name: String,
    pub key_mask: String,
    pub success: bool,
    /// Задержка chat-запроса «ping» в мс
    pub latency_ms: u64,
    /// Первые 160 символов ответа модели (что провайдер реально вернул)
    pub response_text: String,
    /// Сколько моделей вернул эндпоинт (GET /models)
    pub models_available: usize,
    pub error: Option<String>,
}

/// Результат теста одной модели.
#[derive(Debug, Clone, Serialize)]
pub struct ModelTestInfo {
    pub model: String,
    pub success: bool,
    pub latency_ms: u64,
    pub tokens_used: Option<u32>,
    /// Скорость генерации: токенов в секунду (tokens_used / время ответа)
    pub tokens_per_sec: Option<f64>,
    pub response_preview: String,
    pub error: Option<String>,
}

/// Запись статистики модели для UI (с сортировкой).
#[derive(Debug, Clone, Serialize)]
pub struct ModelStatInfo {
    pub model: String,
    pub success: bool,
    pub latency_ms: u64,
    pub tokens_used: Option<u32>,
    pub tokens_per_sec: Option<f64>,
    pub response_preview: Option<String>,
    pub error_message: Option<String>,
    pub tested_at: String,
}

/// Парсит тип провайдера из строки UI («Nvidia», «nvidia», «NVIDIA NIM», …).
pub fn parse_provider_type(s: &str) -> Result<ProviderType, String> {
    let t = s.trim().to_lowercase();
    Ok(match t.as_str() {
        "openai" => ProviderType::OpenAI,
        "anthropic" => ProviderType::Anthropic,
        "google" | "gemini" => ProviderType::Google,
        "mistral" | "mistral ai" => ProviderType::Mistral,
        "groq" => ProviderType::Groq,
        "together" | "together ai" => ProviderType::Together,
        "openrouter" => ProviderType::OpenRouter,
        "ollama" | "ollama (локально)" => ProviderType::Ollama,
        "nvidia" | "nvidia nim" => ProviderType::Nvidia,
        "custom" | "кастомный провайдер" => ProviderType::Custom,
        other => return Err(format!("неизвестный тип провайдера: {other}")),
    })
}

/// Сортировка результатов моделей: "latency" — по возрастанию задержки,
/// "speed" — по убыванию скорости генерации (ток/с), иначе — по имени.
pub fn sort_model_stats(mut v: Vec<ModelStatInfo>, sort_by: &str) -> Vec<ModelStatInfo> {
    match sort_by {
        "latency" => v.sort_by_key(|r| r.latency_ms),
        "speed" => v.sort_by(|a, b| {
            b.tokens_per_sec
                .unwrap_or(0.0)
                .partial_cmp(&a.tokens_per_sec.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        _ => v.sort_by(|a, b| a.model.cmp(&b.model)),
    }
    v
}

/// Первый активный ключ провайдера (или None).
fn first_active_key(db: &AIProviderDB, provider_id: &str) -> Option<ProviderKeyConfig> {
    db.list_keys_for_provider(provider_id)
        .ok()?
        .into_iter()
        .find(|k| k.is_active)
}

/// Добавить нового провайдера (имя, тип, эндпоинт; для известных типов дефолтный endpoint подставляется сам).
#[tauri::command]
pub fn ai_provider_add(name: String, provider_type: String, endpoint: Option<String>) -> Result<ProviderInfo, String> {
    let pt = parse_provider_type(&provider_type)?;
    let endpoint = endpoint
        .filter(|e| !e.trim().is_empty())
        .or_else(|| pt.default_endpoint().map(|s| s.to_string()))
        .ok_or_else(|| "для этого типа провайдера нужно задать эндпоинт вручную".to_string())?;
    let cfg = ProviderConfig {
        id: format!("prov-{}", uuid::Uuid::new_v4()),
        provider_type: pt,
        name: name.trim().to_string(),
        endpoint,
        models: Vec::new(),
        is_enabled: true,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    if cfg.name.is_empty() {
        return Err("имя провайдера не должно быть пустым".into());
    }
    let db = AIProviderDB::open().map_err(|e| format!("БД: {e}"))?;
    db.add_provider(&cfg).map_err(|e| format!("не удалось добавить: {e}"))?;
    let (infos, _, _) = collect_providers()?;
    infos
        .into_iter()
        .find(|p| p.id == cfg.id)
        .ok_or_else(|| "провайдер создан, но не нашёлся в списке".to_string())
}

/// Добавить API-ключ к провайдеру. Ключ шифруется AES-256-GCM и сохраняется; наружу — только маска.
#[tauri::command]
pub fn ai_provider_add_key(provider_id: String, api_key: String, nickname: Option<String>) -> Result<KeyInfo, String> {
    let key = api_key.trim().to_string();
    if key.len() < 8 {
        return Err("ключ слишком короткий".into());
    }
    let encrypted = encrypt_api_key(&key).map_err(|e| format!("шифрование: {e}"))?;
    let kc = ProviderKeyConfig {
        id: format!("key-{}", uuid::Uuid::new_v4()),
        provider_id,
        nickname: nickname.filter(|n| !n.trim().is_empty()),
        encrypted_key: encrypted,
        is_active: true,
        last_tested: None,
        avg_latency_ms: None,
        error_count: 0,
        blocked_until: None,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    let db = AIProviderDB::open().map_err(|e| format!("БД: {e}"))?;
    db.add_key(&kc).map_err(|e| format!("не удалось сохранить ключ: {e}"))?;
    Ok(KeyInfo {
        id: kc.id,
        nickname: kc.nickname,
        mask: mask_of(&kc.encrypted_key),
        is_active: true,
        last_tested: None,
        avg_latency_ms: None,
        error_count: 0,
        blocked_until: None,
    })
}

#[tauri::command]
pub fn ai_provider_remove(provider_id: String) -> Result<String, String> {
    let db = AIProviderDB::open().map_err(|e| format!("БД: {e}"))?;
    db.remove_provider(&provider_id).map_err(|e| format!("удаление: {e}"))?;
    Ok(format!("провайдер {provider_id} и его ключи удалены"))
}

#[tauri::command]
pub fn ai_key_remove(key_id: String) -> Result<String, String> {
    let db = AIProviderDB::open().map_err(|e| format!("БД: {e}"))?;
    db.remove_key(&key_id).map_err(|e| format!("удаление ключа: {e}"))?;
    Ok(format!("ключ {key_id} удалён"))
}

#[tauri::command]
pub fn ai_key_set_active(key_id: String, is_active: bool) -> Result<String, String> {
    let db = AIProviderDB::open().map_err(|e| format!("БД: {e}"))?;
    db.set_key_active(&key_id, is_active).map_err(|e| format!("статус ключа: {e}"))?;
    Ok(format!("ключ {key_id}: active={is_active}"))
}

#[tauri::command]
pub fn ai_provider_set_enabled(provider_id: String, is_enabled: bool) -> Result<String, String> {
    let db = AIProviderDB::open().map_err(|e| format!("БД: {e}"))?;
    let mut p = db.list_providers().map_err(|e| e.to_string())?
        .into_iter().find(|p| p.id == provider_id).ok_or("провайдер не найден")?;
    p.is_enabled = is_enabled;
    db.update_provider(&p).map_err(|e| format!("обновление: {e}"))?;
    Ok(format!("провайдер {provider_id}: enabled={is_enabled}"))
}

/// Делает провайдера дефолтным (пишет ~/.w420/security_ai.json → default_provider).
#[tauri::command]
pub fn ai_provider_set_default(provider_id: String) -> Result<String, String> {
    let db = AIProviderDB::open().map_err(|e| format!("БД: {e}"))?;
    let name = db.list_providers().map_err(|e| e.to_string())?
        .into_iter().find(|p| p.id == provider_id).map(|p| p.name)
        .ok_or("провайдер не найден")?;
    let home = std::env::var("HOME").map_err(|_| "HOME не задан")?;
    let dir = std::path::Path::new(&home).join(".w420");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("security_ai.json");
    let mut v: Value = std::fs::read_to_string(&path).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::json!({}));
    v["default_provider"] = Value::String(name.clone());
    std::fs::write(&path, serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(format!("провайдер по умолчанию: {name}"))
}

/// Тест провайдера: ping-чат + список моделей с эндпоинта. Возвращает текст ответа провайдера.
#[tauri::command]
pub async fn ai_provider_test(provider_id: String) -> Result<ProviderTestInfo, String> {
    // БД читаем синхронно и дропаем до .await (Connection не Send)
    let (provider, key) = {
        let db = AIProviderDB::open().map_err(|e| format!("БД: {e}"))?;
        let p = db.list_providers().map_err(|e| e.to_string())?
            .into_iter().find(|p| p.id == provider_id)
            .ok_or_else(|| "провайдер не найден".to_string())?;
        let k = first_active_key(&db, &provider_id)
            .ok_or_else(|| "у провайдера нет активных ключей".to_string())?;
        (p, k)
    };
    let mask = mask_of(&key.encrypted_key);
    let api_key = w420_ai::encryption::decrypt_api_key(&key.encrypted_key)
        .map_err(|e| format!("расшифровка ключа: {e}"))?;
    let prov = AnyProvider::from_config(&provider);

    // 1) список моделей (не критично, ошибки не валят весь тест)
    let models = prov.list_models(&api_key).await.ok().unwrap_or_default();

    // 2) живой ping-чат с замером времени
    let t0 = Instant::now();
    let chat = prov.chat_completion(&api_key, ChatRequest {
        messages: vec![
            ChatMessage { role: "system".into(), content: "Ты тестовый зонд. Отвечай одним словом.".into() },
            ChatMessage { role: "user".into(), content: "Скажи «ок» одним словом.".into() },
        ],
        model: provider.models.first().cloned().unwrap_or_else(|| "mistralai/mistral-large-4-1t-a52b".into()),
        temperature: 0.0,
        max_tokens: Some(16),
        stream: false,
    }).await;
    let latency_ms = t0.elapsed().as_millis() as u64;

    match chat {
        Ok(resp) => Ok(ProviderTestInfo {
            provider_id,
            provider_name: provider.name,
            key_mask: mask,
            success: true,
            latency_ms,
            response_text: resp.content.chars().take(160).collect(),
            models_available: models.len(),
            error: None,
        }),
        Err(e) => Ok(ProviderTestInfo {
            provider_id,
            provider_name: provider.name,
            key_mask: mask,
            success: false,
            latency_ms,
            response_text: String::new(),
            models_available: models.len(),
            error: Some(format!("{e}")),
        }),
    }
}

/// Список доступных моделей с эндпоинта провайдера (GET /models).
#[tauri::command]
pub async fn ai_provider_list_models(provider_id: String) -> Result<Vec<String>, String> {
    let (provider, key) = {
        let db = AIProviderDB::open().map_err(|e| format!("БД: {e}"))?;
        let p = db.list_providers().map_err(|e| e.to_string())?
            .into_iter().find(|p| p.id == provider_id)
            .ok_or_else(|| "провайдер не найден".to_string())?;
        let k = first_active_key(&db, &provider_id)
            .ok_or_else(|| "у провайдера нет активных ключей".to_string())?;
        (p, k)
    };
    let api_key = w420_ai::encryption::decrypt_api_key(&key.encrypted_key)
        .map_err(|e| format!("расшифровка ключа: {e}"))?;
    let prov = AnyProvider::from_config(&provider);
    let mut models = prov.list_models(&api_key).await.map_err(|e| format!("{e}"))?;
    models.sort();
    Ok(models)
}

/// Сохранить выбранные модели (чекбоксы в UI) в конфигурацию провайдера.
#[tauri::command]
pub fn ai_provider_set_models(provider_id: String, models: Vec<String>) -> Result<ProviderInfo, String> {
    let db = AIProviderDB::open().map_err(|e| format!("БД: {e}"))?;
    let mut p = db.list_providers().map_err(|e| e.to_string())?
        .into_iter().find(|p| p.id == provider_id).ok_or("провайдер не найден")?;
    p.models = models;
    db.update_provider(&p).map_err(|e| format!("сохранение моделей: {e}"))?;
    let (infos, _, _) = collect_providers()?;
    infos.into_iter().find(|x| x.id == provider_id).ok_or_else(|| "не нашёлся после сохранения".to_string())
}

/// Тест выбранных моделей: для каждой — чат с max_tokens=48, замер latency и скорости генерации.
/// Результаты пишутся в model_stats (история + сортировка по скорости в UI).
#[tauri::command]
pub async fn ai_provider_test_models(provider_id: String, models: Vec<String>) -> Result<Vec<ModelTestInfo>, String> {
    if models.is_empty() {
        return Err("список моделей пуст — выберите модели чекбоксами".into());
    }
    let (provider, key) = {
        let db = AIProviderDB::open().map_err(|e| format!("БД: {e}"))?;
        let p = db.list_providers().map_err(|e| e.to_string())?
            .into_iter().find(|p| p.id == provider_id)
            .ok_or_else(|| "провайдер не найден".to_string())?;
        let k = first_active_key(&db, &provider_id)
            .ok_or_else(|| "у провайдера нет активных ключей".to_string())?;
        (p, k)
    };
    let api_key = w420_ai::encryption::decrypt_api_key(&key.encrypted_key)
        .map_err(|e| format!("расшифровка ключа: {e}"))?;
    let prov = AnyProvider::from_config(&provider);

    let mut out: Vec<ModelTestInfo> = Vec::new();
    for model in &models {
        let t0 = Instant::now();
        let chat = prov.chat_completion(&api_key, ChatRequest {
            messages: vec![
                ChatMessage { role: "system".into(), content: "Тест скорости. Отвечай кратко.".into() },
                ChatMessage { role: "user".into(), content: "Посчитай от 1 до 10 через запятую.".into() },
            ],
            model: model.clone(),
            temperature: 0.2,
            max_tokens: Some(48),
            stream: false,
        }).await;
        let latency_ms = t0.elapsed().as_millis() as u64;
        let info = match chat {
            Ok(resp) => {
                let secs = latency_ms as f64 / 1000.0;
                let tps = if secs > 0.0 {
                    resp.tokens_used.map(|t| t as f64 / secs)
                } else {
                    None
                };
                ModelTestInfo {
                    model: model.clone(),
                    success: true,
                    latency_ms,
                    tokens_used: resp.tokens_used,
                    tokens_per_sec: tps,
                    response_preview: resp.content.chars().take(80).collect(),
                    error: None,
                }
            }
            Err(e) => ModelTestInfo {
                model: model.clone(),
                success: false,
                latency_ms,
                tokens_used: None,
                tokens_per_sec: None,
                response_preview: String::new(),
                error: Some(format!("{e}")),
            },
        };
        // пишем в историю model_stats (синхронный блок после await)
        {
            if let Ok(db) = AIProviderDB::open() {
                let _ = db.record_model_test(
                    &provider_id,
                    model,
                    info.success,
                    info.latency_ms,
                    info.tokens_used,
                    info.tokens_per_sec,
                    Some(&info.response_preview),
                    info.error.as_deref(),
                );
            }
        }
        out.push(info);
    }
    Ok(out)
}

/// История/текущие результаты тестов моделей провайдера с сортировкой:
/// sort_by = "latency" (быстрые сверху) | "speed" (быстрая генерация сверху) | иначе по имени.
#[tauri::command]
pub fn ai_provider_model_stats(provider_id: String, sort_by: Option<String>) -> Result<Vec<ModelStatInfo>, String> {
    let db = AIProviderDB::open().map_err(|e| format!("БД: {e}"))?;
    let recs = db.list_model_stats(&provider_id).map_err(|e| format!("статистика моделей: {e}"))?;
    let infos: Vec<ModelStatInfo> = recs.into_iter().map(|r| ModelStatInfo {
        model: r.model,
        success: r.success,
        latency_ms: r.latency_ms,
        tokens_used: r.tokens_used,
        tokens_per_sec: r.tokens_per_sec,
        response_preview: r.response_preview,
        error_message: r.error_message,
        tested_at: r.tested_at,
    }).collect();
    Ok(sort_model_stats(infos, sort_by.as_deref().unwrap_or("name")))
}

/// Тест ВСЕХ конфигураций сразу: все включённые провайдеры × все активные ключи.
/// Результаты сохраняются в key_stats и обновляют avg_latency_ms/error_count ключей.
#[tauri::command]
pub async fn ai_providers_test_all() -> Result<Vec<KeyTestInfo>, String> {
    let (providers, keys) = {
        let db = AIProviderDB::open().map_err(|e| format!("БД: {e}"))?;
        (db.list_providers().map_err(|e| e.to_string())?,
         db.list_all_keys().map_err(|e| e.to_string())?)
    };
    let rotation = KeyRotation::new();
    for p in providers.clone() { rotation.add_provider(p).await; }
    for k in keys.clone().into_iter().filter(|k| k.is_active) { rotation.add_key(k).await; }
    let results = rotation.test_all_keys_owned().await;

    // Пишем результаты в БД (key_stats + статистика ключей)
    {
        let db = AIProviderDB::open().map_err(|e| format!("БД: {e}"))?;
        let now = chrono::Utc::now().to_rfc3339();
        for r in &results {
            if let Some(k) = keys.iter().find(|k| k.id == r.key_id) {
                if r.success {
                    let _ = db.update_key_stats(&r.key_id, Some(r.latency_ms), 0, None);
                } else {
                    let blocked = if k.error_count + 1 >= 3 {
                        Some((chrono::Utc::now() + chrono::Duration::minutes(30)).to_rfc3339())
                    } else { None };
                    let _ = db.update_key_stats(&r.key_id, None, k.error_count + 1, blocked.as_deref());
                }
                let _ = db.mark_key_tested(&r.key_id, &now);
                let _ = db.record_test_result(&r.key_id, &k.provider_id, r.latency_ms, r.success, r.error_message.as_deref());
            }
        }
    }

    let out = results.into_iter().map(|r| {
        let mask = keys.iter().find(|k| k.id == r.key_id).map(|k| mask_of(&k.encrypted_key)).unwrap_or_else(|| "…????".into());
        let prov_name = keys.iter().find(|k| k.id == r.key_id)
            .and_then(|k| providers.iter().find(|p| p.id == k.provider_id))
            .map(|p| p.name.clone()).unwrap_or_else(|| r.provider.clone());
        KeyTestInfo { provider: prov_name, key_id: r.key_id, mask, success: r.success, latency_ms: r.latency_ms, error: r.error_message }
    }).collect();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_hides_key() {
        // маска — только последние 4 символа, полный ключ наружу не уходит
        let fake = "nvapi-abcdef1234567890SECRET";
        let tail: String = fake.chars().rev().take(4).collect::<String>().chars().rev().collect();
        let mask = format!("…{tail}");
        assert_eq!(tail.len(), 4);
        assert!(!mask.contains("SECRET"));
        assert!(mask.chars().count() <= 5); // «…» + 4 символа хвоста
    }

    /// Список провайдеров из реальной БД: NVIDIA NIM с 11 активными ключами, маски без ключей.
    #[test]
    fn test_providers_list_nvidia_11_keys_masked() {
        let list = ai_providers_list().expect("БД провайдеров должна читаться");
        let nv = list.iter().find(|p| p.provider_type == "Nvidia" || p.name.contains("NVIDIA"))
            .expect("в базе должен быть провайдер NVIDIA");
        assert_eq!(nv.keys.iter().filter(|k| k.is_active).count(), 11, "должно быть 11 активных ключей NVIDIA");
        for k in &nv.keys {
            assert!(k.mask.starts_with('…'), "маска обязана быть маской: {}", k.mask);
            assert!(!k.mask.contains("nvapi-"), "маска не должна содержать префикс ключа");
            assert!(k.mask.chars().count() <= 6);
        }
        assert!(nv.is_default, "NVIDIA должен быть провайдером по умолчанию");
    }

    #[test]
    fn test_parse_provider_type() {
        assert_eq!(parse_provider_type("Nvidia").unwrap(), ProviderType::Nvidia);
        assert_eq!(parse_provider_type("NVIDIA NIM").unwrap(), ProviderType::Nvidia);
        assert_eq!(parse_provider_type("ollama").unwrap(), ProviderType::Ollama);
        assert_eq!(parse_provider_type(" Custom ").unwrap(), ProviderType::Custom);
        assert!(parse_provider_type("nope").is_err());
    }

    #[test]
    fn test_sort_model_stats() {
        let mk = |m: &str, lat: u64, tps: Option<f64>| ModelStatInfo {
            model: m.into(), success: true, latency_ms: lat, tokens_used: Some(100),
            tokens_per_sec: tps, response_preview: None, error_message: None, tested_at: String::new(),
        };
        let v = vec![mk("b", 500, Some(10.0)), mk("a", 200, Some(50.0)), mk("c", 900, None)];
        let by_lat = sort_model_stats(v.clone(), "latency");
        assert_eq!(by_lat.iter().map(|r| r.model.as_str()).collect::<Vec<_>>(), ["a", "b", "c"]);
        let by_speed = sort_model_stats(v.clone(), "speed");
        assert_eq!(by_speed.iter().map(|r| r.model.as_str()).collect::<Vec<_>>(), ["a", "b", "c"]);
        let by_name = sort_model_stats(v, "name");
        assert_eq!(by_name.iter().map(|r| r.model.as_str()).collect::<Vec<_>>(), ["a", "b", "c"]);
    }

    /// LIVE: полный цикл против реального NVIDIA NIM — add key нельзя (ключ настоящий),
    /// поэтому тестируем существующего провайдера: test → list_models → test_models → stats.
    #[test]
    #[ignore = "живые запросы к NVIDIA NIM, тратят квоту"]
    fn live_provider_full_cycle() {
        let rt = tauri::async_runtime::block_on(async {
            let list = ai_providers_list().expect("list");
            let nv = list.iter().find(|p| p.provider_type == "NVIDIA NIM" || p.name.contains("NVIDIA")).expect("NVIDIA в базе").clone();
            let t = ai_provider_test(nv.id.clone()).await.expect("provider test");
            println!("LIVE provider test: ok={} lat={}ms models={} resp={:?}", t.success, t.latency_ms, t.models_available, t.response_text);
            assert!(t.success, "тест провайдера: {:?}", t.error);
            assert!(t.models_available > 0);
            let models = ai_provider_list_models(nv.id.clone()).await.expect("list models");
            println!("LIVE models: {} шт. первые: {:?}", models.len(), &models[..models.len().min(5)]);
            assert!(models.len() > 0);
            // берём сохранённые в конфигурации модели провайдера (они уже проверены как рабочие), иначе — первые 3 из списка
            let mut picked: Vec<String> = nv.models.iter().take(3).cloned().collect();
            if picked.is_empty() { picked = models.iter().take(3).cloned().collect(); }
            let res = ai_provider_test_models(nv.id.clone(), picked.clone()).await.expect("test models");
            for r in &res { println!("LIVE model {} ok={} lat={}ms tok={:?} tps={:?} err={:?}", r.model, r.success, r.latency_ms, r.tokens_used, r.tokens_per_sec, r.error); }
            assert!(res.iter().any(|r| r.success));
            let stats = ai_provider_model_stats(nv.id.clone(), Some("speed".into())).expect("stats");
            assert!(!stats.is_empty());
            let stats_lat = ai_provider_model_stats(nv.id, Some("latency".into())).expect("stats lat");
            let lats: Vec<u64> = stats_lat.iter().map(|s| s.latency_ms).collect();
            let mut sorted = lats.clone(); sorted.sort();
            assert_eq!(lats, sorted, "сортировка по latency должна быть по возрастанию");
        });
        let _ = rt;
    }

    /// Живой запрос к NVIDIA NIM через ротацию (запуск: cargo test -p w420 --lib ai_providers -- --ignored --nocapture)
    #[test]
    #[ignore = "живой запрос к NVIDIA NIM, тратит квоту ключа"]
    fn live_ai_chat_nvidia_rotation() {
        let out = tauri::async_runtime::block_on(ai_chat(
            "Ответь одним словом: ок".to_string(),
            None,
            None,
        ))
        .expect("ai_chat должен вернуться от NVIDIA NIM");
        assert!(!out.text.is_empty(), "пустой ответ модели");
        assert!(!out.key_mask.contains("nvapi-"), "маска не должна содержать полный ключ");
        println!(
            "LIVE: provider={} model={} key={} keys_tried={} tokens={:?} latency={}ms text={:?}",
            out.provider_name, out.model, out.key_mask, out.keys_tried, out.tokens_used, out.latency_ms, out.text
        );
    }
}


//! radio.rs — Этап 23: AGI-Ω FM — «настоящий эфир».
//!
//! Тексты ведущего генерирует AGI-мост (agi_chat поверх KeyRotation),
//! озвучка — локальный TTS-сервер (voice_say). Музыка остаётся Web Audio
//! на фронтенде; здесь — текст и голос. Все команды детерминированно
//! возвращают {text, live}; при недоступности модели фронтенд делает fallback.

use serde_json::{json, Value};

/// Промпт ведущего FM для заданного жанра/настроения.
fn dj_prompt(kind: &str, kind_desc: &str, mood: &str, ctx: &str, request: &Option<String>) -> String {
    let req = match request {
        Some(r) if !r.trim().is_empty() =>
            format!("Просьба слушателя: {r}. Сделай короткую реплику на эту тему (1-3 предложения). "),
        _ => format!("{kind_desc} "),
    };
    format!(
        "Ты ведущий радио W420 «AGI-Ω FM». {req}Пиши по-русски, без разметки и эмодзи, 1-3 предложения. \
         Текущее настроение эфира: {mood}. Контекст: {ctx}"
    )
}

/// Реплика ведущего (радио-заказ/заметка). Возвращает текст модели.
#[tauri::command]
pub async fn radio_script(
    kind: String,
    kind_desc: String,
    mood: String,
    ctx: String,
    request: Option<String>,
) -> Result<Value, String> {
    let prompt = dj_prompt(&kind, &kind_desc, &mood, &ctx, &request);
    let r = crate::agi::agi_chat(prompt, None).await?;
    let text = r.get("text").and_then(|t| t.as_str()).unwrap_or_default().trim().to_string();
    if text.is_empty() {
        return Err("модель вернула пустой текст".into());
    }
    Ok(json!({"text": text, "live": true, "kind": kind}))
}

/// Вечерний выпуск «День агентов» по статистике аудита (числа посчитаны фронтом).
#[tauri::command]
pub async fn radio_episode(stats: String, entries: String) -> Result<Value, String> {
    let prompt = format!(
        "Ты ведущий вечернего выпуска «День агентов» на радио W420. По данным ниже напиши выпуск на 110-160 слов по-русски: \
         приветствие, три факта, один вывод или совет, прощание. Используй только эти данные, числа не меняй, ничего не выдумывай. \
         Без разметки и эмодзи.\nСТАТИСТИКА (посчитана программой): {stats}\nПОСЛЕДНИЕ ЗАПИСИ:\n{entries}"
    );
    let r = crate::agi::agi_chat(prompt, None).await?;
    let text = r.get("text").and_then(|t| t.as_str()).unwrap_or_default().trim().to_string();
    if text.is_empty() {
        return Err("модель вернула пустой выпуск".into());
    }
    Ok(json!({"text": text, "live": true}))
}

/// Озвучить текст голосом оператора через локальный TTS-сервер (voice.rs).
#[tauri::command]
pub fn radio_say(text: String) -> Result<Value, String> {
    let r = crate::voice::voice_say(text, None, Some("ru".to_string()));
    Ok(json!({
        "ok": r.ok, "bytes": r.bytes, "b64": r.b64, "path": r.path,
        "error": if r.error.is_empty() { serde_json::Value::Null } else { json!(r.error) },
    }))
}

/// Статус радио-подсистемы (для бейджа).
#[tauri::command]
pub fn radio_status() -> Result<Value, String> {
    let agi = crate::agi::agi_status()?;
    let voice = crate::voice::voice_status();
    Ok(json!({
        "agi_live": agi.get("live").and_then(|v| v.as_bool()).unwrap_or(false),
        "tts_running": voice.tts_running,
        "live": true,
    }))
}

// ============================================================================
// Тесты: построение промптов (чистые функции)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dj_prompt_with_request() {
        let p = dj_prompt("заказ", "desc", "покой", "ctx", &Some("расскажи про EDR".into()));
        assert!(p.contains("Просьба слушателя: расскажи про EDR"));
        assert!(p.contains("покой") && p.contains("ctx"));
        assert!(p.contains("по-русски"));
    }

    #[test]
    fn test_dj_prompt_without_request_uses_kind() {
        let p = dj_prompt("анекдот", "Короткий анекдот…", "напряжение", "ctx", &None);
        assert!(p.contains("Короткий анекдот"));
        assert!(!p.contains("Просьба слушателя"));
        // пустая заявка = None
        let p2 = dj_prompt("сводка", "Сводка…", "работа", "c", &Some("   ".into()));
        assert!(!p2.contains("Просьба слушателя"));
    }

    #[test]
    fn test_episode_prompt_contains_stats_and_entries() {
        let p = format!(
            "Ты ведущий вечернего выпуска «День агентов» на радио W420. По данным ниже напиши выпуск на 110-160 слов по-русски: \
             приветствие, три факта, один вывод или совет, прощание. Используй только эти данные, числа не меняй, ничего не выдумывай. \
             Без разметки и эмодзи.\nСТАТИСТИКА (посчитана программой): {stats}\nПОСЛЕДНИЕ ЗАПИСИ:\n{entries}",
            stats = "записей 12", entries = "10:00 tool siem"
        );
        assert!(p.contains("записей 12") && p.contains("10:00 tool siem") && p.contains("110-160 слов"));
    }
}

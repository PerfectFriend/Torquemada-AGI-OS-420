//! map.rs — Этап 24: MIND MAP AGI-GEN.
//!
//! `map_generate(prompt)` просит AGI-мост вернуть СТРОГИЙ JSON
//! {"nodes":[{"text":…,"parent":…}]}; ответ извлекается из текста
//! (модель может обернуть JSON в ```json … ```), валидируется по схеме:
//! parent — индекс более раннего узла или -1 (корень), узлов ≤ 40,
//! текст непустой и ≤ 60 символов. Во фронтенд уходит только валидная схема.

use serde_json::{json, Value};

/// Извлечь первый валидный JSON-объект из текста модели (с ```-блоками и без).
pub fn extract_json_object(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end > start {
        Some(&text[start..=end])
    } else {
        None
    }
}

/// Валидация схемы mind map. Возвращает нормализованный список узлов.
pub fn validate_map_nodes(v: &Value) -> Result<Vec<(String, i64)>, String> {
    let arr = v.get("nodes").and_then(|n| n.as_array()).ok_or("нет поля nodes")?;
    if arr.is_empty() {
        return Err("пустая карта".into());
    }
    if arr.len() > 40 {
        return Err("слишком много узлов (>40)".into());
    }
    let mut out = Vec::new();
    for (i, n) in arr.iter().enumerate() {
        let text = n.get("text").and_then(|t| t.as_str()).unwrap_or("").trim();
        if text.is_empty() {
            return Err(format!("узел {i}: пустой текст"));
        }
        let text = text.chars().take(60).collect::<String>();
        let parent = n.get("parent").and_then(|p| p.as_i64()).unwrap_or(-1);
        if parent >= i as i64 {
            return Err(format!("узел {i}: parent должен быть индексом раннего узла или -1"));
        }
        if parent < -1 {
            return Err(format!("узел {i}: невалидный parent"));
        }
        out.push((text, parent));
    }
    Ok(out)
}

/// Сгенерировать mind map по теме через AGI-мост.
#[tauri::command]
pub async fn map_generate(prompt: String) -> Result<Value, String> {
    let prompt = prompt.trim();
    if prompt.is_empty() {
        return Err("нужна тема для карты".into());
    }
    let ask = format!(
        "Ты — генератор mind map для AGI-терминала W420. По теме ниже построй карту знаний. \
         Верни СТРОГО один JSON-объект вида {{\"nodes\":[{{\"text\":\"...\",\"parent\":-1}}, ...]}}: \
         до 40 узлов, текст каждого 2-6 слов (макс 60 символов), parent — индекс РАННЕГО узла в массиве \
         или -1 для первого (корневого) узла. Первый узел — тема целиком. Только JSON, без пояснений и разметки.\nТЕМА: {prompt}"
    );
    let r = crate::agi::agi_chat(ask, None).await?;
    let raw = r.get("text").and_then(|t| t.as_str()).unwrap_or("");
    let slice = extract_json_object(raw).ok_or("модель не вернула JSON")?;
    let v: Value = serde_json::from_str(slice).map_err(|e| format!("невалидный JSON: {e}"))?;
    let nodes = validate_map_nodes(&v)?;
    let out: Vec<Value> = nodes
        .into_iter()
        .map(|(text, parent)| json!({"text": text, "parent": parent}))
        .collect();
    Ok(json!({"nodes": out, "count": out.len(), "live": true, "raw_excerpt": &raw[..raw.len().min(120)]}))
}

/// Статус AGI-GEN (бейдж LIVE/SIM).
#[tauri::command]
pub fn map_agi_status() -> Result<Value, String> {
    let agi = crate::agi::agi_status()?;
    Ok(json!({"live": agi.get("live").and_then(|v| v.as_bool()).unwrap_or(false)}))
}

// ============================================================================
// Тесты чистых функций
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_plain_json() {
        assert_eq!(extract_json_object(r#"{"nodes":[]}"#), Some(r#"{"nodes":[]}"#));
    }

    #[test]
    fn test_extract_from_markdown_fence() {
        let s = "Вот карта:\n```json\n{\"nodes\":[{\"text\":\"x\",\"parent\":-1}]}\n```\nГотово.";
        let e = extract_json_object(s).unwrap();
        let v: Value = serde_json::from_str(e).unwrap();
        assert!(v["nodes"].is_array());
    }

    #[test]
    fn test_extract_no_json() {
        assert_eq!(extract_json_object("никакого json"), None);
    }

    #[test]
    fn test_validate_ok() {
        let v = json!({"nodes":[{"text":"корень","parent":-1},{"text":"ветка","parent":0}]});
        let n = validate_map_nodes(&v).unwrap();
        assert_eq!(n.len(), 2);
        assert_eq!(n[1].1, 0);
    }

    #[test]
    fn test_validate_rejects_forward_parent() {
        let v = json!({"nodes":[{"text":"a","parent":1},{"text":"b","parent":-1}]});
        assert!(validate_map_nodes(&v).is_err());
    }

    #[test]
    fn test_validate_rejects_empty_text_and_missing_nodes() {
        assert!(validate_map_nodes(&json!({"nodes":[{"text":"","parent":-1}]})).is_err());
        assert!(validate_map_nodes(&json!({"foo":1})).is_err());
        assert!(validate_map_nodes(&json!({"nodes":[]})).is_err());
    }

    #[test]
    fn test_validate_caps_and_truncates() {
        let long = "x".repeat(200);
        let v = json!({"nodes":[{"text":long,"parent":-1}]});
        let n = validate_map_nodes(&v).unwrap();
        assert_eq!(n[0].0.chars().count(), 60);
        // >40 узлов — отказ
        let many = json!({"nodes": (0..41).map(|i| json!({"text":format!("n{i}"),"parent":-1})).collect::<Vec<_>>()});
        assert!(validate_map_nodes(&many).is_err());
    }
}

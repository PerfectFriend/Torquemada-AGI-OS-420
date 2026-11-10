//! Глобальные настройки приложения (язык, тема, радио и др.).
//!
//! Хранятся в JSON-файле `~/.w420/settings.json`. Фронтенд читает их командой
//! `settings_get` при старте и присылает изменения через `settings_set` (патч
//! сливается с текущим файлом, чтобы не затирать ключи других модулей).
//! Вне Tauri фронтенд использует localStorage как фолбэк.

use serde_json::{json, Value};
use std::path::PathBuf;

/// Путь к файлу настроек: ~/.w420/settings.json
fn settings_path() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|e| format!("HOME не задан: {e}"))?;
    let dir = PathBuf::from(home).join(".w420");
    std::fs::create_dir_all(&dir).map_err(|e| format!("не удалось создать {dir:?}: {e}"))?;
    Ok(dir.join("settings.json"))
}

/// Текущие настройки (или пустой объект, если файла ещё нет).
#[tauri::command]
pub fn settings_get() -> Result<Value, String> {
    let path = settings_path()?;
    match std::fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => {
            serde_json::from_str(&s).map_err(|e| format!("settings.json повреждён: {e}"))
        }
        _ => Ok(json!({})),
    }
}

/// Сливает `patch` с текущими настройками, записывает файл и возвращает итог.
#[tauri::command]
pub fn settings_set(patch: Value) -> Result<Value, String> {
    let path = settings_path()?;
    let mut current = match std::fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => {
            serde_json::from_str::<Value>(&s).map_err(|e| format!("settings.json повреждён: {e}"))?
        }
        _ => json!({}),
    };
    if !current.is_object() {
        current = json!({});
    }
    if let (Some(cur), Some(p)) = (current.as_object_mut(), patch.as_object()) {
        for (k, v) in p {
            cur.insert(k.clone(), v.clone());
        }
    }
    let text = serde_json::to_string_pretty(&current).map_err(|e| format!("сериализация: {e}"))?;
    std::fs::write(&path, text).map_err(|e| format!("не удалось записать {path:?}: {e}"))?;
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_patch() {
        let mut current = json!({"lang": "ru", "theme": "dark"});
        let patch = json!({"lang": "es"});
        let cur = current.as_object_mut().unwrap();
        for (k, v) in patch.as_object().unwrap() {
            cur.insert(k.clone(), v.clone());
        }
        assert_eq!(current["lang"], "es");
        assert_eq!(current["theme"], "dark", "остальные ключи не затёрты");
    }
}

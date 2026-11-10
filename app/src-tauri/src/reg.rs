//! reg.rs — Этап 34 (DameWare Parity): реестр.
//!
//! Два слоя:
//! 1) Локальный реестр w420 (sqlite ~/.w420/registry.db) — key/value с историей
//!    изменений (для аудита конфигов самого приложения).
//! 2) Удалённый реестр Windows-хоста через существующий SSH-канал hosts
//!    (reg.exe query/add/delete). Пути и имена валидируются, значения квотятся.

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::sync::Mutex;

pub struct RegLocal {
    pub conn: Mutex<Connection>,
}

impl RegLocal {
    pub fn open() -> Result<Self, String> {
        let home = std::env::var("HOME").unwrap_or_default();
        std::fs::create_dir_all(format!("{home}/.w420")).map_err(|e| e.to_string())?;
        let conn = Connection::open(format!("{home}/.w420/registry.db")).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_ts INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS kv_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                ts INTEGER NOT NULL
             );",
        ).map_err(|e| e.to_string())?;
        Ok(Self { conn: Mutex::new(conn) })
    }
}

fn now_ts() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

// ======================= Валидация/квотирование (тестируется) =======================

/// Путь реестра Windows: HKLM\..., HKCU\... — без кавычек/;
pub fn valid_reg_path(path: &str) -> bool {
    let ok_hive = ["HKLM", "HKCU", "HKCR", "HKU", "HKCC"].iter().any(|h| path.starts_with(&format!("{h}\\")));
    ok_hive && path.chars().all(|c| c.is_ascii_alphanumeric() || "\\_-. ".contains(c))
}

/// Имя параметра: без кавычек и ; и &
pub fn valid_reg_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 256 && !name.contains(['"', ';', '&', '|', '<', '>', '\n', '\r'])
}

/// Тип значения reg.exe
pub fn valid_reg_type(t: &str) -> bool {
    ["REG_SZ", "REG_DWORD", "REG_EXPAND_SZ", "REG_MULTI_SZ", "REG_BINARY", "REG_QWORD"].contains(&t)
}

/// Квотирование строки для cmd: оборачиваем в кавычки, внутренние кавычки экранируем.
pub fn quote_cmd(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\\\""))
}

/// Построить команду reg query (без выполнения).
pub fn build_reg_query(path: &str, value: Option<&str>) -> Result<String, String> {
    if !valid_reg_path(path) { return Err("плохой путь реестра (ожидается HKLM\\... и т.п.)".into()); }
    let mut c = format!("reg query {}", quote_cmd(path));
    if let Some(v) = value {
        if !valid_reg_name(v) { return Err("плохое имя параметра".into()); }
        c.push_str(&format!(" /v {}", quote_cmd(v)));
    }
    Ok(c)
}

/// Построить команду reg add.
pub fn build_reg_add(path: &str, name: &str, value: &str, rtype: &str) -> Result<String, String> {
    if !valid_reg_path(path) { return Err("плохой путь реестра".into()); }
    if !valid_reg_name(name) { return Err("плохое имя параметра".into()); }
    if !valid_reg_type(rtype) { return Err("плохой тип".into()); }
    if value.contains(['\n', '\r']) || value.len() > 4096 { return Err("плохое значение".into()); }
    Ok(format!("reg add {} /v {} /t {} /d {} /f", quote_cmd(path), quote_cmd(name), rtype, quote_cmd(value)))
}

/// Построить команду reg delete.
pub fn build_reg_delete(path: &str, name: &str) -> Result<String, String> {
    if !valid_reg_path(path) { return Err("плохой путь реестра".into()); }
    if !valid_reg_name(name) { return Err("плохое имя параметра".into()); }
    Ok(format!("reg delete {} /v {} /f", quote_cmd(path), quote_cmd(name)))
}

/// Парсинг вывода `reg query` в пары имя=значение (для UI).
pub fn parse_reg_query(stdout: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("ERROR") { continue; }
        if let Some((name, val)) = t.split_once("    ") {
            out.push(json!({"name": name.trim(), "value": val.trim()}));
        }
    }
    out
}

// ======================= Команды Tauri =======================

/// Локальный реестр: get
#[tauri::command]
pub fn reg_local_get(reg: tauri::State<'_, RegLocal>, key: String) -> Result<Value, String> {
    if key.is_empty() || key.len() > 512 { return Err("плохой ключ".into()); }
    let conn = reg.conn.lock().unwrap();
    let r: Result<Option<String>, _> = conn.query_row("SELECT value FROM kv WHERE key=?1", params![key], |row| row.get(0));
    match r {
        Ok(Some(v)) => Ok(json!({"key": key, "value": v, "found": true})),
        _ => Ok(json!({"key": key, "found": false})),
    }
}

/// Локальный реестр: set (с историей)
#[tauri::command]
pub fn reg_local_set(reg: tauri::State<'_, RegLocal>, key: String, value: String) -> Result<Value, String> {
    if key.is_empty() || key.len() > 512 { return Err("плохой ключ".into()); }
    if value.len() > 65536 { return Err("значение слишком длинное".into()); }
    let ts = now_ts();
    let mut conn = reg.conn.lock().unwrap();
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute("INSERT INTO kv_history (key, value, ts) VALUES (?1, ?2, ?3)", params![&key, &value, ts]).map_err(|e| e.to_string())?;
    tx.execute("INSERT INTO kv (key, value, updated_ts) VALUES (?1, ?2, ?3) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ts=excluded.updated_ts", params![&key, &value, ts]).map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(json!({"ok": true, "key": key, "ts": ts}))
}

/// Локальный реестр: список ключей
#[tauri::command]
pub fn reg_local_list(reg: tauri::State<'_, RegLocal>) -> Result<Value, String> {
    let conn = reg.conn.lock().unwrap();
    let mut stmt = conn.prepare("SELECT key, updated_ts FROM kv ORDER BY key").map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows { let (k, ts) = r.map_err(|e| e.to_string())?; out.push(json!({"key": k, "ts": ts})); }
    Ok(json!({"keys": out, "count": out.len()}))
}

/// Локальный реестр: история ключа
#[tauri::command]
pub fn reg_local_history(reg: tauri::State<'_, RegLocal>, key: String) -> Result<Value, String> {
    let conn = reg.conn.lock().unwrap();
    let mut stmt = conn.prepare("SELECT value, ts FROM kv_history WHERE key=?1 ORDER BY id DESC LIMIT 100").map_err(|e| e.to_string())?;
    let rows = stmt.query_map(params![key], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows { let (v, ts) = r.map_err(|e| e.to_string())?; out.push(json!({"value": v, "ts": ts})); }
    Ok(json!({"key": key, "history": out}))
}

/// Удалённый реестр Windows: reg query через SSH-хост.
#[tauri::command]
pub fn reg_remote_query(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String, path: String, value: Option<String>) -> Result<Value, String> {
    let cmd = build_reg_query(&path, value.as_deref())?;
    let r = hosts.exec_command(&host_id, &cmd)?;
    Ok(json!({"host": host_id, "cmd": cmd, "exit_code": r.exit_code.unwrap_or(-1), "entries": parse_reg_query(&r.stdout), "raw": r.stdout}))
}

/// Удалённый реестр: reg add.
#[tauri::command]
pub fn reg_remote_set(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String, path: String, name: String, value: String, rtype: String) -> Result<Value, String> {
    let cmd = build_reg_add(&path, &name, &value, &rtype)?;
    let r = hosts.exec_command(&host_id, &cmd)?;
    Ok(json!({"host": host_id, "cmd": cmd, "exit_code": r.exit_code.unwrap_or(-1), "ok": r.success, "stderr": r.stderr}))
}

/// Удалённый реестр: reg delete.
#[tauri::command]
pub fn reg_remote_delete(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String, path: String, name: String) -> Result<Value, String> {
    let cmd = build_reg_delete(&path, &name)?;
    let r = hosts.exec_command(&host_id, &cmd)?;
    Ok(json!({"host": host_id, "cmd": cmd, "exit_code": r.exit_code.unwrap_or(-1), "ok": r.success, "stderr": r.stderr}))
}

// ======================= Тесты =======================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_paths() {
        assert!(valid_reg_path("HKLM\\SOFTWARE\\W420"));
        assert!(valid_reg_path("HKCU\\Software\\My App-1.0_x"));
        assert!(!valid_reg_path("HKLM\\SOFTWARE; rm -rf /"));
        assert!(!valid_reg_path("C:\\Windows"));
        assert!(!valid_reg_path("HKLM\""));
    }

    #[test]
    fn test_valid_names_types() {
        assert!(valid_reg_name("DisplayName"));
        assert!(!valid_reg_name("a\"b"));
        assert!(!valid_reg_name("a;b"));
        assert!(valid_reg_type("REG_SZ"));
        assert!(valid_reg_type("REG_DWORD"));
        assert!(!valid_reg_type("REG_HACK"));
    }

    #[test]
    fn test_build_commands() {
        let q = build_reg_query("HKLM\\SOFTWARE\\W420", Some("Version")).unwrap();
        assert!(q.contains("reg query") && q.contains("/v"));
        let a = build_reg_add("HKCU\\Software\\W420", "Mode", "safe", "REG_SZ").unwrap();
        assert!(a.contains("reg add") && a.contains("REG_SZ") && a.contains("/f"));
        let d = build_reg_delete("HKCU\\Software\\W420", "Mode").unwrap();
        assert!(d.contains("reg delete"));
        assert!(build_reg_add("HKLM\\x", "n", "bad\nvalue", "REG_SZ").is_err());
        assert!(build_reg_query("bad", None).is_err());
    }

    #[test]
    fn test_parse_reg_query() {
        let s = "HKEY_LOCAL_MACHINE\\SOFTWARE\\W420\n\n    Version    REG_SZ    1.0.4\n    Mode    REG_SZ    safe\n\n";
        let e = parse_reg_query(s);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0]["name"], "Version");
        assert_eq!(e[0]["value"], "REG_SZ    1.0.4");
    }

    #[test]
    fn test_quote_cmd() {
        assert_eq!(quote_cmd("a b"), "\"a b\"");
        assert_eq!(quote_cmd("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn test_local_kv_roundtrip() {
        let reg = RegLocal::open().unwrap();
        reg_local_set_inner(&reg, "test.key", "v1").unwrap();
        reg_local_set_inner(&reg, "test.key", "v2").unwrap();
        let g = reg_local_get_inner(&reg, "test.key").unwrap();
        assert_eq!(g, "v2");
        let h = reg_local_history_inner(&reg, "test.key").unwrap();
        assert_eq!(h.len(), 2);
        assert_eq!(h[0], "v2"); // свежее первым
    }

    // внутренние хелперы для тестов (без State)
    fn reg_local_set_inner(reg: &RegLocal, key: &str, value: &str) -> Result<(), String> {
        let ts = now_ts();
        let mut conn = reg.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO kv_history (key, value, ts) VALUES (?1, ?2, ?3)", params![key, value, ts]).map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO kv (key, value, updated_ts) VALUES (?1, ?2, ?3) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ts=excluded.updated_ts", params![key, value, ts]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }
    fn reg_local_get_inner(reg: &RegLocal, key: &str) -> Result<String, String> {
        let conn = reg.conn.lock().unwrap();
        conn.query_row("SELECT value FROM kv WHERE key=?1", params![key], |r| r.get(0)).map_err(|e| e.to_string())
    }
    fn reg_local_history_inner(reg: &RegLocal, key: &str) -> Result<Vec<String>, String> {
        let conn = reg.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM kv_history WHERE key=?1 ORDER BY id DESC").map_err(|e| e.to_string())?;
        let rows = stmt.query_map(params![key], |r| r.get::<_, String>(0)).map_err(|e| e.to_string())?;
        rows.map(|r| r.map_err(|e| e.to_string())).collect()
    }
}

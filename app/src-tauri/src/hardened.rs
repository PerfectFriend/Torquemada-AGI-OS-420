//! hardened.rs — режим повышенной безопасности W420_HARDENED и human-in-the-loop
//! для destructive-команд (security-аудит 14.11.2026, пункт 2.2).
//!
//! - `W420_HARDENED=1` (env) или флаг `"hardened": true` в ~/.w420/settings.json
//!   полностью отключает опасные команды (power, очистку логов, изоляцию хоста,
//!   применение emergency/firewall-профилей, отзыв peer'ов, деплой патчей).
//! - Вне hardened-режима destructive-команды всё равно требуют явного
//!   подтверждения: аргумент `confirm=true` в вызове команды.
//! - Каждый вызов destructive-команды пишется в аудит (~/.w420/audit.db):
//!   команда, host_id, timestamp, результат (ok/err/отклонено).

use rusqlite::Connection;
use std::path::PathBuf;

fn home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"))
}

/// Включён ли hardened-режим: env W420_HARDENED=1 или settings.json {"hardened": true}.
pub fn hardened() -> bool {
    if std::env::var("W420_HARDENED").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false) {
        return true;
    }
    let p = home().join(".w420").join("settings.json");
    if let Ok(txt) = std::fs::read_to_string(p) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
            if v.get("hardened").and_then(|h| h.as_bool()).unwrap_or(false) {
                return true;
            }
        }
    }
    false
}

/// Гейт для destructive-команд.
/// - hardened-режим: команда заблокирована всегда.
/// - обычный режим: требуется confirm == Some(true).
pub fn guard_destructive(cmd: &str, host_id: Option<&str>, confirm: Option<bool>) -> Result<(), String> {
    let result = if hardened() {
        audit_cmd(cmd, host_id, "BLOCKED(hardened)");
        return Err(format!(
            "команда {cmd} отключена в режиме W420_HARDENED=1 (см. SECURITY.md)"
        ));
    } else if confirm != Some(true) {
        audit_cmd(cmd, host_id, "NEEDS_CONFIRM");
        return Err(format!(
            "команда {cmd} destructive: требуется явное подтверждение (confirm=true)"
        ));
    } else {
        audit_cmd(cmd, host_id, "ALLOWED");
        Ok(())
    };
    result
}

/// Запись вызова в журнал аудита (~/.w420/audit.db, таблица cmd_audit).
pub fn audit_cmd(cmd: &str, host_id: Option<&str>, result: &str) {
    let db = home().join(".w420").join("audit.db");
    let _ = std::fs::create_dir_all(db.parent().unwrap_or(&home().join(".w420")));
    if let Ok(c) = Connection::open(db) {
        let _ = c.execute(
            "CREATE TABLE IF NOT EXISTS cmd_audit (
               ts TEXT NOT NULL,
               cmd TEXT NOT NULL,
               host_id TEXT,
               result TEXT NOT NULL
             )",
            [],
        );
        let ts = chrono::Utc::now().to_rfc3339();
        let _ = c.execute(
            "INSERT INTO cmd_audit (ts, cmd, host_id, result) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![ts, cmd, host_id.unwrap_or(""), result],
        );
    }
}

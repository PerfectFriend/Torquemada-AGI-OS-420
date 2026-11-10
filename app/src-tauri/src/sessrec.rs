//! sessrec.rs — Этап 32 (DameWare Parity): запись сессий + журнал с hash-chain.
//!
//! Запись командных (SSH/локальных) сессий в asciinema-совместимый .cast (v2),
//! если нет asciinema — фолбэк на `script` (typescript). Каждая запись попадает
//! в аудит-цепочку ~/.w420/audit-chain.jsonl (sha256: prev_hash + payload),
//! цепочку можно проверить `sessrec_verify_chain`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::process::Command;
use std::sync::Mutex;

pub struct RecManager {
    pub procs: Mutex<std::collections::HashMap<u32, std::process::Child>>,
    pub next_id: std::sync::atomic::AtomicU32,
}

impl Default for RecManager {
    fn default() -> Self {
        Self {
            procs: Mutex::new(Default::default()),
            next_id: std::sync::atomic::AtomicU32::new(1),
        }
    }
}

fn sessions_dir() -> String {
    format!("{}/.w420/sessions", std::env::var("HOME").unwrap_or_default())
}

fn audit_chain_path() -> String {
    format!("{}/.w420/audit-chain.jsonl", std::env::var("HOME").unwrap_or_default())
}

// ======================= Чистые функции (тестируются) =======================

/// Заголовок .cast v2.
pub fn cast_header(cols: u32, rows: u32, env_shell: &str) -> String {
    json!({"version": 2, "width": cols, "height": rows, "timestamp": now_ts(), "env": {"SHELL": env_shell}}).to_string()
}

/// Одно событие .cast: [ts_с_начала, "o", данные].
pub fn cast_event(start_ts: u64, data: &str) -> String {
    json!([now_ts() - start_ts, "o", data]).to_string()
}

pub fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Хэш записи цепочки: sha256(prev_hash || payload). prev пустой для первой.
pub fn chain_hash(prev: &str, payload: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(payload.as_bytes());
    hex::encode(h.finalize())
}

/// Добавить запись в цепочку, вернуть её хэш.
pub fn chain_append(payload: &str) -> Result<String, String> {
    let path = audit_chain_path();
    let prev = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.lines().last().map(|l| l.to_string()))
        .and_then(|l| serde_json::from_str::<Value>(&l).ok())
        .and_then(|v| v["hash"].as_str().map(|s| s.to_string()))
        .unwrap_or_default();
    let hash = chain_hash(&prev, payload);
    let line = json!({"ts": now_ts(), "hash": hash, "prev": prev, "payload": payload});
    if let Ok(home) = std::env::var("HOME") {
        let _ = std::fs::create_dir_all(format!("{home}/.w420"));
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(f, "{line}");
        }
    }
    Ok(hash)
}

/// Проверить всю цепочку; вернуть (ok, проверено записей, первая坏ая).
pub fn verify_chain() -> Result<Value, String> {
    let s = std::fs::read_to_string(audit_chain_path()).map_err(|_| "цепочка пуста".to_string())?;
    let mut prev = String::new();
    let mut n = 0u64;
    for (i, line) in s.lines().enumerate() {
        if line.trim().is_empty() { continue; }
        let v: Value = serde_json::from_str(line).map_err(|e| format!("строка {}: {e}", i + 1))?;
        let payload = v["payload"].as_str().ok_or("нет payload")?;
        let expect = chain_hash(&prev, payload);
        if v["hash"].as_str() != Some(expect.as_str()) {
            return Ok(json!({"ok": false, "checked": n, "bad_line": i + 1}));
        }
        prev = expect;
        n += 1;
    }
    Ok(json!({"ok": true, "checked": n}))
}

// ======================= Команды Tauri =======================

/// Начать запись: если есть asciinema — пишем .cast; иначе `script` (typescript).
/// cmd по умолчанию — интерактивный bash; можно записать и одну команду.
#[tauri::command]
pub fn sessrec_start(mgr: tauri::State<'_, RecManager>, label: Option<String>, cmd: Option<String>) -> Result<Value, String> {
    let id = mgr.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = sessions_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let label = label.unwrap_or_else(|| format!("sess-{}", now_ts()));
    if label.contains(|c: char| !c.is_ascii_alphanumeric() && !"-_".contains(c)) {
        return Err("плохая метка".into());
    }
    let shell_cmd = cmd.unwrap_or_else(|| "bash".to_string());
    let cast_path = format!("{dir}/{id}-{label}.cast");
    let type_path = format!("{dir}/{id}-{label}.typescript");

    let child = if std::path::Path::new("/usr/bin/asciinema").exists() || which("asciinema").is_some() {
        Command::new("asciinema").args(["rec", "-c", &shell_cmd, "--overwrite", &cast_path]).spawn()
    } else {
        Command::new("script").args(["-qec", &shell_cmd, &type_path]).spawn()
    };
    let child = child.map_err(|e| format!("spawn: {e}"))?;
    let format = if which("asciinema").is_some() { "cast" } else { "typescript" };
    let path = if format == "cast" { cast_path } else { type_path };
    // в цепочку — факт начала записи
    chain_append(&format!("sessrec_start id={id} label={label} path={path}"))?;
    mgr.procs.lock().unwrap().insert(id, child);
    Ok(json!({"id": id, "path": path, "format": format, "label": label}))
}

#[tauri::command]
pub fn sessrec_stop(mgr: tauri::State<'_, RecManager>, id: u32) -> Result<Value, String> {
    if let Some(mut c) = mgr.procs.lock().unwrap().remove(&id) {
        let _ = c.kill();
        let _ = c.wait();
    }
    chain_append(&format!("sessrec_stop id={id}"))?;
    Ok(json!({"stopped": id}))
}

/// Список записей в ~/.w420/sessions.
#[tauri::command]
pub fn sessrec_list() -> Result<Value, String> {
    let dir = sessions_dir();
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let p = e.path();
            if let Ok(m) = e.metadata() {
                out.push(json!({
                    "path": p.to_string_lossy(),
                    "size": m.len(),
                    "mtime": m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0),
                    "format": if p.to_string_lossy().ends_with(".cast") { "cast" } else { "typescript" },
                }));
            }
        }
    }
    out.sort_by_key(|v| v["mtime"].as_u64().unwrap_or(0));
    Ok(json!({"recordings": out, "count": out.len()}))
}

/// Прочитать .cast как события (для inline play в UI).
#[tauri::command]
pub fn sessrec_read_cast(path: String) -> Result<Value, String> {
    if !path.starts_with(&sessions_dir()) || path.contains("..") {
        return Err("путь вне каталога сессий".into());
    }
    let s = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let mut lines = s.lines();
    let header: Value = serde_json::from_str(lines.next().unwrap_or("{}")).map_err(|e| format!("header: {e}"))?;
    let mut events = Vec::new();
    for l in lines {
        if l.trim().is_empty() { continue; }
        if let Ok(v) = serde_json::from_str::<Value>(l) { events.push(v); }
    }
    Ok(json!({"header": header, "events": events, "count": events.len()}))
}

/// Рендер .cast → mp4 через asciinema+agg/ffmpeg, если есть; иначе вернуть cast.
#[tauri::command]
pub fn sessrec_render_mp4(path: String, out_mp4: String) -> Result<Value, String> {
    if !path.starts_with(&sessions_dir()) || path.contains("..") || out_mp4.contains("..") {
        return Err("плохой путь".into());
    }
    if which("asciinema").is_none() || which("agg").is_none() {
        return Err("нужны asciinema и agg (или ffmpeg) — рендер не собран".into());
    }
    let out = Command::new("sh").arg("-c")
        .arg(format!("asciinema render {} | agg --font-size 14 --cols 100 {} ", shell_q(&path), shell_q(&out_mp4)))
        .output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    Ok(json!({"mp4": out_mp4}))
}

#[tauri::command]
pub fn sessrec_verify_chain() -> Result<Value, String> {
    verify_chain()
}

fn which(bin: &str) -> Option<String> {
    std::env::var("PATH").ok()?.split(':').map(|p| format!("{p}/{bin}")).find(|p| std::path::Path::new(p).is_file())
}

fn shell_q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ======================= Тесты =======================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cast_format() {
        let h = cast_header(120, 40, "/bin/bash");
        let v: Value = serde_json::from_str(&h).unwrap();
        assert_eq!(v["version"], 2);
        assert_eq!(v["width"], 120);
        let e = cast_event(now_ts(), "hello\r\n");
        let ev: Value = serde_json::from_str(&e).unwrap();
        assert_eq!(ev[1], "o");
        assert_eq!(ev[2], "hello\r\n");
        assert!(ev[0].as_u64().unwrap() <= 2);
    }

    #[test]
    fn test_chain_hash_stable() {
        assert_eq!(chain_hash("", "abc"), chain_hash("", "abc"));
        assert_ne!(chain_hash("", "abc"), chain_hash("x", "abc"));
        assert_eq!(chain_hash("", "abc").len(), 64);
    }

    #[test]
    fn test_verify_chain_local() {
        // цепочка в реальном HOME — дописываем тестовую запись и проверяем
        let h1 = chain_append("test-payload-1").unwrap();
        let h2 = chain_append("test-payload-2").unwrap();
        assert_ne!(h1, h2);
        let r = verify_chain().unwrap();
        assert_eq!(r["ok"], true);
        assert!(r["checked"].as_u64().unwrap() >= 2);
    }

    #[test]
    fn test_record_oneshot_with_script() {
        // реальная запись одной команды через `script` (есть в util-linux)
        if which("script").is_none() { return; }
        let dir = sessions_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let p = format!("{dir}/test-oneshot.typescript", );
        let out = Command::new("script").args(["-qec", "echo w420-test-marker", &p]).output().unwrap();
        assert!(out.status.success());
        let content = std::fs::read_to_string(&p).unwrap();
        assert!(content.contains("w420-test-marker"), "запись должна содержать вывод команды: {content}");
        let _ = std::fs::remove_file(&p);
    }
}

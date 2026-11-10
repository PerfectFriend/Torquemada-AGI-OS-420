//! evtlog.rs — Этап 35 (DameWare Parity): журнал событий.
//!
//! 1) Локальный журнал w420: sqlite ~/.w420/events.db (ts, level, source,
//!    message, tags) — log/query/stats/clear.
//! 2) Удалённый Windows Event Log через SSH: `wevtutil qe <log> /f:xml /c:N`
//!    с XPath-фильтром; XML парсим в JSON вручную (зависимостей не добавляем).

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::sync::Mutex;

pub struct EvtLog {
    pub conn: Mutex<Connection>,
}

impl EvtLog {
    pub fn open() -> Result<Self, String> {
        let home = std::env::var("HOME").unwrap_or_default();
        std::fs::create_dir_all(format!("{home}/.w420")).map_err(|e| e.to_string())?;
        let conn = Connection::open(format!("{home}/.w420/events.db")).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                level TEXT NOT NULL,
                source TEXT NOT NULL,
                message TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT ''
             );
             CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
             CREATE INDEX IF NOT EXISTS idx_events_level ON events(level);",
        ).map_err(|e| e.to_string())?;
        Ok(Self { conn: Mutex::new(conn) })
    }
}

fn now_ts() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn valid_level(l: &str) -> bool {
    ["debug", "info", "warn", "error", "critical"].contains(&l)
}

// ======================= Удалённый wevtutil: сборка/парсинг =======================

/// Имя лога wevtutil: только буквы/цифры/_/-/.
pub fn valid_log_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && name.chars().all(|c| c.is_ascii_alphanumeric() || "_-./".contains(c))
}

/// XPath-фильтр: жёсткий белый список символов (скобки нужны для выражений).
pub fn valid_xpath(f: &str) -> bool {
    // разрешаем синтаксис XPath (скобки, <=, /, *, @), запрещаем инъекции
    !f.is_empty() && f.len() <= 1024
        && f.chars().all(|c| c.is_ascii_alphanumeric() || "[]/*()<>=@_' \t+-.,".contains(c))
        && !f.contains("..")
}

/// Собрать команду wevtutil qe.
pub fn build_wevtutil(log: &str, xpath: Option<&str>, count: u32) -> Result<String, String> {
    if !valid_log_name(log) { return Err("плохое имя лога".into()); }
    if let Some(x) = xpath { if !valid_xpath(x) { return Err("плохой XPath-фильтр".into()); } }
    let count = count.clamp(1, 1000);
    let mut c = format!("wevtutil qe {}", shell_q(log));
    if let Some(x) = xpath { c.push_str(&format!(" /q:{}", shell_q(x))); }
    c.push_str(&format!(" /f:xml /c:{count} /rd:true"));
    Ok(c)
}

/// Список каналов: wevtutil el (en-US локаль может отличаться — /f: не задаём).
pub fn build_wevtutil_el() -> String {
    "wevtutil el".to_string()
}

/// Парсинг XML-вывода wevtutil (формат Event/System+EventData или RenderedDescription).
/// Вытаскиваем System/{Provider,EventID,Level,TimeCreated,Computer} и текст сообщения.
pub fn parse_wevt_xml(xml: &str) -> Vec<Value> {
    let mut out = Vec::new();
    // режем по <Event ...> ... </Event>
    let mut rest = xml;
    while let Some(start) = rest.find("<Event") {
        let end = match rest[start..].find("</Event>") {
            Some(e) => start + e + "</Event>".len(),
            None => break,
        };
        let block = &rest[start..end];
        out.push(parse_event_block(block));
        rest = &rest[end..];
    }
    out
}

fn parse_event_block(block: &str) -> Value {
    let mut ev = json!({});
    let grab = |tag: &str| -> Option<String> {
        let open = format!("<{tag}");
        let close = format!("</{tag}>");
        let s = block.find(&open)?;
        let s2 = block[s..].find('>')? + s + 1;
        let e = block[s2..].find(&close)? + s2;
        Some(xml_unescape(&block[s2..e]).trim().to_string())
    };
    if let Some(p) = grab("Provider") { ev["provider"] = json!(p); }
    // Provider может быть атрибутом: <Provider Name="..."/>
    if ev.get("provider").is_none() {
        if let Some(s) = block.find("<Provider Name=\"") {
            let rest = &block[s + "<Provider Name=\"".len()..];
            if let Some(e) = rest.find('"') { ev["provider"] = json!(rest[..e]); }
        }
    }
    if let Some(v) = grab("EventID") { ev["event_id"] = json!(v.parse::<u64>().unwrap_or(0)); }
    if let Some(v) = grab("Level") { ev["level"] = json!(v.parse::<u64>().unwrap_or(0)); }
    if let Some(v) = grab("TimeCreated") { ev["time"] = json!(v); }
    if let Some(v) = grab("Computer") { ev["computer"] = json!(v); }
    // сообщение: либо <Message>, либо первый <Data> в EventData, либо RenderingInfo
    if let Some(m) = grab("Message") { ev["message"] = json!(m); }
    else if let Some(s) = block.find("<EventData") {
        let seg = &block[s..];
        if let Some(d) = seg.find("<Data") {
            let d2 = &seg[d..];
            if let Some(gt) = d2.find('>') {
                let t = &d2[gt + 1..];
                if let Some(e) = t.find("</Data>") { ev["message"] = json!(xml_unescape(&t[..e]).trim()); }
            }
        }
    }
    ev
}

pub fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

fn shell_q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// XPath для уровня: Level<=2 — критические/ошибки.
pub fn xpath_errors() -> &'static str {
    "*[System/Level<=2]"
}

// ======================= Команды Tauri =======================

/// Записать событие в локальный журнал.
#[tauri::command]
pub fn evt_log(evt: tauri::State<'_, EvtLog>, level: String, source: String, message: String, tags: Option<String>) -> Result<Value, String> {
    if !valid_level(&level) { return Err("level: debug|info|warn|error|critical".into()); }
    if source.is_empty() || source.len() > 128 { return Err("плохой source".into()); }
    if message.is_empty() || message.len() > 16384 { return Err("плохое message".into()); }
    let tags = tags.unwrap_or_default();
    if tags.len() > 256 { return Err("tags слишком длинные".into()); }
    let ts = now_ts();
    let conn = evt.conn.lock().unwrap();
    conn.execute("INSERT INTO events (ts, level, source, message, tags) VALUES (?1,?2,?3,?4,?5)",
                 params![ts, &level, &source, &message, &tags]).map_err(|e| e.to_string())?;
    Ok(json!({"ok": true, "ts": ts}))
}

/// Запрос из локального журнала: фильтры level/since/limit + поиск по тексту.
#[tauri::command]
pub fn evt_query(evt: tauri::State<'_, EvtLog>, level: Option<String>, since_ts: Option<i64>, search: Option<String>, limit: Option<u32>) -> Result<Value, String> {
    let mut sql = String::from("SELECT ts, level, source, message, tags FROM events WHERE 1=1");
    let mut args: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    if let Some(l) = level {
        if !valid_level(&l) { return Err("плохой level".into()); }
        sql.push_str(" AND level=?"); args.push(Box::new(l));
    }
    if let Some(s) = since_ts { sql.push_str(" AND ts>=?"); args.push(Box::new(s)); }
    if let Some(q) = search {
        if q.len() > 128 { return Err("поиск слишком длинный".into()); }
        sql.push_str(" AND (message LIKE ? OR source LIKE ? OR tags LIKE ?)");
        let pat = format!("%{q}%");
        args.push(Box::new(pat.clone())); args.push(Box::new(pat.clone())); args.push(Box::new(pat));
    }
    sql.push_str(" ORDER BY ts DESC LIMIT ?");
    let lim = limit.unwrap_or(200).clamp(1, 2000);
    args.push(Box::new(lim as i64));
    let conn = evt.conn.lock().unwrap();
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let refs: Vec<&dyn rusqlite::types::ToSql> = args.iter().map(|a| a.as_ref()).collect();
    let rows = stmt.query_map(refs.as_slice(), |r| {
        Ok(json!({"ts": r.get::<_, i64>(0)?, "level": r.get::<_, String>(1)?, "source": r.get::<_, String>(2)?, "message": r.get::<_, String>(3)?, "tags": r.get::<_, String>(4)?}))
    }).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows { out.push(r.map_err(|e| e.to_string())?); }
    Ok(json!({"events": out, "count": out.len()}))
}

/// Статистика по уровням.
#[tauri::command]
pub fn evt_stats(evt: tauri::State<'_, EvtLog>) -> Result<Value, String> {
    let conn = evt.conn.lock().unwrap();
    let mut stmt = conn.prepare("SELECT level, COUNT(*) FROM events GROUP BY level").map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows { let (l, c) = r.map_err(|e| e.to_string())?; out.push(json!({"level": l, "count": c})); }
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0)).unwrap_or(0);
    Ok(json!({"by_level": out, "total": total}))
}

/// Удалить старые записи (retention): оставить N последних.
#[tauri::command]
pub fn evt_prune(evt: tauri::State<'_, EvtLog>, keep: u32) -> Result<Value, String> {
    let keep = keep.clamp(100, 1_000_000) as i64;
    let conn = evt.conn.lock().unwrap();
    let n: i64 = conn.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY ts DESC LIMIT ?1)", params![keep]).map_err(|e| e.to_string())? as i64;
    Ok(json!({"deleted": n, "kept": keep}))
}

/// Удалённый Event Log: список каналов.
#[tauri::command]
pub fn evt_remote_logs(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String) -> Result<Value, String> {
    let r = hosts.exec_command(&host_id, &build_wevtutil_el())?;
    let logs: Vec<&str> = r.stdout.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
    Ok(json!({"host": host_id, "logs": logs, "count": logs.len(), "ok": r.success}))
}

/// Удалённый Event Log: запрос канала с XPath.
#[tauri::command]
pub fn evt_remote_query(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String, log: String, xpath: Option<String>, count: Option<u32>) -> Result<Value, String> {
    let cmd = build_wevtutil(&log, xpath.as_deref(), count.unwrap_or(50))?;
    let r = hosts.exec_command(&host_id, &cmd)?;
    Ok(json!({"host": host_id, "log": log, "cmd": cmd, "ok": r.success,
              "events": parse_wevt_xml(&r.stdout), "stderr": r.stderr}))
}

// ======================= Тесты =======================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validators() {
        assert!(valid_level("error"));
        assert!(!valid_level("hack"));
        assert!(valid_log_name("Application"));
        assert!(valid_log_name("Microsoft-Windows-Kernel/Power"));
        assert!(!valid_log_name("App; del"));
        assert!(valid_xpath("*[System/Level<=2]"));
        assert!(!valid_xpath("*[System/Level<=2]\" or 1=1"));
        assert!(!valid_xpath("../../etc"));
    }

    #[test]
    fn test_build_wevtutil() {
        let c = build_wevtutil("Application", Some("*[System/Level<=2]"), 10).unwrap();
        assert!(c.contains("wevtutil qe 'Application'"));
        assert!(c.contains("/c:10") && c.contains("/f:xml"));
        assert!(build_wevtutil("bad;name", None, 5).is_err());
        assert!(build_wevtutil("Application", Some("bad\"xpath"), 5).is_err());
        // count клампится
        let c = build_wevtutil("System", None, 99999).unwrap();
        assert!(c.contains("/c:1000"));
    }

    #[test]
    fn test_parse_wevt_xml() {
        let xml = r#"<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="TestProv" Guid="{123}"/><EventID Qualifiers="0">1001</EventID>
<Level>2</Level><TimeCreated SystemTime="2026-11-09T10:00:00.000Z"/><Computer>WIN-PC</Computer></System>
<EventData><Data>Disk failure on C:</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="TestProv"/><EventID>1002</EventID><Level>4</Level>
<TimeCreated SystemTime="2026-11-09T10:01:00.000Z"/><Computer>WIN-PC</Computer></System>
<RenderingInfo><Message>Service started &amp; running</Message></RenderingInfo></Event></Events>"#;
        let evs = parse_wevt_xml(xml);
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0]["provider"], "TestProv");
        assert_eq!(evs[0]["event_id"], 1001);
        assert_eq!(evs[0]["level"], 2);
        assert_eq!(evs[0]["computer"], "WIN-PC");
        assert_eq!(evs[0]["message"], "Disk failure on C:");
        assert_eq!(evs[1]["message"], "Service started & running");
    }

    #[test]
    fn test_local_evt_roundtrip() {
        let log = EvtLog::open().unwrap();
        let conn = log.conn.lock().unwrap();
        let ts = now_ts();
        conn.execute("INSERT INTO events (ts, level, source, message, tags) VALUES (?1,'error','test','boom','x')", params![ts]).unwrap();
        conn.execute("INSERT INTO events (ts, level, source, message, tags) VALUES (?1,'info','test','ok','x')", params![ts]).unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM events WHERE source='test'", [], |r| r.get(0)).unwrap();
        assert!(n >= 2);
        let errs: i64 = conn.query_row("SELECT COUNT(*) FROM events WHERE level='error'", [], |r| r.get(0)).unwrap();
        assert!(errs >= 1);
    }

    #[test]
    fn test_xml_unescape() {
        assert_eq!(xml_unescape("a&lt;b&gt;c&amp;d"), "a<b>c&d");
    }
}

//! Фаза 9 (ядро): SIEM — агрегация и корреляция событий безопасности (siem.rs).
//!
//! Единая БД `~/.w420/siem.db`, таблица `events` — нормализованный поток:
//!   source: ids (traffic.db alerts) | threats (threat_alerts) | net_scan (новые хосты) | firewall
//! Инкрементальный ingest по курсору last_ts на каждый source (таблица meta).
//! Корреляция: ≥2 события с одним src_ip за окно 1 час ИЛИ событие severity=critical
//! → инцидент в таблице incidents (без дубликатов для открытых).
//! AI-сводка: `siem_ai_summary` гоняет последние события через KeyRotation (NVIDIA, ключи в AES-256-GCM БД).

use rusqlite::Connection;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;

pub struct SiemManager {
    pub db: Mutex<PathBuf>,
}

fn home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"))
}

#[derive(Serialize, Clone)]
pub struct SiemEvent {
    pub id: i64,
    pub ts: String,
    pub source: String,
    pub category: String,
    pub severity: String,
    pub src_ip: String,
    pub message: String,
}

#[derive(Serialize, Clone)]
pub struct SiemRule {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub min_events: i64,
    pub window_minutes: i64,
    pub min_severity: String,
    pub title: String,
    pub enabled: bool,
    pub created_at: String,
}

fn row_to_event(r: &rusqlite::Row) -> rusqlite::Result<SiemEvent> {
    Ok(SiemEvent {
        id: r.get(0)?,
        ts: r.get(1)?,
        source: r.get(2)?,
        category: r.get(3)?,
        severity: r.get(4)?,
        src_ip: r.get(5)?,
        message: r.get(6)?,
    })
}

impl SiemManager {
    pub fn new() -> Self {
        let db = home().join(".w420").join("siem.db");
        let m = Self { db: Mutex::new(db.clone()) };
        m.init(&db);
        m
    }

    fn init(&self, db: &PathBuf) {
        if let Ok(c) = Connection::open(db) {
            let _ = c.execute_batch(
                "CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    source TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    src_ip TEXT NOT NULL DEFAULT '',
                    message TEXT NOT NULL,
                    raw TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_ev_ts ON events(ts);
                CREATE INDEX IF NOT EXISTS idx_ev_src ON events(src_ip);
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    event_ids TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                );
                CREATE TABLE IF NOT EXISTS meta (source TEXT PRIMARY KEY, last_ts TEXT NOT NULL DEFAULT '');
                CREATE TABLE IF NOT EXISTS ingest_log (ts TEXT, source TEXT, added INTEGER);
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    min_events INTEGER NOT NULL DEFAULT 2,
                    window_minutes INTEGER NOT NULL DEFAULT 60,
                    min_severity TEXT NOT NULL DEFAULT 'low',
                    title TEXT NOT NULL DEFAULT 'Корреляция событий',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );",
            );
            // дефолтные правила корреляции (создаются один раз, если таблица пуста)
            let _ = c.execute_batch(
                "INSERT INTO rules (name, description, min_events, window_minutes, min_severity, title, enabled, created_at)
                 SELECT 'burst-src', '≥N событий с одного источника за окно', 2, 60, 'low', 'Корреляция: {cnt} событий с {src} за {window} мин', 1, datetime('now')
                 WHERE NOT EXISTS (SELECT 1 FROM rules);
                 INSERT INTO rules (name, description, min_events, window_minutes, min_severity, title, enabled, created_at)
                 SELECT 'critical-single', 'одно critical-событие = инцидент', 1, 60, 'critical', 'Критическое событие: {msg}', 1, datetime('now')
                 WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name='critical-single');",
            );
        }
    }

    pub fn conn(&self) -> Result<Connection, String> {
        let p = self.db.lock().unwrap().clone();
        Connection::open(p).map_err(|e| e.to_string())
    }

    fn cursor(&self, c: &Connection, source: &str) -> String {
        c.query_row("SELECT last_ts FROM meta WHERE source=?1", [source], |r| r.get(0))
            .unwrap_or_default()
    }

    fn set_cursor(&self, c: &Connection, source: &str, ts: &str) {
        let _ = c.execute(
            "INSERT INTO meta (source, last_ts) VALUES (?1, ?2)
             ON CONFLICT(source) DO UPDATE SET last_ts=excluded.last_ts",
            rusqlite::params![source, ts],
        );
    }

    /// Инкрементальный сбор событий из всех источников. Возвращает число добавленных.
    pub fn ingest(&self) -> Result<u32, String> {
        let c = self.conn()?;
        let dir = home().join(".w420");
        let mut added = 0u32;

        // 1) IDS-алерты из traffic.db
        if let Ok(src) = Connection::open(dir.join("traffic.db")) {
            let cur = self.cursor(&c, "ids");
            let mut stmt = src
                .prepare("SELECT id, ts, severity, category, signature, src_ip, description FROM alerts WHERE ts > ?1 ORDER BY ts")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([&cur], |r| {
                    Ok((
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(0)?,
                    ))
                })
                .map_err(|e| e.to_string())?;
            let mut last = cur.clone();
            for row in rows.flatten() {
                let (ts, sev, cat, sig, ip, desc, id) = row;
                let _ = c.execute(
                    "INSERT INTO events (ts, source, category, severity, src_ip, message, raw) VALUES (?1,'ids',?2,?3,?4,?5,?6)",
                    rusqlite::params![ts, cat, sev, ip, format!("[{sig}] {desc}"), format!("alert_id={id}")],
                );
                if ts > last { last = ts; }
                added += 1;
            }
            self.set_cursor(&c, "ids", &last);
        }

        // 2) Угрозы/CVE из threats.db
        if let Ok(src) = Connection::open(dir.join("threats.db")) {
            let cur = self.cursor(&c, "threats");
            let mut stmt = src
                .prepare("SELECT alert_id, created_at, severity, title, cve_id FROM threat_alerts WHERE created_at > ?1 ORDER BY created_at")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([&cur], |r| {
                    Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(0)?))
                })
                .map_err(|e| e.to_string())?;
            let mut last = cur.clone();
            for row in rows.flatten() {
                let (ts, sev, title, cve, id) = row;
                let sev = if sev == "critical" { "critical" } else { "high" };
                let _ = c.execute(
                    "INSERT INTO events (ts, source, category, severity, src_ip, message, raw) VALUES (?1,'threats','cve',?2,'',?3,?4)",
                    rusqlite::params![ts, sev, title, format!("{cve} alert_id={id}")],
                );
                if ts > last { last = ts; }
                added += 1;
            }
            self.set_cursor(&c, "threats", &last);
        }

        // 3) Новые хосты из net_scan.db (is_known=0)
        if let Ok(src) = Connection::open(dir.join("net_scan.db")) {
            let cur = self.cursor(&c, "net_scan");
            let mut stmt = src
                .prepare("SELECT scanned_at, ip FROM scan_results WHERE is_known=0 AND scanned_at > ?1 ORDER BY scanned_at")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([&cur], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(|e| e.to_string())?;
            let mut last = cur.clone();
            for row in rows.flatten() {
                let (ts, ip) = row;
                let _ = c.execute(
                    "INSERT INTO events (ts, source, category, severity, src_ip, message, raw) VALUES (?1,'net_scan','new_host','medium',?2,'обнаружен новый хост в сети',?3)",
                    rusqlite::params![ts, ip, ip],
                );
                if ts > last { last = ts; }
                added += 1;
            }
            self.set_cursor(&c, "net_scan", &last);
        }

        // 4) События брандмауэра из firewall.db
        let fw_path = dir.join("firewall.db");
        if fw_path.exists() {
            if let Ok(src) = Connection::open(&fw_path) {
                let has = src
                    .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='fw_events'", [], |r| r.get::<_, i64>(0))
                    .unwrap_or(0) > 0;
                if has {
            let cur = self.cursor(&c, "firewall");
            let mut stmt = src
                .prepare("SELECT ts, ip, rule, action FROM fw_events WHERE ts > ?1 ORDER BY ts")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([&cur], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?)))
                .map_err(|e| e.to_string())?;
            let mut last = cur.clone();
            for row in rows.flatten() {
                let (ts, ip, rule, action) = row;
                let sev = if action == "isolate" { "high" } else { "low" };
                let _ = c.execute(
                    "INSERT INTO events (ts, source, category, severity, src_ip, message, raw) VALUES (?1,'firewall','fw_rule',?2,?3,?4,?5)",
                    rusqlite::params![ts, sev, ip, format!("{action}: {rule}"), rule],
                );
                if ts > last { last = ts; }
                added += 1;
            }
            self.set_cursor(&c, "firewall", &last);
                }
            }
        }

        let _ = c.execute(
            "INSERT INTO ingest_log (ts, source, added) VALUES (?1,'all',?2)",
            rusqlite::params![chrono::Utc::now().to_rfc3339(), added],
        );
        Ok(added)
    }

    /// Корреляция: группировка по src_ip за последний час; ≥2 события или critical → инцидент.
    /// Ранг важности: low=1, medium=2, high=3, critical=4 (сравнение строк в SQL ненадёжно).
    pub fn severity_rank(sev: &str) -> u8 {
        match sev {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            _ => 1,
        }
    }

    /// Корреляция по включённым правилам таблицы `rules`.
    /// Правило: в окне `window_minutes` у источника `src_ip` накопилось ≥ `min_events`
    /// событий с рангом ≥ `min_severity` → инцидент (без дублей для открытых).
    /// Возвращает число созданных инцидентов.
    pub fn correlate(&self) -> Result<u32, String> {
        let c = self.conn()?;
        let rules = self.list_rules_inner(&c)?;
        let mut made = 0u32;
        for rule in rules.into_iter().filter(|r| r.enabled) {
            let window = (chrono::Utc::now() - chrono::Duration::minutes(rule.window_minutes as i64)).to_rfc3339();
            let min_rank = Self::severity_rank(&rule.min_severity);
            // события окна с непустым src_ip; группировку и ранги считаем в Rust
            let mut stmt = c
                .prepare("SELECT id, ts, src_ip, severity, message FROM events WHERE src_ip != '' AND ts >= ?1")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([&window], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                })
                .map_err(|e| e.to_string())?;
            // src_ip -> (count, max_sev, ids, last_ts, last_msg)
            let mut by_src: std::collections::HashMap<String, (u32, String, String, String, String)> = std::collections::HashMap::new();
            for row in rows.flatten() {
                let (id, ts, src, sev, msg) = row;
                if Self::severity_rank(&sev) < min_rank { continue; }
                let e = by_src.entry(src).or_insert((0, String::new(), String::new(), String::new(), String::new()));
                e.0 += 1;
                if Self::severity_rank(&sev) > Self::severity_rank(&e.1) { e.1 = sev.clone(); }
                if !e.2.is_empty() { e.2.push(','); }
                e.2.push_str(&id.to_string());
                e.3 = ts;
                e.4 = msg;
            }
            for (src, (cnt, sev, ids, ts, msg)) in by_src {
                if cnt < rule.min_events as u32 { continue; }
                let exists: i64 = c
                    .query_row(
                        "SELECT COUNT(*) FROM incidents WHERE src_ip=?1 AND status='open' AND created_at >= ?2",
                        rusqlite::params![src, window],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);
                if exists > 0 { continue; }
                let title = rule.title
                    .replace("{cnt}", &cnt.to_string())
                    .replace("{src}", &src)
                    .replace("{window}", &rule.window_minutes.to_string())
                    .replace("{msg}", &msg.chars().take(80).collect::<String>());
                let _ = c.execute(
                    "INSERT INTO incidents (created_at, src_ip, severity, title, event_ids) VALUES (?1,?2,?3,?4,?5)",
                    rusqlite::params![ts, src, sev, title, ids],
                );
                made += 1;
            }
        }
        Ok(made)
    }

    // ==================== ПРАВИЛА КОРРЕЛЯЦИИ ====================

    fn list_rules_inner(&self, c: &Connection) -> Result<Vec<SiemRule>, String> {
        let mut st = c.prepare(
            "SELECT id, name, description, min_events, window_minutes, min_severity, title, enabled, created_at FROM rules ORDER BY id"
        ).map_err(|e| e.to_string())?;
        let rows = st.query_map([], |r| {
            Ok(SiemRule {
                id: r.get(0)?,
                name: r.get(1)?,
                description: r.get(2)?,
                min_events: r.get(3)?,
                window_minutes: r.get(4)?,
                min_severity: r.get(5)?,
                title: r.get(6)?,
                enabled: r.get::<_, i32>(7)? != 0,
                created_at: r.get(8)?,
            })
        }).map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }

    pub fn list_rules(&self) -> Result<Vec<SiemRule>, String> {
        let c = self.conn()?;
        self.list_rules_inner(&c)
    }

    pub fn add_rule(&self, name: &str, description: &str, min_events: i64, window_minutes: i64, min_severity: &str, title: &str) -> Result<SiemRule, String> {
        if name.trim().is_empty() { return Err("имя правила не должно быть пустым".into()); }
        if !["low", "medium", "high", "critical"].contains(&min_severity) {
            return Err("min_severity: low|medium|high|critical".into());
        }
        let c = self.conn()?;
        let now = chrono::Utc::now().to_rfc3339();
        c.execute(
            "INSERT INTO rules (name, description, min_events, window_minutes, min_severity, title, enabled, created_at) VALUES (?1,?2,?3,?4,?5,?6,1,?7)",
            rusqlite::params![name.trim(), description, min_events.max(1), window_minutes.max(1), min_severity, title, now],
        ).map_err(|e| e.to_string())?;
        let id: i64 = c.last_insert_rowid();
        self.list_rules_inner(&c)?.into_iter().find(|r| r.id == id).ok_or_else(|| "правило создано, но не найдено".to_string())
    }

    pub fn remove_rule(&self, id: i64) -> Result<String, String> {
        let c = self.conn()?;
        let n = c.execute("DELETE FROM rules WHERE id=?1", [id]).map_err(|e| e.to_string())?;
        Ok(format!("правило {id} удалено ({n} записей)"))
    }

    pub fn toggle_rule(&self, id: i64, enabled: bool) -> Result<String, String> {
        let c = self.conn()?;
        let n = c.execute("UPDATE rules SET enabled=?2 WHERE id=?1", rusqlite::params![id, enabled as i32]).map_err(|e| e.to_string())?;
        Ok(format!("правило {id}: enabled={enabled} ({n} записей)"))
    }

    // ==================== ИНЦИДЕНТЫ ====================

    pub fn list_incidents(&self, status: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
        let c = self.conn()?;
        let sql = match status {
            Some(_) => "SELECT id, created_at, src_ip, severity, title, event_ids, status FROM incidents WHERE status=?1 ORDER BY created_at DESC LIMIT 500",
            None => "SELECT id, created_at, src_ip, severity, title, event_ids, status FROM incidents ORDER BY created_at DESC LIMIT 500",
        };
        let mut st = c.prepare(sql).map_err(|e| e.to_string())?;
        let map_row = |r: &rusqlite::Row| -> rusqlite::Result<serde_json::Value> {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?, "created_at": r.get::<_, String>(1)?, "src_ip": r.get::<_, String>(2)?,
                "severity": r.get::<_, String>(3)?, "title": r.get::<_, String>(4)?,
                "event_ids": r.get::<_, String>(5)?, "status": r.get::<_, String>(6)?,
            }))
        };
        let rows = match status {
            Some(s) => st.query_map(rusqlite::params![s], map_row).map_err(|e| e.to_string())?,
            None => st.query_map(rusqlite::params![], map_row).map_err(|e| e.to_string())?,
        };
        Ok(rows.flatten().collect())
    }

    pub fn create_incident(&self, src_ip: &str, severity: &str, title: &str, event_ids: Option<&str>) -> Result<i64, String> {
        let c = self.conn()?;
        let now = chrono::Utc::now().to_rfc3339();
        c.execute(
            "INSERT INTO incidents (created_at, src_ip, severity, title, event_ids, status) VALUES (?1,?2,?3,?4,?5,'open')",
            rusqlite::params![now, src_ip, severity, title, event_ids.unwrap_or("")],
        ).map_err(|e| e.to_string())?;
        Ok(c.last_insert_rowid())
    }

    pub fn set_incident_status(&self, id: i64, status: &str) -> Result<String, String> {
        if !["open", "in_progress", "resolved", "false_positive"].contains(&status) {
            return Err("status: open|in_progress|resolved|false_positive".into());
        }
        let c = self.conn()?;
        let n = c.execute("UPDATE incidents SET status=?2 WHERE id=?1", rusqlite::params![id, status]).map_err(|e| e.to_string())?;
        Ok(format!("инцидент {id} → {status} ({n} записей)"))
    }

    /// Выборка событий (с фильтром по severity или без).
    pub fn fetch_events(&self, severity: Option<&str>, lim: u32) -> Result<Vec<SiemEvent>, String> {
        let c = self.conn()?;
        let lim = lim.min(1000);
        let sev = severity.unwrap_or("").to_string();
        let mut st = c
            .prepare("SELECT id, ts, source, category, severity, src_ip, message FROM events WHERE (?1='' OR severity=?1) ORDER BY ts DESC LIMIT ?2")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map(rusqlite::params![sev, lim], row_to_event)
            .map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }

    pub fn search(&self, query: &str, lim: u32) -> Result<Vec<SiemEvent>, String> {
        let c = self.conn()?;
        let pat = format!("%{query}%");
        let mut st = c
            .prepare("SELECT id, ts, source, category, severity, src_ip, message FROM events WHERE message LIKE ?1 OR src_ip LIKE ?1 ORDER BY ts DESC LIMIT ?2")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map(rusqlite::params![pat, lim.min(500)], row_to_event)
            .map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }

    pub fn dashboard(&self) -> Result<serde_json::Value, String> {
        let c = self.conn()?;
        let counts: Vec<(String, i64)> = {
            let mut st = c.prepare("SELECT severity, COUNT(*) FROM events GROUP BY severity").map_err(|e| e.to_string())?;
            let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).map_err(|e| e.to_string())?;
            rows.flatten().collect()
        };
        let by_source: Vec<(String, i64)> = {
            let mut st = c.prepare("SELECT source, COUNT(*) FROM events GROUP BY source").map_err(|e| e.to_string())?;
            let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).map_err(|e| e.to_string())?;
            rows.flatten().collect()
        };
        let top_src: Vec<(String, i64)> = {
            let mut st = c.prepare("SELECT src_ip, COUNT(*) FROM events WHERE src_ip != '' GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 10").map_err(|e| e.to_string())?;
            let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).map_err(|e| e.to_string())?;
            rows.flatten().collect()
        };
        let incidents: Vec<serde_json::Value> = {
            let mut st = c.prepare("SELECT id, created_at, src_ip, severity, title, status FROM incidents ORDER BY id DESC LIMIT 50").map_err(|e| e.to_string())?;
            let rows = st.query_map([], |r| Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?, "created_at": r.get::<_, String>(1)?, "src_ip": r.get::<_, String>(2)?,
                "severity": r.get::<_, String>(3)?, "title": r.get::<_, String>(4)?, "status": r.get::<_, String>(5)?,
            }))).map_err(|e| e.to_string())?;
            rows.flatten().collect()
        };
        let total: i64 = c.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0)).unwrap_or(0);
        Ok(serde_json::json!({
            "total_events": total,
            "by_severity": counts,
            "by_source": by_source,
            "top_src_ips": top_src,
            "open_incidents": incidents,
        }))
    }

    /// AI-сводка инцидентов через KeyRotation (NVIDIA; ключи не покидают бэкенд).
    pub async fn ai_summary(&self) -> Result<String, String> {
        use w420_ai::db::AIProviderDB;
        use w420_ai::rotation::KeyRotation;
        use w420_ai::{ChatMessage, ChatRequest};

        let added = self.ingest()?;
        let incidents = self.correlate()?;
        let events = self.fetch_events(None, 50)?;
        let payload = serde_json::to_string_pretty(&events).unwrap_or_default();

        // rusqlite::Connection не-Send: открываем БД, читаем провайдеров/ключи, дропаем соединение до .await
        let (providers_vec, keys_vec) = {
            let db = AIProviderDB::open().map_err(|e| format!("БД провайдеров: {e}"))?;
            let providers = db.list_providers().map_err(|e| format!("провайдеры: {e}"))?;
            let keys = db.list_all_keys().map_err(|e| format!("ключи: {e}"))?;
            (providers, keys)
        };
        if providers_vec.is_empty() {
            return Err("нет настроенных AI-провайдеров".into());
        }

        let rotation = KeyRotation::new();
        for p in &providers_vec {
            rotation.add_provider(p.clone()).await;
        }
        for k in &keys_vec {
            rotation.add_key(k.clone()).await;
        }

        let request = ChatRequest {
            model: "mistralai/mistral-large-4-1t-a52b".into(),
            messages: vec![
                ChatMessage {
                    role: "system".into(),
                    content: "Ты SOC-аналитик W420. По списку событий безопасности составь краткую сводку на русском: инциденты, тренды, что требует реакции в первую очередь. До 10 пунктов.".into(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: format!("Новых событий при ingest: {added}, новых корреляций: {incidents}.\nСобытия:\n{payload}"),
                },
            ],
            temperature: 0.3,
            max_tokens: Some(1024),
            stream: false,
        };
        let resp = rotation
            .chat_completion_with_rotation(request, None)
            .await
            .map_err(|e| format!("AI: {e}"))?;
        Ok(resp.response.content)
    }
}

#[tauri::command]
pub fn siem_ingest(siem: tauri::State<'_, SiemManager>) -> Result<u32, String> {
    siem.ingest()
}

#[tauri::command]
pub fn siem_correlate(siem: tauri::State<'_, SiemManager>) -> Result<u32, String> {
    siem.correlate()
}

#[tauri::command]
pub fn siem_events(siem: tauri::State<'_, SiemManager>, limit: Option<u32>, severity: Option<String>) -> Result<Vec<SiemEvent>, String> {
    siem.fetch_events(severity.as_deref(), limit.unwrap_or(100))
}

#[tauri::command]
pub fn siem_search(siem: tauri::State<'_, SiemManager>, query: String, limit: Option<u32>) -> Result<Vec<SiemEvent>, String> {
    siem.search(&query, limit.unwrap_or(100))
}

#[tauri::command]
pub fn siem_dashboard(siem: tauri::State<'_, SiemManager>) -> Result<serde_json::Value, String> {
    siem.dashboard()
}

#[tauri::command]
pub async fn siem_ai_summary(siem: tauri::State<'_, SiemManager>) -> Result<String, String> {
    siem.inner().ai_summary().await
}

// ---------- Правила корреляции ----------

#[tauri::command]
pub fn siem_rules_list(siem: tauri::State<'_, SiemManager>) -> Result<Vec<SiemRule>, String> {
    siem.inner().list_rules()
}

#[tauri::command]
pub fn siem_rule_add(
    siem: tauri::State<'_, SiemManager>,
    name: String,
    description: Option<String>,
    min_events: Option<i64>,
    window_minutes: Option<i64>,
    min_severity: Option<String>,
    title: Option<String>,
) -> Result<SiemRule, String> {
    siem.inner().add_rule(
        &name,
        description.as_deref().unwrap_or(""),
        min_events.unwrap_or(2),
        window_minutes.unwrap_or(60),
        min_severity.as_deref().unwrap_or("low"),
        title.as_deref().unwrap_or("Корреляция: {cnt} событий с {src} за {window} мин"),
    )
}

#[tauri::command]
pub fn siem_rule_remove(siem: tauri::State<'_, SiemManager>, id: i64) -> Result<String, String> {
    siem.inner().remove_rule(id)
}

#[tauri::command]
pub fn siem_rule_toggle(siem: tauri::State<'_, SiemManager>, id: i64, enabled: bool) -> Result<String, String> {
    siem.inner().toggle_rule(id, enabled)
}

// ---------- Инциденты ----------

#[tauri::command]
pub fn siem_incidents_list(siem: tauri::State<'_, SiemManager>, status: Option<String>) -> Result<Vec<serde_json::Value>, String> {
    siem.inner().list_incidents(status.as_deref())
}

#[tauri::command]
pub fn siem_incident_create(
    siem: tauri::State<'_, SiemManager>,
    src_ip: String,
    severity: String,
    title: String,
    event_ids: Option<String>,
) -> Result<i64, String> {
    siem.inner().create_incident(&src_ip, &severity, &title, event_ids.as_deref())
}

#[tauri::command]
pub fn siem_incident_set_status(siem: tauri::State<'_, SiemManager>, id: i64, status: String) -> Result<String, String> {
    siem.inner().set_incident_status(id, &status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mgr() -> (PathBuf, SiemManager) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("w420_siem_test_{}_{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("siem.db");
        let _ = std::fs::remove_file(&db);
        let m = SiemManager { db: Mutex::new(db.clone()) };
        m.init(&db);
        (dir, m)
    }

    fn insert(c: &Connection, ts: &str, src_ip: &str, sev: &str) {
        c.execute(
            "INSERT INTO events (ts, source, category, severity, src_ip, message) VALUES (?1,'ids','test',?2,?3,'x')",
            rusqlite::params![ts, sev, src_ip],
        ).unwrap();
    }

    #[test]
    fn test_correlate_groups_by_ip() {
        let (_d, m) = test_mgr();
        let c = m.conn().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        insert(&c, &now, "10.0.0.5", "high");
        insert(&c, &now, "10.0.0.5", "high");
        insert(&c, &now, "10.0.0.9", "low");
        let made = m.correlate().unwrap();
        assert_eq!(made, 1);
        let open: i64 = c.query_row("SELECT COUNT(*) FROM incidents WHERE src_ip='10.0.0.5' AND status='open'", [], |r| r.get(0)).unwrap();
        assert_eq!(open, 1);
        // повторная корреляция не плодит дубликат
        assert_eq!(m.correlate().unwrap(), 0);
    }

    #[test]
    fn test_correlate_critical_single() {
        let (_d, m) = test_mgr();
        let c = m.conn().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        insert(&c, &now, "1.2.3.4", "critical");
        assert_eq!(m.correlate().unwrap(), 1);
    }

    #[test]
    fn test_fetch_and_search() {
        let (_d, m) = test_mgr();
        let c = m.conn().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        insert(&c, &now, "5.6.7.8", "high");
        assert_eq!(m.fetch_events(None, 10).unwrap().len(), 1);
        assert_eq!(m.fetch_events(Some("low"), 10).unwrap().len(), 0);
        assert_eq!(m.search("5.6.7.8", 10).unwrap().len(), 1);
        let d = m.dashboard().unwrap();
        assert_eq!(d["total_events"].as_i64().unwrap(), 1);
    }

    #[test]
    fn test_ingest_does_not_panic() {
        // ingest читает реальные ~/.w420 БД (или молча пропускает их отсутствие)
        let (_d, m) = test_mgr();
        let _ = m.ingest();
    }

    #[test]
    fn test_rules_crud_and_toggle() {
        let (_d, m) = test_mgr();
        // дефолтные правила засеяны
        let rules = m.list_rules().unwrap();
        assert!(rules.iter().any(|r| r.name == "burst-src"), "дефолтное правило burst-src должно быть");
        assert!(rules.iter().any(|r| r.name == "critical-single"));
        // add
        let r = m.add_rule("ssh-brute", "брутфорс ssh", 5, 10, "medium", "Брутфорс: {cnt} событий с {src}").unwrap();
        assert!(r.enabled);
        // валидация
        assert!(m.add_rule("", "x", 1, 1, "low", "t").is_err());
        assert!(m.add_rule("x", "x", 1, 1, "nope", "t").is_err());
        // toggle off — правило перестаёт срабатывать; дефолтные тоже выключаем для чистоты
        m.toggle_rule(r.id, false).unwrap();
        for x in m.list_rules().unwrap() { if x.id != r.id { m.toggle_rule(x.id, false).unwrap(); } }
        let c = m.conn().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        for _ in 0..6 { insert(&c, &now, "9.9.9.9", "medium"); }
        assert_eq!(m.correlate().unwrap(), 0, "все правила выключены — корреляции нет");
        // включаем наше правило обратно: 6 событий ≥ 5 → инцидент
        m.toggle_rule(r.id, true).unwrap();
        assert_eq!(m.correlate().unwrap(), 1);
        let inc = m.list_incidents(None).unwrap();
        assert_eq!(inc.len(), 1);
        assert!(inc[0]["title"].as_str().unwrap().contains("9.9.9.9"));
        // remove
        m.remove_rule(r.id).unwrap();
        assert!(m.list_rules().unwrap().iter().all(|x| x.id != r.id));
    }

    #[test]
    fn test_rule_min_severity_filter() {
        let (_d, m) = test_mgr();
        let r = m.add_rule("high-only", "только high+", 2, 60, "high", "High: {cnt} с {src}").unwrap();
        m.toggle_rule(r.id, true).unwrap();
        // выключаем дефолтные, чтобы считать только наше правило
        for x in m.list_rules().unwrap() { if x.name != "high-only" { m.toggle_rule(x.id, false).unwrap(); } }
        let c = m.conn().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        insert(&c, &now, "8.8.8.8", "low");
        insert(&c, &now, "8.8.8.8", "medium"); // ранги ниже high — не считаются
        assert_eq!(m.correlate().unwrap(), 0, "low/medium не должны считаться правилом high+");
        insert(&c, &now, "8.8.8.8", "high");
        insert(&c, &now, "8.8.8.8", "critical");
        assert_eq!(m.correlate().unwrap(), 1);
    }

    #[test]
    fn test_incidents_crud() {
        let (_d, m) = test_mgr();
        let id = m.create_incident("1.1.1.1", "high", "ручной инцидент", Some("1,2")).unwrap();
        assert!(id > 0);
        assert_eq!(m.list_incidents(Some("open")).unwrap().len(), 1);
        m.set_incident_status(id, "in_progress").unwrap();
        assert_eq!(m.list_incidents(Some("open")).unwrap().len(), 0);
        assert_eq!(m.list_incidents(Some("in_progress")).unwrap().len(), 1);
        assert!(m.set_incident_status(id, "weird").is_err());
        m.set_incident_status(id, "resolved").unwrap();
        assert_eq!(m.list_incidents(None).unwrap()[0]["status"], "resolved");
    }

    #[test]
    fn test_severity_rank() {
        assert!(SiemManager::severity_rank("critical") > SiemManager::severity_rank("high"));
        assert!(SiemManager::severity_rank("high") > SiemManager::severity_rank("medium"));
        assert!(SiemManager::severity_rank("medium") > SiemManager::severity_rank("low"));
        assert_eq!(SiemManager::severity_rank("что-то"), 1);
    }

    /// Живой end-to-end: реальный ingest из ~/.w420 + корреляция + AI-сводка через NVIDIA.
    /// Запуск вручную: cargo test -p w420 --lib live_siem -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn live_siem_ingest_ai_summary() {
        let m = SiemManager::new();
        let added = m.ingest().unwrap();
        let incidents = m.correlate().unwrap();
        println!("LIVE ingest: +{added} событий, новых инцидентов: {incidents}");
        let d = m.dashboard().unwrap();
        println!("LIVE dashboard: total={} by_severity={:?}", d["total_events"], d["by_severity"]);
        let summary = m.ai_summary().await.expect("AI-сводка должна пройти через NVIDIA");
        println!("LIVE AI summary:\n{summary}");
        assert!(!summary.is_empty());
    }
}

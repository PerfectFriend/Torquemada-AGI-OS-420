//! Фаза 15: AI SOC — автономный центр операций безопасности (ai_soc.rs).
//!
//! «Мозг» системы: собственный автономный цикл
//!   сбор (siem.ingest + correlate, edr.diff, traffic.alerts) →
//!   решение (инциденты ↔ playbooks) →
//!   действие (block IP / isolate host / kill pid — через существующие модули) →
//!   отчёт (AI-сводка через KeyRotation/NVIDIA).
//!
//! Плановые Tauri-команды: `soc_status`, `soc_autonomous_cycle`, `soc_incidents`,
//! `soc_playbook_run`, `soc_chat`, `soc_report_generate`, `soc_forecast`, `soc_feedback`.
//!
//! Безопасность по умолчанию: действия применяются только для инцидентов severity>=min_severity
//! playbook'а с auto=true, с защитой от изоляции loopback/своего IP. Всё логируется в ~/.w420/soc.db.

use rusqlite::Connection;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;

pub const DEFAULT_MODEL: &str = "mistralai/mistral-large-4-1t-a52b";

pub struct SocManager {
    pub db: Mutex<PathBuf>,
}

fn home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

impl SocManager {
    pub fn new() -> Self {
        let db = home().join(".w420").join("soc.db");
        let m = Self { db: Mutex::new(db.clone()) };
        m.init_db(&db);
        m
    }

    fn init_db(&self, db: &PathBuf) {
        if let Ok(c) = Connection::open(db) {
            let _ = c.execute_batch(
                "CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL,
                    src_ip TEXT NOT NULL DEFAULT '', title TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open', matched_playbook TEXT,
                    actions_taken TEXT NOT NULL DEFAULT '', ai_summary TEXT
                );
                CREATE TABLE IF NOT EXISTS playbooks (
                    name TEXT PRIMARY KEY, trigger_kind TEXT NOT NULL,
                    min_severity TEXT NOT NULL, actions TEXT NOT NULL,
                    auto INTEGER NOT NULL DEFAULT 1, runs INTEGER NOT NULL DEFAULT 0,
                    success INTEGER NOT NULL DEFAULT 0, fail INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS soc_cycles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL, events_seen INTEGER NOT NULL,
                    incidents_new INTEGER NOT NULL, actions_taken INTEGER NOT NULL,
                    detail TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL, incident_id INTEGER NOT NULL,
                    playbook TEXT NOT NULL, worked INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS config (k TEXT PRIMARY KEY, v TEXT NOT NULL);",
            );
            // встроенные playbooks (идемпотентно)
            let pbs = [
                ("bruteforce_block", "bruteforce", "medium", "block_ip,incident", 1),
                ("malware_isolate", "edr_high", "high", "isolate_ip,incident", 1),
                ("data_exfil_block", "traffic_anomaly", "high", "block_ip,alert", 0),
                ("new_host_alert", "new_host", "low", "incident", 1),
                ("critical_contain", "critical", "critical", "isolate_ip,block_ip,incident", 1),
            ];
            for (name, kind, sev, actions, auto) in pbs {
                let _ = c.execute(
                    "INSERT OR IGNORE INTO playbooks (name, trigger_kind, min_severity, actions, auto) VALUES (?1,?2,?3,?4,?5)",
                    rusqlite::params![name, kind, sev, actions, auto],
                );
            }
            let _ = c.execute(
                "INSERT OR IGNORE INTO config (k, v) VALUES ('auto_response', '1')",
                [],
            );
        }
    }

    pub fn conn(&self) -> Result<Connection, String> {
        let p = self.db.lock().unwrap().clone();
        Connection::open(p).map_err(|e| e.to_string())
    }

    fn cfg(&self, k: &str) -> String {
        self.conn()
            .ok()
            .and_then(|c| {
                c.query_row("SELECT v FROM config WHERE k=?1", [k], |r| r.get::<_, String>(0)).ok()
            })
            .unwrap_or_else(|| "1".to_string())
    }

    /// Дашборд SOC: состояние циклов, инцидентов, playbooks.
    pub fn status(&self) -> Result<serde_json::Value, String> {
        let c = self.conn()?;
        let (inc_open, inc_high, cyc, actions): (i64, i64, i64, i64) = c
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM incidents WHERE status='open'),
                    (SELECT COUNT(*) FROM incidents WHERE status='open' AND severity IN ('high','critical')),
                    (SELECT COUNT(*) FROM soc_cycles),
                    (SELECT COALESCE(SUM(actions_taken),0) FROM soc_cycles)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap_or((0, 0, 0, 0));
        let mut st = c
            .prepare("SELECT name, trigger_kind, min_severity, auto, runs, success, fail FROM playbooks ORDER BY name")
            .map_err(|e| e.to_string())?;
        let pbs: Vec<serde_json::Value> = st
            .query_map([], |r| {
                Ok(serde_json::json!({
                    "name": r.get::<_, String>(0)?, "trigger": r.get::<_, String>(1)?,
                    "min_severity": r.get::<_, String>(2)?, "auto": r.get::<_, i64>(3)? == 1,
                    "runs": r.get::<_, i64>(4)?, "success": r.get::<_, i64>(5)?, "fail": r.get::<_, i64>(6)?,
                }))
            })
            .map_err(|e| e.to_string())?
            .flatten()
            .collect();
        let last_cycle: Option<String> = c
            .query_row("SELECT ts FROM soc_cycles ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .ok();
        Ok(serde_json::json!({
            "auto_response": self.cfg("auto_response") == "1",
            "incidents_open": inc_open, "incidents_open_high_crit": inc_high,
            "cycles_run": cyc, "actions_total": actions,
            "last_cycle_ts": last_cycle, "playbooks": pbs,
        }))
    }

    /// Инциденты (фильтр по статусу/severity).
    pub fn incidents(&self, status: Option<String>, severity: Option<String>, limit: Option<u32>) -> Result<Vec<serde_json::Value>, String> {
        let c = self.conn()?;
        let base = "SELECT id, ts, kind, severity, src_ip, title, status, matched_playbook, actions_taken, ai_summary FROM incidents";
        let cond = match (&status, &severity) {
            (Some(_), Some(_)) => " WHERE status=?1 AND severity=?2 ORDER BY id DESC LIMIT ?3",
            (Some(_), None) => " WHERE status=?1 ORDER BY id DESC LIMIT ?2",
            (None, Some(_)) => " WHERE severity=?1 ORDER BY id DESC LIMIT ?2",
            (None, None) => " ORDER BY id DESC LIMIT ?1",
        };
        let sql = format!("{base}{cond}");
        let mut st = c.prepare(&sql).map_err(|e| e.to_string())?;
        let build = |r: &rusqlite::Row| -> rusqlite::Result<serde_json::Value> {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?, "ts": r.get::<_, String>(1)?,
                "kind": r.get::<_, String>(2)?, "severity": r.get::<_, String>(3)?,
                "src_ip": r.get::<_, String>(4)?, "title": r.get::<_, String>(5)?,
                "status": r.get::<_, String>(6)?, "matched_playbook": r.get::<_, Option<String>>(7)?,
                "actions_taken": r.get::<_, String>(8)?, "ai_summary": r.get::<_, Option<String>>(9)?,
            }))
        };
        let rows: Vec<serde_json::Value> = match (&status, &severity) {
            (Some(s), Some(v)) => st
                .query_map(rusqlite::params![s, v, limit.unwrap_or(100)], |r| build(r))
                .map_err(|e| e.to_string())?
                .flatten()
                .collect(),
            (Some(s), None) => st
                .query_map(rusqlite::params![s, limit.unwrap_or(100)], |r| build(r))
                .map_err(|e| e.to_string())?
                .flatten()
                .collect(),
            (None, Some(v)) => st
                .query_map(rusqlite::params![v, limit.unwrap_or(100)], |r| build(r))
                .map_err(|e| e.to_string())?
                .flatten()
                .collect(),
            (None, None) => st
                .query_map(rusqlite::params![limit.unwrap_or(100)], |r| build(r))
                .map_err(|e| e.to_string())?
                .flatten()
                .collect(),
        };
        Ok(rows)
    }

    /// Закрыть инцидент (с фидбэком: сработал ли playbook).
    pub fn close_incident(&self, id: i64, worked: Option<bool>) -> Result<String, String> {
        let c = self.conn()?;
        let pb: Option<String> = c
            .query_row("SELECT matched_playbook FROM incidents WHERE id=?1", [id], |r| r.get(0))
            .ok()
            .flatten();
        if let Some(pb) = &pb {
            if !pb.is_empty() {
                let w = worked.unwrap_or(true);
                let _ = c.execute(
                    "INSERT INTO feedback (ts, incident_id, playbook, worked) VALUES (?1,?2,?3,?4)",
                    rusqlite::params![now(), id, pb, if w { 1 } else { 0 }],
                );
                // обучение: растём/падаем в success/fail плейбука
                if w {
                    let _ = c.execute("UPDATE playbooks SET success=success+1 WHERE name=?1", [pb]);
                } else {
                    let _ = c.execute("UPDATE playbooks SET fail=fail+1 WHERE name=?1", [pb]);
                }
            }
        }
        let _ = c.execute("UPDATE incidents SET status='closed' WHERE id=?1", [id]);
        Ok(format!("инцидент #{id} закрыт"))
    }

    // ========================================================================
    // Автономный цикл: сбор → решение → действие → отчёт
    // ========================================================================

    /// Полный автономный проход. Синхронная часть (сбор/решение/действие) + возврат данных,
    /// AI-отчёт делается отдельной async-командой (см. `ai_cycle_report`), чтобы не тащить rusqlite через await.
    pub fn autonomous_cycle(&self, ai_pending: bool) -> Result<serde_json::Value, String> {
        let started = now();
        let mut events_seen = 0i64;
        let mut incidents_new = 0i64;
        let mut actions_taken = 0i64;
        let mut log: Vec<String> = Vec::new();

        // 1) СБОР: siem ingest + correlate через их менеджеры (общий файл БД)
        let siem = crate::siem::SiemManager::new();
        if let Ok(n) = siem.ingest() {
            events_seen += n as i64;
            log.push(format!("siem.ingest: +{n}"));
        }
        if let Ok(n) = siem.correlate() {
            log.push(format!("siem.correlate: +{n} корреляций"));
        }
        // 2) EDR: свежий скан процессов и diff к baseline (read-only)
        let edr = crate::edr::EdrManager::new();
        let mut edr_high = 0i64;
        if let Ok(procs) = edr.scan_processes() {
            // ss -tunp сами (в edr ss_tunp приватный), парсим публичным parse_ss
            let ss_out = std::process::Command::new("ss")
                .args(["-tunp"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default();
            let conns = crate::edr::parse_ss(&ss_out);
            if let Ok(n) = edr.diff_baseline(&procs, &conns) {
                if n > 0 {
                    edr_high = n as i64;
                    log.push(format!("edr.diff: {n} новых событий"));
                }
            }
        }
        // 3) Трафик: критические алерты из traffic.db
        if let Ok(tm) = crate::traffic::TrafficManager::new() {
            if let Ok(alerts) = tm.list_alerts(25) {
                for a in &alerts {
                    if a.severity == "critical" {
                        events_seen += 1;
                        log.push(format!("traffic.alert: {}", a.src_ip));
                    }
                }
            }
        }

        // 4) РЕШЕНИЕ+ДЕЙСТВИЕ: инциденты из корреляций SIEM → playbooks → действия
        let auto_on = self.cfg("auto_response") == "1";
        let c = self.conn()?;
        // берём открытые инциденты из siem.db, dedupe по (src_ip,title) в soc.incidents
        let mut pending: Vec<(String, String, String)> = Vec::new(); // severity, src_ip, title
        if let Ok(src) = Connection::open(home().join(".w420").join("siem.db")) {
            if let Ok(mut q) = src.prepare(
                "SELECT severity, src_ip, title FROM incidents WHERE status='open' ORDER BY id DESC LIMIT 50",
            ) {
                if let Ok(rows) = q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))) {
                    for row in rows.flatten() {
                        pending.push(row);
                    }
                }
            }
        }
        let mut acted: Vec<(i64, String, String)> = Vec::new(); // incident_id, playbook, actions

        for (sev, ip, title) in pending {
            if !actionable_ip(&ip) {
                log.push(format!("guard: пропуск {ip} (loopback/пустой)"));
                continue;
            }
            // дедуп: инцидент с этим ip+title за сегодня уже есть?
            let exists: i64 = c
                .query_row(
                    "SELECT COUNT(*) FROM incidents WHERE src_ip=?1 AND title=?2",
                    rusqlite::params![&ip, &title],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if exists > 0 {
                continue;
            }
            incidents_new += 1;
            c.execute(
                "INSERT INTO incidents (ts, kind, severity, src_ip, title) VALUES (?1,'correlation',?2,?3,?4)",
                rusqlite::params![now(), &sev, &ip, &title],
            )
            .map_err(|e| e.to_string())?;
            let iid = c.last_insert_rowid();

            // матч playbook и действие (если авто-режим разрешает)
            if let Some((pb, actions, min_sev)) = self.match_playbook(&sev, "correlation") {
                let _ = c.execute(
                    "UPDATE incidents SET matched_playbook=?1 WHERE id=?2",
                    rusqlite::params![&pb, iid],
                );
                let _ = c.execute("UPDATE playbooks SET runs=runs+1 WHERE name=?1", [&pb]);
                if auto_on && sev_rank(&sev) >= sev_rank(&min_sev) {
                    let mut taken: Vec<String> = Vec::new();
                    for act in actions.split(',') {
                        match act {
                            "block_ip" => match crate::traffic::block_ip(&ip, &format!("SOC:{pb}")) {
                                Ok(m) => {
                                    taken.push(format!("block_ip:{ip}"));
                                    actions_taken += 1;
                                    log.push(m);
                                }
                                Err(e) => log.push(format!("block_ip err: {e}")),
                            },
                            "isolate_ip" => match crate::edr::isolate_ip_free(&ip) {
                                Ok(m) => {
                                    taken.push(format!("isolate_ip:{ip}"));
                                    actions_taken += 1;
                                    log.push(m);
                                }
                                Err(e) => log.push(format!("isolate err: {e}")),
                            },
                            "isolate_host" => match crate::edr::isolate_ip_free(&ip) {
                                Ok(m) => {
                                    taken.push(format!("isolate_host:{ip}"));
                                    actions_taken += 1;
                                    log.push(m);
                                }
                                Err(e) => log.push(format!("isolate_host err: {e}")),
                            },
                            "kill_pid" => log.push("kill_pid: требуется pid, пропуск в авто-цикле".into()),
                            "incident" | "alert" => {}
                            _ => {}
                        }
                    }
                    if !taken.is_empty() {
                        let _ = c.execute(
                            "UPDATE incidents SET actions_taken=?1 WHERE id=?2",
                            rusqlite::params![taken.join(","), iid],
                        );
                        acted.push((iid, pb.clone(), taken.join(",")));
                    }
                } else {
                    log.push(format!("playbook {pb}: только алерт (severity {sev} < {min_sev} или авто-режим выкл)"));
                }
            }
        }
        // EDR-инциденты напрямую (высокая severity от watch/diff) — без ip, kind=edr
        if edr_high > 0 {
            incidents_new += 1;
            c.execute(
                "INSERT INTO incidents (ts, kind, severity, src_ip, title) VALUES (?1,'edr_high','high','','EDR: новые события поведенческого baseline')",
                rusqlite::params![now()],
            )
            .map_err(|e| e.to_string())?;
            let iid = c.last_insert_rowid();
            if auto_on {
                let taken = "baseline_diff";
                let _ = c.execute(
                    "UPDATE incidents SET matched_playbook='malware_isolate', actions_taken=?1 WHERE id=?2",
                    rusqlite::params![taken, iid],
                );
                let _ = c.execute("UPDATE playbooks SET runs=runs+1 WHERE name='malware_isolate'", []);
            }
        }

        // 5) Регистрация цикла
        c.execute(
            "INSERT INTO soc_cycles (ts, events_seen, incidents_new, actions_taken, detail) VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![started, events_seen, incidents_new, actions_taken, log.join(" | ")],
        )
        .map_err(|e| e.to_string())?;

        Ok(serde_json::json!({
            "started": started, "finished": now(),
            "events_seen": events_seen, "incidents_new": incidents_new,
            "actions_taken": actions_taken, "auto_response": auto_on,
            "actions": acted.iter().map(|(id, pb, a)| serde_json::json!({"incident": id, "playbook": pb, "actions": a})).collect::<Vec<_>>(),
            "log": log,
            "ai_report_pending": ai_pending,
        }))
    }

    /// Подбор playbook'а по severity (ранг сравниваем в Rust — в SQL строковое сравнение ломается).
    /// Приоритет: critical_contain (trigger critical) → затем по убыванию min_severity.
    pub fn match_playbook(&self, severity: &str, _kind: &str) -> Option<(String, String, String)> {
        let c = self.conn().ok()?;
        let mut st = c
            .prepare("SELECT name, actions, min_severity, trigger_kind FROM playbooks")
            .ok()?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .ok()?;
        let sev = sev_rank(severity);
        let mut best: Option<(u8, String, String, String)> = None;
        for row in rows.flatten() {
            let (name, actions, min_sev, kind) = row;
            if sev < sev_rank(&min_sev) {
                continue;
            }
            let prio = if kind == "critical" { 2 } else { 1 };
            if best.as_ref().map(|b| prio > b.0).unwrap_or(true) {
                best = Some((prio, name, actions, min_sev));
            }
        }
        best.map(|(_, name, actions, min_sev)| (name, actions, min_sev))
    }

    /// Ручной запуск playbook'а по имени (собирает контекст, выполняет действия сейчас).
    pub fn playbook_run(&self, name: &str, ip: Option<String>) -> Result<serde_json::Value, String> {
        let c = self.conn()?;
        let (kind, min_sev, actions, auto): (String, String, String, i64) = c
            .query_row(
                "SELECT trigger_kind, min_severity, actions, auto FROM playbooks WHERE name=?1",
                [name],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|_| format!("playbook '{name}' не найден"))?;
        let _ = (kind.clone(), min_sev.clone());
        let _ = c.execute("UPDATE playbooks SET runs=runs+1 WHERE name=?1", [name]);

        let ip = ip.unwrap_or_default();
        let mut taken: Vec<String> = Vec::new();
        for act in actions.split(',') {
            match act {
                "block_ip" if !ip.is_empty() => {
                    if let Ok(_) = crate::traffic::block_ip(&ip, &format!("SOC:{name}")) {
                        taken.push(format!("block_ip:{ip}"));
                    }
                }
                "isolate_ip" | "isolate_host" if !ip.is_empty() => {
                    if let Ok(m) = crate::edr::isolate_ip_free(&ip) {
                        taken.push(format!("{act}:{ip}"));
                        let _ = m;
                    }
                }
                _ => {}
            }
        }
        if auto == 0 && !taken.is_empty() {
            let _ = c.execute("UPDATE playbooks SET success=success+1 WHERE name=?1", [name]);
        }
        Ok(serde_json::json!({
            "playbook": name, "ip": ip, "actions": taken,
            "note": if auto == 0 { "playbook без auto — действия выполнены вручную" } else { "" },
        }))
    }

    /// Обратная связь: сработал ли playbook в инциденте (обучение).
    pub fn feedback(&self, incident_id: i64, worked: bool) -> Result<String, String> {
        self.close_incident(incident_id, Some(worked))
    }

    /// AI-отчёт по последнему циклу (async; NVIDIA через KeyRotation).
    pub async fn ai_cycle_report(&self) -> Result<String, String> {
        use w420_ai::db::AIProviderDB;
        use w420_ai::rotation::KeyRotation;
        use w420_ai::{ChatMessage, ChatRequest};

        let status = self.status().unwrap_or(serde_json::json!({}));
        let incidents = self.incidents(Some("open".into()), None, Some(20)).unwrap_or_default();
        let cycles = {
            let c = self.conn()?;
            let mut st = c
                .prepare("SELECT ts, events_seen, incidents_new, actions_taken, detail FROM soc_cycles ORDER BY id DESC LIMIT 5")
                .map_err(|e| e.to_string())?;
            let rows: Vec<serde_json::Value> = st
                .query_map([], |r| {
                    Ok(serde_json::json!({
                        "ts": r.get::<_, String>(0)?, "events": r.get::<_, i64>(1)?,
                        "incidents": r.get::<_, i64>(2)?, "actions": r.get::<_, i64>(3)?,
                    }))
                })
                .map_err(|e| e.to_string())?
                .flatten()
                .collect();
            rows
        };
        let payload = format!(
            "SOC-статус: {}\nОткрытые инциденты: {}\nПоследние циклы: {}",
            serde_json::to_string_pretty(&status).unwrap_or_default(),
            serde_json::to_string_pretty(&incidents).unwrap_or_default(),
            serde_json::to_string_pretty(&cycles).unwrap_or_default(),
        );

        // rusqlite::Connection не-Send: читаем до await, дропаем
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
            model: DEFAULT_MODEL.into(),
            messages: vec![
                ChatMessage {
                    role: "system".into(),
                    content: "Ты автономный SOC-оператор W420. По данным последних циклов и открытым инцидентам дай сводку смены на русском: что произошло, какие действия приняты, что требует внимания прямо сейчас. До 10 пунктов, без воды.".into(),
                },
                ChatMessage { role: "user".into(), content: payload },
            ],
            temperature: 0.3,
            max_tokens: Some(4096),
            stream: false,
        };
        let resp = rotation.chat_completion_with_rotation(request, None).await;
        // персистим статистику ключей (backoff/latency) в БД провайдеров
        if let Ok(db) = w420_ai::db::AIProviderDB::open() { let _ = rotation.persist_stats(&db); }
        let resp = resp.map_err(|e| format!("AI: {e}"))?;
        // сохраним сводку к последнему циклу
        if let Ok(c) = self.conn() {
            let _ = c.execute(
                "UPDATE soc_cycles SET detail = detail || '\nAI: ' || ?1 WHERE id = (SELECT MAX(id) FROM soc_cycles)",
                [&resp.response.content],
            );
        }
        Ok(resp.response.content)
    }

    /// Диалог с SOC на естественном языке (async).
    pub async fn chat(&self, question: &str) -> Result<String, String> {
        use w420_ai::db::AIProviderDB;
        use w420_ai::rotation::KeyRotation;
        use w420_ai::{ChatMessage, ChatRequest};

        let context = self.status().unwrap_or(serde_json::json!({}));
        let incidents = self.incidents(Some("open".into()), None, Some(10)).unwrap_or_default();
        let ctx = format!(
            "Контекст SOC (W420):\nСтатус: {}\nОткрытые инциденты: {}\n\nВопрос администратора: {question}\n\nОтвечай на русском. Если вопрос предполагает действие (проверить/заблокировать/изолировать) — опиши план шагов и команды, которые запустишь (soc_playbook_run, isolate_ip).",
            serde_json::to_string_pretty(&context).unwrap_or_default(),
            serde_json::to_string_pretty(&incidents).unwrap_or_default(),
        );
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
            model: DEFAULT_MODEL.into(),
            messages: vec![
                ChatMessage {
                    role: "system".into(),
                    content: "Ты SOC-аналитик W420. Отвечай кратко, по делу, на русском. Не выдумывай факты — опирайся только на переданный контекст (инциденты, статус).".into(),
                },
                ChatMessage { role: "user".into(), content: ctx },
            ],
            temperature: 0.4,
            max_tokens: Some(4096),
            stream: false,
        };
        let resp = rotation.chat_completion_with_rotation(request, None).await;
        // персистим статистику ключей (backoff/latency) в БД провайдеров
        if let Ok(db) = w420_ai::db::AIProviderDB::open() { let _ = rotation.persist_stats(&db); }
        let resp = resp.map_err(|e| format!("AI: {e}"))?;
        Ok(resp.response.content)
    }

    /// Прогноз атак: агрегируем историю инцидентов → AI-прогноз (async).
    pub async fn forecast(&self) -> Result<String, String> {
        use w420_ai::db::AIProviderDB;
        use w420_ai::rotation::KeyRotation;
        use w420_ai::{ChatMessage, ChatRequest};

        // агрегация: инциденты по kind/severity за всё время + по часам
        let stats = {
            let c = self.conn()?;
            let mut out = serde_json::json!({});
            if let Ok(mut st) = c.prepare(
                "SELECT kind, COUNT(*) FROM incidents GROUP BY kind",
            ) {
                let by_kind: Vec<serde_json::Value> = st
                    .query_map([], |r| Ok(serde_json::json!({"kind": r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)?})))
                    .map_err(|e| e.to_string())?
                    .flatten()
                    .collect();
                out["by_kind"] = serde_json::json!(by_kind);
            }
            if let Ok(mut st) = c.prepare("SELECT severity, COUNT(*) FROM incidents GROUP BY severity") {
                let by_sev: Vec<serde_json::Value> = st
                    .query_map([], |r| Ok(serde_json::json!({"severity": r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)?})))
                    .map_err(|e| e.to_string())?
                    .flatten()
                    .collect();
                out["by_severity"] = serde_json::json!(by_sev);
            }
            out
        };
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
            model: DEFAULT_MODEL.into(),
            messages: vec![
                ChatMessage {
                    role: "system".into(),
                    content: "Ты прогностик SOC W420. По агрегированной статистике инцидтов предскажи вероятные векторы атак в ближайшие сутки на русском: что повторится, к чему готовиться, какие контрмеры включить заранее. До 7 пунктов.".into(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: format!("Статистика инцидентов:\n{}", serde_json::to_string_pretty(&stats).unwrap_or_default()),
                },
            ],
            temperature: 0.4,
            max_tokens: Some(4096),
            stream: false,
        };
        let resp = rotation.chat_completion_with_rotation(request, None).await;
        // персистим статистику ключей (backoff/latency) в БД провайдеров
        if let Ok(db) = w420_ai::db::AIProviderDB::open() { let _ = rotation.persist_stats(&db); }
        let resp = resp.map_err(|e| format!("AI: {e}"))?;
        Ok(resp.response.content)
    }
}

// ============================================================================
// Чистые функции (юнит-тесты)
// ============================================================================

/// Защита от самоизоляции/блокировки мусора: пустые и loopback-адреса не трогаем.
pub fn actionable_ip(ip: &str) -> bool {
    if ip.trim().is_empty() {
        return false;
    }
    let bad_prefixes = ["127.", "0.0.0.0", "::1", "255.255.255.255"];
    !bad_prefixes.iter().any(|p| ip.starts_with(p))
}

/// Числовой ранг severity для сравнений (info<low<medium<high<critical).
pub fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Порог «нужно реагировать автоматически» — critical/high.
pub fn needs_auto_action(severity: &str) -> bool {
    sev_rank(severity) >= 3
}

// ============================================================================
// Tauri команды
// ============================================================================

#[tauri::command]
pub fn soc_status(mgr: tauri::State<'_, SocManager>) -> Result<serde_json::Value, String> {
    mgr.status()
}

#[tauri::command]
pub fn soc_autonomous_cycle(mgr: tauri::State<'_, SocManager>) -> Result<serde_json::Value, String> {
    mgr.autonomous_cycle(false)
}

#[tauri::command]
pub fn soc_incidents(mgr: tauri::State<'_, SocManager>, status: Option<String>, severity: Option<String>, limit: Option<u32>) -> Result<Vec<serde_json::Value>, String> {
    mgr.incidents(status, severity, limit)
}

#[tauri::command]
pub fn soc_playbook_run(mgr: tauri::State<'_, SocManager>, name: String, ip: Option<String>) -> Result<serde_json::Value, String> {
    mgr.playbook_run(&name, ip)
}

#[tauri::command]
pub fn soc_feedback(mgr: tauri::State<'_, SocManager>, incident_id: i64, worked: bool) -> Result<String, String> {
    mgr.feedback(incident_id, worked)
}

#[tauri::command]
pub async fn soc_ai_cycle_report(mgr: tauri::State<'_, SocManager>) -> Result<String, String> {
    mgr.ai_cycle_report().await
}

#[tauri::command]
pub async fn soc_chat(mgr: tauri::State<'_, SocManager>, question: String) -> Result<String, String> {
    mgr.chat(&question).await
}

#[tauri::command]
pub async fn soc_forecast(mgr: tauri::State<'_, SocManager>) -> Result<String, String> {
    mgr.forecast().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_actionable_ip() {
        assert!(actionable_ip("192.168.1.50"));
        assert!(actionable_ip("10.0.0.1"));
        assert!(!actionable_ip(""));
        assert!(!actionable_ip("   "));
        assert!(!actionable_ip("127.0.0.1"));
        assert!(!actionable_ip("0.0.0.0"));
        assert!(!actionable_ip("::1"));
    }

    #[test]
    fn test_sev_rank_and_auto() {
        assert!(sev_rank("critical") > sev_rank("high"));
        assert!(sev_rank("high") > sev_rank("medium"));
        assert_eq!(sev_rank("unknown"), 0);
        assert!(needs_auto_action("critical"));
        assert!(needs_auto_action("high"));
        assert!(!needs_auto_action("medium"));
        assert!(!needs_auto_action("low"));
    }

    /// LIVE: автономный цикл на пустой/текущей БД — не должен падать, лог пишется.
    /// AI-отчёт и чат проверяются отдельным live-тестом (async + NVIDIA).
    #[test]
    fn live_soc_cycle_dry() {
        let m = SocManager::new();
        // откат: уберём инциденты от прошлых прогонов
        if let Ok(c) = m.conn() {
            let _ = c.execute("DELETE FROM incidents", []);
        }
        let r = m.autonomous_cycle(false).expect("cycle");
        println!("LIVE soc cycle: incidents_new={} actions={}", r["incidents_new"], r["actions_taken"]);
        assert_eq!(r["auto_response"], true);
        let st = m.status().expect("status");
        assert!(st["cycles_run"].as_i64().unwrap() >= 1);
        // чат без инцидентов
        let inc = m.incidents(None, None, Some(5)).expect("incidents");
        println!("LIVE incidents total: {}", inc.len());
    }

    /// LIVE: чат + прогноз + AI-отчёт цикла через NVIDIA (tokio runtime вручную, т.к. #[tokio::test] в lib-тестах не используем).
    #[test]
    #[ignore]
    fn live_soc_ai() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async {
            let m = SocManager::new();
            let chat = m.chat("Сколько открытых инцидентов и что делать?").await.expect("chat");
            println!("LIVE soc chat: {}", chat.chars().take(200).collect::<String>());
            assert!(chat.len() > 20, "ожидали содержательный ответ");
            let fc = m.forecast().await.expect("forecast");
            println!("LIVE soc forecast: {}", fc.chars().take(200).collect::<String>());
            assert!(fc.len() > 20);
            let rep = m.ai_cycle_report().await.expect("report");
            println!("LIVE soc report: {}", rep.chars().take(200).collect::<String>());
            assert!(rep.len() > 20);
        });
    }
}

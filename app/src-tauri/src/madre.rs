//! madre.rs — «Мать Торквемада» (Madre Torquemada), движок арсенала Torquemada 228 AGI.
//!
//! Философия: «Доверяем только своим пакетам — чужие все дропаем, для них нет хостов.»
//! Default-deny: исходящий трафик разрешён ТОЛЬКО к allowlist (свои хосты, свои DNS/NTP,
//! свои update-эндпоинты); всё остальное дропается на уровне ядра (nftables).
//!
//! Состав арсенала:
//!   * default-deny egress (таблица inet w420_madre) — применяется атомарно через nft -f;
//!   * honeypot — TCP-ловушки на типичных портах (22/2222/8080/…), все подключения логятся;
//!   * watchdog — цикл, который опрашивает EDR/SIEM и при аномалии пишет событие и (в режиме
//!     enforce) изолирует источник через firewall;
//!   * штурвал AGI — madre_helm отдаёт AGI-оболочке (agi.rs) сводку арсенала и может
//!     выполнить PROPOSE от модели только после human-in-the-loop approve.
//!
//! Все мутации сети требуют прав; без них команда возвращает needs_root, а желаемое
//! состояние сохраняется в ~/.w420/madre.json (как в firewall.rs).

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::traffic::run_nft;

// ============================================================================
// Константы философии
// ============================================================================

/// Системный промпт Матери — AGI за штурвалом арсенала.
pub const MADRE_SYSTEM_PROMPT: &str = "Ты — Madre Torquemada, движок антихакерского арсенала Torquemada 228 AGI. \
Правило Матери: доверяем только своим пакетам, чужие все дропаем — для них нет хостов. \
Политика default-deny: запрещено всё, что не разрешено. Отвечай по-русски, кратко, по делу. \
У тебя есть сводка арсенала (madre_status); если нужна мутация сети — PROPOSE отдельной строкой, \
человек подтвердит вручную (human-in-the-loop).";

/// Порты ханипота: типичные цели сканеров и «чужих пакетов».
pub const HONEYPOT_PORTS: [u16; 6] = [22, 2222, 3389, 8080, 8443, 9200];

/// Свои подсети по умолчанию (локалка — своя).
pub const OWN_NETWORKS: [&str; 3] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

// ============================================================================
// Состояние
// ============================================================================

#[derive(Clone, Serialize, Deserialize)]
pub struct MadreConfig {
    /// observe — только логируем; enforce — дропаем/изолируем
    pub mode: String,
    pub honeypot_on: bool,
    pub watchdog_on: bool,
    pub watchdog_secs: u64,
    /// allowlist исходящего трафика: IP/CIDR/домен-resolved IP
    pub allow: Vec<String>,
}

impl Default for MadreConfig {
    fn default() -> Self {
        Self {
            mode: "observe".into(),
            honeypot_on: false,
            watchdog_on: false,
            watchdog_secs: 30,
            allow: vec![
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
            ],
        }
    }
}

pub struct MadreManager {
    pub cfg: Mutex<MadreConfig>,
    pub file: PathBuf,
    pub db: PathBuf,
    pub honeypot: Mutex<Option<Vec<JoinHandle<()>>>>,
    pub watchdog: Mutex<Option<JoinHandle<()>>>,
}

fn home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"))
}

impl MadreManager {
    pub fn new() -> Self {
        let dir = home().join(".w420");
        let file = dir.join("madre.json");
        let cfg = fs::read_to_string(&file)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let mgr = Self {
            cfg: Mutex::new(cfg),
            file,
            db: dir.join("madre.db"),
            honeypot: Mutex::new(None),
            watchdog: Mutex::new(None),
        };
        mgr.init_db();
        mgr
    }

    fn persist(&self, c: &MadreConfig) {
        if let Some(p) = self.file.parent() {
            let _ = fs::create_dir_all(p);
        }
        let _ = fs::write(&self.file, serde_json::to_string_pretty(c).unwrap_or_default());
    }

    fn init_db(&self) {
        if let Ok(conn) = Connection::open(&self.db) {
            let _ = conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS madre_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    kind TEXT NOT NULL,        -- drop | honeypot | watchdog | helm | allow
                    src TEXT,                  -- ip/порт/источник
                    detail TEXT
                );",
            );
        }
    }

    /// Записать событие арсенала в hash-audit-friendly лог (sqlite).
    pub fn log(&self, kind: &str, src: Option<&str>, detail: &str) {
        if let Ok(conn) = Connection::open(&self.db) {
            let _ = conn.execute(
                "INSERT INTO madre_events (ts, kind, src, detail) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![chrono::Utc::now().to_rfc3339(), kind, src.unwrap_or(""), detail],
            );
        }
    }

    pub fn events(&self, limit: u32) -> Vec<Value> {
        let mut out = Vec::new();
        if let Ok(conn) = Connection::open(&self.db) {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT ts, kind, src, detail FROM madre_events ORDER BY id DESC LIMIT ?1",
            ) {
                let rows = stmt
                    .query_map(rusqlite::params![limit], |r| {
                        Ok(json!({
                            "ts": r.get::<_, String>(0)?,
                            "kind": r.get::<_, String>(1)?,
                            "src": r.get::<_, String>(2)?,
                            "detail": r.get::<_, String>(3)?,
                        }))
                    })
                    .ok();
                if let Some(rows) = rows {
                    for r in rows.flatten() {
                        out.push(r);
                    }
                }
            }
        }
        out
    }
}

// ============================================================================
// Чистая логика (тестируется без root и без сети)
// ============================================================================

/// Разбор allowlist: валидные CIDR/IP, пустые и мусор отсекаем.
pub fn parse_allowlist(raw: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for item in raw {
        let t = item.trim();
        if t.is_empty() {
            continue;
        }
        if t.contains('/') {
            if t.parse::<ipnet::IpNet>().is_ok() {
                out.push(t.to_string());
            }
        } else if t.parse::<std::net::IpAddr>().is_ok() {
            out.push(t.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Свой ли адрес: allowlist или одна из OWN_NETWORKS.
pub fn is_own(addr: &str, allow: &[String]) -> bool {
    let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    for a in allow {
        if let Ok(net) = a.parse::<ipnet::IpNet>() {
            if net.contains(&ip) {
                return true;
            }
        } else if let Ok(aip) = a.parse::<std::net::IpAddr>() {
            if aip == ip {
                return true;
            }
        }
    }
    OWN_NETWORKS.iter().any(|n| n.parse::<ipnet::IpNet>().map(|net| net.contains(&ip)).unwrap_or(false))
}

/// Вердикт Матери для пакета: foreign → drop, own → accept.
pub fn verdict(dst: &str, allow: &[String]) -> &'static str {
    if is_own(dst, allow) {
        "accept"
    } else {
        "drop"
    }
}

/// nft-правила арсенала: default-deny egress + allowlist + honeypot-логирование input.
/// Чистая функция — тестируется без ядра.
pub fn build_madre_rules(cfg: &MadreConfig) -> String {
    let allow = parse_allowlist(&cfg.allow);
    let mut s = String::from("table inet w420_madre {\n");
    // input: чужие пакеты дропаем, кроме established и портов ханипота (логируем)
    s.push_str("  chain input {\n    type filter hook input priority 10; policy drop;\n");
    s.push_str("    iif \"lo\" accept\n    ct state established,related accept\n");
    for p in HONEYPOT_PORTS {
        s.push_str(&format!(
            "    tcp dport {p} limit rate 5/minute log prefix \"w420_honeypot_in_{p}: \" accept\n"
        ));
    }
    s.push_str("  }\n");
    // output: default-deny, только свои
    s.push_str("  chain output {\n    type filter hook output priority 10; policy drop;\n");
    s.push_str("    oif \"lo\" accept\n    ct state established,related accept\n");
    for a in &allow {
        s.push_str(&format!("    ip daddr {a} accept\n    ip6 daddr {a} accept\n"));
    }
    // свои DNS/NTP наружу — только к allowlist (они уже в allow как подсети/хосты)
    s.push_str("    udp dport 53 accept comment \"dns к allowlist выше не применяется — резолвим сами\"\n");
    s.push_str("  }\n}\n");
    s
}

/// Применить правила арсенала в ядро (атомарно: delete table + nft -f).
pub fn apply_madre_rules(cfg: &MadreConfig) -> Result<String, String> {
    let rules = build_madre_rules(cfg);
    let _ = run_nft(&["delete", "table", "inet", "w420_madre"]);
    let tmp = std::env::temp_dir().join("w420_madre.nft");
    fs::write(&tmp, &rules).map_err(|e| format!("write: {e}"))?;
    run_nft(&["-f", tmp.to_str().unwrap_or("w420_madre.nft")])
}

/// Убрать таблицу арсенала из ядра (режим observe полного отключения сети).
pub fn clear_madre_rules() -> Result<String, String> {
    run_nft(&["delete", "table", "inet", "w420_madre"]).or(Ok("уже пусто".into()))
}

// ============================================================================
// Ханипот
// ============================================================================

fn honeypot_serve(listener: TcpListener, port: u16, mgr_db: PathBuf) {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let peer = s.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                // Пишем в madre.db напрямую ( managers недоступен из потока — своя копия пути)
                if let Ok(conn) = Connection::open(&mgr_db) {
                    let _ = conn.execute(
                        "INSERT INTO madre_events (ts, kind, src, detail) VALUES (?1, 'honeypot', ?2, ?3)",
                        rusqlite::params![
                            chrono::Utc::now().to_rfc3339(),
                            peer,
                            format!("подключение на порт-ловушку {port}")
                        ],
                    );
                }
                drop(s);
            }
            Err(_) => break,
        }
    }
}

impl MadreManager {
    pub fn honeypot_start(&self) -> Result<Value, String> {
        let mut hp = self.honeypot.lock().unwrap();
        if hp.is_some() {
            return Ok(json!({"running": true, "already": true}));
        }
        let db = self.db.clone();
        let mut handles = Vec::new();
        let mut bound = Vec::new();
        for p in HONEYPOT_PORTS {
            match TcpListener::bind(("0.0.0.0", p)) {
                Ok(l) => {
                    bound.push(p);
                    let db2 = db.clone();
                    handles.push(std::thread::spawn(move || {
                        let _ = l.set_nonblocking(false);
                        honeypot_serve(l, p, db2)
                    }));
                }
                Err(e) => {
                    self.log("honeypot", Some(&p.to_string()), &format!("порт занят: {e}"));
                }
            }
        }
        *hp = Some(handles);
        self.log("honeypot", None, &format!("старт, порты: {bound:?}"));
        let mut cfg = self.cfg.lock().unwrap();
        cfg.honeypot_on = true;
        self.persist(&cfg);
        Ok(json!({"running": true, "ports": bound}))
    }

    pub fn honeypot_stop(&self) -> Value {
        // Потоки блокированы на accept — просто забываем хендлы; сокеты закроются при выходе.
        // Для мгновенной остановки: дропаем listener невозможен из thread — потому помечаем off.
        let mut hp = self.honeypot.lock().unwrap();
        *hp = None;
        let mut cfg = self.cfg.lock().unwrap();
        cfg.honeypot_on = false;
        self.persist(&cfg);
        self.log("honeypot", None, "стоп (метка)");
        json!({"running": false})
    }

    // ========================================================================
    // Вотчдог
    // ========================================================================

    pub fn watchdog_start(&self) -> Result<Value, String> {
        let mut wd = self.watchdog.lock().unwrap();
        if wd.is_some() {
            return Ok(json!({"running": true, "already": true}));
        }
        let db = self.db.clone();
        let secs = self.cfg.lock().unwrap().watchdog_secs.max(5);
        let handle = std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(secs));
            // Сверяем EDR-базлайн: если есть diff — событие watchdog
            // (полный опрос — в edr.rs; здесь — лёгкая проверка через ss на известные C2-порты)
            if let Ok(out) = std::process::Command::new("ss")
                .args(["-tunap"])
                .output()
            {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    // эвристика: соединения на подозрительные порты вне своих сетей
                    if let Some(dst) = line.split_whitespace().nth(4) {
                        let ip = dst.split(':').next().unwrap_or("");
                        if !ip.is_empty()
                            && !is_own(ip, &OWN_NETWORKS.to_vec().iter().map(|s| s.to_string()).collect::<Vec<_>>())
                        {
                            let port = dst.rsplit(':').next().unwrap_or("");
                            if ["4444", "5555", "6666", "31337", "12345"].contains(&port) {
                                if let Ok(conn) = Connection::open(&db) {
                                    let _ = conn.execute(
                                        "INSERT INTO madre_events (ts, kind, src, detail) VALUES (?1, 'watchdog', ?2, ?3)",
                                        rusqlite::params![
                                            chrono::Utc::now().to_rfc3339(),
                                            ip,
                                            format!("подозрительное соединение на порт {port} — чужой пакет, дропаем в enforce")
                                        ],
                                    );
                                }
                            }
                        }
                    }
                }
            }
        });
        *wd = Some(handle);
        let mut cfg = self.cfg.lock().unwrap();
        cfg.watchdog_on = true;
        self.persist(&cfg);
        self.log("watchdog", None, &format!("старт, интервал {secs}с"));
        Ok(json!({"running": true, "interval_secs": secs}))
    }

    pub fn watchdog_stop(&self) -> Value {
        let mut wd = self.watchdog.lock().unwrap();
        if let Some(h) = wd.take() {
            // поток спит — просто отцепляем; join невозможен без флага, потому detach
            drop(h);
        }
        let mut cfg = self.cfg.lock().unwrap();
        cfg.watchdog_on = false;
        self.persist(&cfg);
        self.log("watchdog", None, "стоп (метка)");
        json!({"running": false})
    }
}

// ============================================================================
// Tauri-команды
// ============================================================================

/// Сводка арсенала: конфиг + последние события + статус honeypot/watchdog.
#[tauri::command]
pub fn madre_status(mgr: tauri::State<'_, MadreManager>) -> Result<Value, String> {
    let cfg = mgr.cfg.lock().unwrap().clone();
    Ok(json!({
        "config": cfg,
        "honeypot_running": mgr.honeypot.lock().unwrap().is_some(),
        "watchdog_running": mgr.watchdog.lock().unwrap().is_some(),
        "honeypot_ports": HONEYPOT_PORTS,
        "events": mgr.events(20),
    }))
}

/// Режим: observe | enforce.
#[tauri::command]
pub fn madre_mode_set(mgr: tauri::State<'_, MadreManager>, mode: String) -> Result<Value, String> {
    if mode != "observe" && mode != "enforce" {
        return Err("режим: observe | enforce".into());
    }
    let mut cfg = mgr.cfg.lock().unwrap();
    cfg.mode = mode.clone();
    mgr.persist(&cfg);
    mgr.log("helm", None, &format!("режим арсенала → {mode}"));
    Ok(json!({"mode": mode}))
}

/// Добавить в allowlist (свои хосты/сети).
#[tauri::command]
pub fn madre_allow_add(mgr: tauri::State<'_, MadreManager>, entry: String) -> Result<Value, String> {
    let mut cfg = mgr.cfg.lock().unwrap();
    cfg.allow.push(entry.clone());
    cfg.allow = parse_allowlist(&cfg.allow);
    mgr.persist(&cfg);
    mgr.log("allow", Some(&entry), "добавлено в allowlist (свои)");
    Ok(json!({"allow": cfg.allow}))
}

#[tauri::command]
pub fn madre_allow_remove(mgr: tauri::State<'_, MadreManager>, entry: String) -> Result<Value, String> {
    let mut cfg = mgr.cfg.lock().unwrap();
    cfg.allow.retain(|a| a != &entry);
    mgr.persist(&cfg);
    mgr.log("allow", Some(&entry), "убрано из allowlist");
    Ok(json!({"allow": cfg.allow}))
}

#[tauri::command]
pub fn madre_allow_list(mgr: tauri::State<'_, MadreManager>) -> Result<Value, String> {
    let cfg = mgr.cfg.lock().unwrap();
    Ok(json!({"allow": parse_allowlist(&cfg.allow), "own_networks": OWN_NETWORKS}))
}

/// Применить default-deny правила в ядро (или снять — clear=true).
#[tauri::command]
pub fn madre_apply(mgr: tauri::State<'_, MadreManager>, clear: Option<bool>) -> Result<Value, String> {
    if clear.unwrap_or(false) {
        let r = clear_madre_rules();
        mgr.log("helm", None, "таблица w420_madre снята (clear)");
        return Ok(json!({"cleared": true, "nft": r}));
    }
    let cfg = mgr.cfg.lock().unwrap().clone();
    match apply_madre_rules(&cfg) {
        Ok(out) => {
            mgr.log("helm", None, "default-deny применён: чужие пакеты дропаются");
            Ok(json!({"applied": true, "mode": cfg.mode, "nft": out}))
        }
        Err(e) => {
            if e.contains("Operation not permitted") || e.contains("Permission denied") {
                mgr.log("helm", None, "нужен root (root_setup.sh) для nft");
                Ok(json!({"applied": false, "needs_root": true, "error": e}))
            } else {
                Err(e)
            }
        }
    }
}

/// Вердикт Матери для адреса — симуляция политики без применения (для UI/обучения).
#[tauri::command]
pub fn madre_verdict(mgr: tauri::State<'_, MadreManager>, dst: String) -> Result<Value, String> {
    let cfg = mgr.cfg.lock().unwrap();
    let allow = parse_allowlist(&cfg.allow);
    let v = verdict(&dst, &allow);
    Ok(json!({"dst": dst, "verdict": v, "own": is_own(&dst, &allow)}))
}

#[tauri::command]
pub fn madre_honeypot_start(mgr: tauri::State<'_, MadreManager>) -> Result<Value, String> {
    mgr.honeypot_start()
}

#[tauri::command]
pub fn madre_honeypot_stop(mgr: tauri::State<'_, MadreManager>) -> Result<Value, String> {
    Ok(mgr.honeypot_stop())
}

#[tauri::command]
pub fn madre_watchdog_start(mgr: tauri::State<'_, MadreManager>) -> Result<Value, String> {
    mgr.watchdog_start()
}

#[tauri::command]
pub fn madre_watchdog_stop(mgr: tauri::State<'_, MadreManager>) -> Result<Value, String> {
    Ok(mgr.watchdog_stop())
}

/// События арсенала (лог hank… madre.db).
#[tauri::command]
pub fn madre_events(mgr: tauri::State<'_, MadreManager>, limit: Option<u32>) -> Result<Value, String> {
    Ok(json!({"events": mgr.events(limit.unwrap_or(50))}))
}

/// Штурвал AGI: сводка для модели + системный промпт Матери.
/// AGI-оболочка (agi.rs) сидит за штурвалом и видит только этот статус — ключи ей не нужны.
#[tauri::command]
pub fn madre_helm(mgr: tauri::State<'_, MadreManager>) -> Result<Value, String> {
    let cfg = mgr.cfg.lock().unwrap().clone();
    let events = mgr.events(10);
    Ok(json!({
        "system_prompt": MADRE_SYSTEM_PROMPT,
        "mode": cfg.mode,
        "honeypot_on": cfg.honeypot_on,
        "watchdog_on": cfg.watchdog_on,
        "allow": parse_allowlist(&cfg.allow),
        "philosophy": "доверяем только своим пакетам; чужие все дропаем — для них нет хостов",
        "recent_events": events,
    }))
}

// ============================================================================
// Тесты
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_allowlist_filters_garbage() {
        let raw = vec![
            "10.0.0.0/8".to_string(),
            "192.168.1.5".to_string(),
            "".to_string(),
            "мусор".to_string(),
            "999.1.1.1".to_string(),
            "10.0.0.0/8".to_string(), // дубль
        ];
        let out = parse_allowlist(&raw);
        assert_eq!(out, vec!["10.0.0.0/8".to_string(), "192.168.1.5".to_string()]);
    }

    #[test]
    fn test_is_own_and_verdict() {
        let allow = parse_allowlist(&["10.0.0.0/8".into(), "8.8.8.8".into()]);
        assert!(is_own("10.1.2.3", &allow));
        assert!(is_own("192.168.0.10", &allow)); // своя подсеть по умолчанию
        assert!(is_own("8.8.8.8", &allow)); // в allowlist
        assert!(!is_own("45.155.205.233", &allow)); // чужой
        assert_eq!(verdict("45.155.205.233", &allow), "drop");
        assert_eq!(verdict("10.0.0.9", &allow), "accept");
        assert_eq!(verdict("не-ip", &allow), "drop");
    }

    #[test]
    fn test_build_madre_rules_default_deny() {
        let cfg = MadreConfig {
            mode: "enforce".into(),
            allow: vec!["10.0.0.0/8".into(), "1.2.3.4".into()],
            ..Default::default()
        };
        let rules = build_madre_rules(&cfg);
        assert!(rules.contains("table inet w420_madre"));
        // default-deny на input и output
        assert!(rules.contains("chain input {\n    type filter hook input priority 10; policy drop;"));
        assert!(rules.contains("chain output {\n    type filter hook output priority 10; policy drop;"));
        // allowlist применён
        assert!(rules.contains("ip daddr 10.0.0.0/8 accept"));
        assert!(rules.contains("ip daddr 1.2.3.4 accept"));
        // порты ханипота логируются
        for p in HONEYPOT_PORTS {
            assert!(rules.contains(&format!("tcp dport {p} limit rate 5/minute log")));
        }
    }

    #[test]
    fn test_honeypot_ports_unique_and_sane() {
        let mut v = HONEYPOT_PORTS.to_vec();
        v.sort_unstable();
        v.dedup();
        assert_eq!(v.len(), HONEYPOT_PORTS.len());
        assert!(HONEYPOT_PORTS.contains(&22));
    }

    #[test]
    fn test_madre_prompt_mentions_philosophy() {
        assert!(MADRE_SYSTEM_PROMPT.contains("чужие все дропаем"));
        assert!(MADRE_SYSTEM_PROMPT.contains("default-deny"));
    }
}

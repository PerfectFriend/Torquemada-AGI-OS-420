//! Фаза 8: управление брандмауэром и сегментация сети (firewall.rs).
//!
//! Таблица `inet w420_fw` с цепочками input/output — все интерфейсы сразу.
//! Применение профилей — атомарно: delete table + один `nft -f` batch
//! (тот же паттерн, что в emergency.rs; см. skill nftables-firewall-automation).
//! После root_setup.sh nft работает от обычного пользователя (cap_net_admin),
//! иначе команда вернёт needs_root, а желаемый профиль сохранится в ~/.w420/firewall.json.
//!
//! Профили: office (открытый офис), guest (только DNS/HTTP(S) наружу, входящий drop),
//! dmz (входящие 22/80/443, остальное drop), isolated (полная изоляция, кроме lo).

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::State;

use crate::traffic::run_nft;

pub struct FirewallManager {
    pub state: Mutex<FwState>,
    pub file: PathBuf,
    pub log_db: PathBuf,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FwState {
    pub profile: String, // office | guest | dmz | isolated
}

impl Default for FwState {
    fn default() -> Self {
        Self { profile: "office".into() }
    }
}

fn home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"))
}

impl FirewallManager {
    pub fn new() -> Self {
        let dir = home().join(".w420");
        let file = dir.join("firewall.json");
        let state = fs::read_to_string(&file)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let mgr = Self {
            state: Mutex::new(state),
            file,
            log_db: dir.join("firewall.db"),
        };
        mgr.init_log_db();
        mgr
    }

    fn persist(&self, st: &FwState) {
        if let Some(p) = self.file.parent() {
            let _ = fs::create_dir_all(p);
        }
        let _ = fs::write(&self.file, serde_json::to_string_pretty(st).unwrap_or_default());
    }

    fn init_log_db(&self) {
        if let Ok(conn) = Connection::open(&self.log_db) {
            let _ = conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS fw_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    ip TEXT, rule TEXT, action TEXT, profile TEXT
                );",
            );
        }
    }

    pub fn log_event(&self, ip: Option<&str>, rule: &str, action: &str, profile: &str) {
        if let Ok(conn) = Connection::open(&self.log_db) {
            let _ = conn.execute(
                "INSERT INTO fw_events (ts, ip, rule, action, profile) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    chrono::Utc::now().to_rfc3339(),
                    ip.unwrap_or(""),
                    rule,
                    action,
                    profile
                ],
            );
        }
    }
}

/// Правила профиля (чистая функция — тестируется без ядра). None = снять таблицу.
pub fn build_profile_rules(profile: &str) -> Option<String> {
    let mut s = String::from("table inet w420_fw {\n");
    match profile {
        "office" => {
            s.push_str("  chain input {\n    type filter hook input priority 0; policy accept;\n    iif \"lo\" accept\n    ct state established,related accept\n  }\n");
            s.push_str("  chain output {\n    type filter hook output priority 0; policy accept;\n  }\n");
        }
        "guest" => {
            // Гостевая сеть: входящий drop (кроме established), исходящий — только DNS/HTTP(S)
            s.push_str("  chain input {\n    type filter hook input priority 0; policy drop;\n    iif \"lo\" accept\n    ct state established,related accept\n    ip protocol icmp accept\n  }\n");
            s.push_str("  chain output {\n    type filter hook output priority 0; policy drop;\n    oif \"lo\" accept\n    ct state established,related accept\n    udp dport 53 accept\n    tcp dport 53 accept\n    tcp dport { 80, 443 } accept\n  }\n");
        }
        "dmz" => {
            // DMZ: наружу 22/80/443, входящий drop остального
            s.push_str("  chain input {\n    type filter hook input priority 0; policy drop;\n    iif \"lo\" accept\n    ct state established,related accept\n    tcp dport { 22, 80, 443 } accept\n    ip protocol icmp accept\n  }\n");
            s.push_str("  chain output {\n    type filter hook output priority 0; policy accept;\n  }\n");
        }
        "isolated" => {
            // Полная изоляция узла
            s.push_str("  chain input {\n    type filter hook input priority 0; policy drop;\n    iif \"lo\" accept\n  }\n");
            s.push_str("  chain output {\n    type filter hook output priority 0; policy drop;\n    oif \"lo\" accept\n  }\n");
        }
        _ => return None,
    }
    s.push_str("}\n");
    Some(s)
}

/// Применить профиль в ядро: delete table (ошибку игнорируем) + один batch `nft -f`.
pub fn apply_profile(profile: &str) -> Result<String, String> {
    let Some(rules) = build_profile_rules(profile) else {
        return Err(format!("неизвестный профиль: {profile}"));
    };
    let _ = run_nft(&["delete", "table", "inet", "w420_fw"]); // pre-delete отдельно: batch падает на первой ошибке
    let tmp = std::env::temp_dir().join("w420_fw.nft");
    fs::write(&tmp, &rules).map_err(|e| format!("write: {e}"))?;
    run_nft(&["-f", tmp.to_str().unwrap_or("w420_fw.nft")])
}

#[derive(Serialize)]
pub struct FwApplyResult {
    pub saved: bool,
    pub applied: bool,
    pub needs_root: bool,
    pub detail: String,
    pub rules: String,
}

/// Применить профиль сегментации (сохраняется в firewall.json).
#[tauri::command]
pub fn fw_profile_apply(mgr: State<FirewallManager>, profile: String) -> FwApplyResult {
    let mut st = mgr.state.lock().unwrap().clone();
    st.profile = profile.clone();
    mgr.persist(&st);
    let rules = build_profile_rules(&profile).unwrap_or_default();
    match apply_profile(&profile) {
        Ok(detail) => {
            mgr.log_event(None, "profile", &format!("apply {profile}"), &profile);
            FwApplyResult { saved: true, applied: true, needs_root: false, detail, rules }
        }
        Err(e) => {
            let needs_root = e.contains("Operation not permitted") || e.contains("permission");
            FwApplyResult { saved: true, applied: false, needs_root, detail: e, rules }
        }
    }
}

/// Текущий профиль + наличие таблицы в ядре.
#[tauri::command]
pub fn fw_status(mgr: State<FirewallManager>) -> serde_json::Value {
    let st = mgr.state.lock().unwrap().clone();
    let table = run_nft(&["list", "table", "inet", "w420_fw"]).ok();
    serde_json::json!({
        "profile": st.profile,
        "table_present": table.is_some(),
        "rules_text": table.unwrap_or_default(),
    })
}

/// Список правил таблицы w420_fw (с handles для удаления).
#[tauri::command]
pub fn fw_rules_list() -> Result<Vec<serde_json::Value>, String> {
    let out = run_nft(&["list", "table", "inet", "w420_fw"])?;
    let mut rules = Vec::new();
    let mut chain = String::new();
    for line in out.lines() {
        let t = line.trim();
        if t.starts_with("chain ") {
            chain = t.trim_start_matches("chain ").split_whitespace().next().unwrap_or("").to_string();
        }
        if t.contains("# handle ") {
            let handle = t.rsplit("# handle ").next().unwrap_or("").trim().to_string();
            rules.push(serde_json::json!({"chain": chain, "handle": handle, "rule": t}));
        }
    }
    Ok(rules)
}

/// Добавить правило: action=drop|accept, proto=tcp|udp|any, port, src(optional).
#[tauri::command]
pub fn fw_rule_add(
    mgr: State<FirewallManager>,
    chain: String, // input | output
    action: String,
    proto: Option<String>,
    port: Option<u16>,
    src: Option<String>,
) -> Result<String, String> {
    let chain = if chain == "output" { "output" } else { "input" };
    let mut rule = String::new();
    if let Some(ip) = src.as_deref().filter(|s| !s.is_empty()) {
        rule.push_str(&format!("ip saddr {ip} "));
    }
    if let (Some(p), Some(port)) = (proto.as_deref(), port) {
        rule.push_str(&format!("{p} dport {port} "));
    }
    rule.push_str(action.as_str());
    let args = ["add", "rule", "inet", "w420_fw", chain];
    let rule_args: Vec<&str> = rule.split_whitespace().collect();
    let mut full: Vec<&str> = args.to_vec();
    full.extend(rule_args.iter().copied());
    let out = run_nft(&full)?;
    mgr.log_event(src.as_deref(), &rule, "add", &mgr.state.lock().unwrap().profile);
    Ok(out)
}

/// Удалить правило по handle.
#[tauri::command]
pub fn fw_rule_remove(mgr: State<FirewallManager>, chain: String, handle: String) -> Result<String, String> {
    let chain = if chain == "output" { "output" } else { "input" };
    let out = run_nft(&["delete", "rule", "inet", "w420_fw", chain, "handle", &handle])?;
    mgr.log_event(None, &format!("handle {handle}"), "remove", &mgr.state.lock().unwrap().profile);
    Ok(out)
}

/// Автоизоляция скомпрометированного хоста: drop в обе стороны + запись в лог.
#[tauri::command]
pub fn fw_isolate_host(mgr: State<FirewallManager>, ip: String) -> Result<String, String> {
    let r1 = run_nft(&["add", "rule", "inet", "w420_fw", "input", "ip", "saddr", &ip, "drop"]);
    let r2 = run_nft(&["add", "rule", "inet", "w420_fw", "output", "ip", "daddr", &ip, "drop"]);
    mgr.log_event(Some(&ip), "isolate both directions", "isolate", &mgr.state.lock().unwrap().profile);
    match (r1, r2) {
        (Ok(_), Ok(_)) => Ok(format!("хост {ip} изолирован (input+output drop)")),
        (a, b) => Err(format!("input: {:?}, output: {:?}", a.err(), b.err())),
    }
}

/// Журнал событий брандмауэра (блокировки/изоляции/профили).
#[tauri::command]
pub fn fw_logs(mgr: State<FirewallManager>, limit: Option<u32>) -> Result<Vec<serde_json::Value>, String> {
    let conn = Connection::open(&mgr.log_db).map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare("SELECT ts, ip, rule, action, profile FROM fw_events ORDER BY id DESC LIMIT ?1")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([limit.unwrap_or(100)], |r| {
            Ok(serde_json::json!({
                "ts": r.get::<_, String>(0)?,
                "ip": r.get::<_, String>(1)?,
                "rule": r.get::<_, String>(2)?,
                "action": r.get::<_, String>(3)?,
                "profile": r.get::<_, String>(4)?,
            }))
        })
        .map_err(|e| e.to_string())?;
    Ok(rows.flatten().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profiles_build() {
        for p in ["office", "guest", "dmz", "isolated"] {
            let r = build_profile_rules(p).unwrap();
            assert!(r.contains("table inet w420_fw"));
            assert!(r.contains("hook input"));
        }
        assert!(build_profile_rules("nope").is_none());
    }

    #[test]
    fn test_guest_is_lockdown() {
        let r = build_profile_rules("guest").unwrap();
        assert!(r.contains("hook input priority 0; policy drop;"));
        assert!(r.contains("tcp dport { 80, 443 } accept"));
    }

    #[test]
    fn test_isolated_drops_both() {
        let r = build_profile_rules("isolated").unwrap();
        assert!(r.contains("hook input priority 0; policy drop;"));
        assert!(r.contains("hook output priority 0; policy drop;"));
    }

    /// Живой тест ядра: применить профиль и снять. Работает после root_setup.sh (cap_net_admin).
    /// Без прав — мягко пропускаем.
    #[test]
    fn live_apply_revert_profile() {
        match apply_profile("guest") {
            Ok(_) => {
                let listed = run_nft(&["list", "table", "inet", "w420_fw"]).unwrap();
                assert!(listed.contains("policy drop"));
                let _ = run_nft(&["delete", "table", "inet", "w420_fw"]);
                println!("LIVE: guest профиль применён и снят, в ядре была таблица w420_fw");
            }
            Err(e) if e.contains("permitted") || e.contains("permission") => {
                println!("LIVE SKIP: нет прав на nft — применит root_setup.sh");
            }
            Err(e) => panic!("неожиданная ошибка nft: {e}"),
        }
    }
}

//! Аварийный режим W420: жёсткая политика фильтрации пакетов на ВСЕХ каналах сразу.
//!
//! Одна таблица `inet w420_em` с хуками input/output покрывает все интерфейсы
//! одновременно — применение идёт одним batch-файлом через `nft -f` (атомарно).
//! Уровни:
//!   monitor   — фильтры сняты (delete table);
//!   alert     — policy accept, но режем C2-порты и IP из чёрного списка IDS;
//!   emergency — input policy DROP (разрешены lo, established/related, ICMP),
//!               опционально egress_strict: output DROP кроме DNS/HTTP(S)/established.
//! Состояние хранится в ~/.w420/emergency.json и применяется при старте/по команде.
//! nft требует root — без passwordless sudo команда вернёт needs_root: true,
//! но желаемое состояние сохраняется и применится при наличии прав.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::State;

use crate::traffic::run_nft;

/// C2 / часто используемые ботнетами порты для уровня alert.
const C2_PORTS: &[u16] = &[1234, 4444, 5555, 6666, 7777, 9001, 31337, 12345, 27374];

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EmergencyState {
    pub enabled: bool,
    /// monitor | alert | emergency
    pub level: String,
    /// жёсткая фильтрация исходящего трафика (только DNS/HTTP(S))
    pub egress_strict: bool,
    /// авто-включение аварийного режима при критическом алерте IDS
    pub auto_on_alert: bool,
}

impl Default for EmergencyState {
    fn default() -> Self {
        Self {
            enabled: false,
            level: "monitor".into(),
            egress_strict: false,
            auto_on_alert: false,
        }
    }
}

pub struct EmergencyManager {
    pub state: Mutex<EmergencyState>,
    pub file: PathBuf,
}

impl EmergencyManager {
    pub fn new() -> Self {
        let file = dirs_home().join(".w420").join("emergency.json");
        let state = fs::read_to_string(&file)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self {
            state: Mutex::new(state),
            file,
        }
    }

    fn persist(&self, st: &EmergencyState) {
        if let Some(p) = self.file.parent() {
            let _ = fs::create_dir_all(p);
        }
        let _ = fs::write(&self.file, serde_json::to_string_pretty(st).unwrap_or_default());
    }
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

/// IP из чёрного списка IDS (traffic.db) для уровня alert.
fn blocked_ips() -> Vec<String> {
    let db = dirs_home().join(".w420").join("traffic.db");
    let Ok(conn) = Connection::open(&db) else {
        return Vec::new();
    };
    let Ok(mut stmt) = conn.prepare("SELECT ip FROM blocked_ips") else {
        return Vec::new();
    };
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .ok()
        .map(|it| it.flatten().collect())
        .unwrap_or_default();
    rows
}

/// Сборка batch-файла правил nft для уровня. Чистая функция — тестируется без root.
/// `None` = снять все фильтры (monitor).
pub fn build_rules(level: &str, egress_strict: bool) -> Option<String> {
    match level {
        "monitor" => None,
        "alert" => {
            let c2: Vec<String> = C2_PORTS.iter().map(|p| p.to_string()).collect();
            let blocked = blocked_ips();
            let mut s = String::from("table inet w420_em {\n");
            s.push_str("  chain input {\n    type filter hook input priority 0; policy accept;\n");
            s.push_str("    iif \"lo\" accept\n");
            s.push_str("    ct state established,related accept\n");
            s.push_str(&format!(
                "    tcp dport {{ {} }} drop\n",
                c2.join(", ")
            ));
            s.push_str(&format!(
                "    udp dport {{ {} }} drop\n",
                c2.join(", ")
            ));
            if !blocked.is_empty() {
                s.push_str(&format!("    ip saddr {{ {} }} drop\n", blocked.join(", ")));
            }
            s.push_str("  }\n}\n");
            Some(s)
        }
        "emergency" => {
            let mut s = String::from("table inet w420_em {\n");
            // Жёсткий входящий фильтр на всех интерфейсах сразу
            s.push_str("  chain input {\n    type filter hook input priority 0; policy drop;\n");
            s.push_str("    iif \"lo\" accept\n");
            s.push_str("    ct state established,related accept\n");
            s.push_str("    ip protocol icmp accept\n");
            s.push_str("    ip6 nexthdr ipv6-icmp accept\n");
            s.push_str("  }\n");
            // Исходящий: по умолчанию разрешён, при egress_strict — только DNS/HTTP(S)
            if egress_strict {
                s.push_str("  chain output {\n    type filter hook output priority 0; policy drop;\n");
                s.push_str("    oif \"lo\" accept\n");
                s.push_str("    ct state established,related accept\n");
                s.push_str("    udp dport 53 accept\n");
                s.push_str("    tcp dport 53 accept\n");
                s.push_str("    tcp dport { 80, 443 } accept\n");
                s.push_str("  }\n");
            } else {
                s.push_str("  chain output {\n    type filter hook output priority 0; policy accept;\n  }\n");
            }
            s.push_str("}\n");
            Some(s)
        }
        _ => None,
    }
}

/// Применить правила: сначала удалить старую таблицу (ошибку игнорируем),
/// затем одним `nft -f` создать новую — атомарно на всех каналах.
pub fn apply_rules(level: &str, egress_strict: bool) -> Result<String, String> {
    // monitor или неизвестный уровень при выключенном режиме = снять таблицу
    if level == "monitor" {
        let _ = run_nft(&["delete", "table", "inet", "w420_em"]); // если нет — ок
        return Ok("фильтры сняты (monitor)".into());
    }
    let Some(rules) = build_rules(level, egress_strict) else {
        return Err(format!("неизвестный уровень: {level}"));
    };
    let _ = run_nft(&["delete", "table", "inet", "w420_em"]); // чистый лист, ошибку игнорируем
    let tmp = std::env::temp_dir().join("w420_em.nft");
    fs::write(&tmp, &rules).map_err(|e| format!("write: {e}"))?;
    // nft -f применяет batch целиком: либо все правила, либо ничего
    run_nft(&["-f", tmp.to_str().unwrap_or("w420_em.nft")])
}

#[derive(Serialize)]
pub struct EmergencyStatus {
    pub enabled: bool,
    pub level: String,
    pub egress_strict: bool,
    pub auto_on_alert: bool,
    pub table_present: bool,
}

/// Текущее состояние аварийного режима + наличие таблицы в ядре.
#[tauri::command]
pub fn emergency_status(mgr: State<EmergencyManager>) -> EmergencyStatus {
    let st = mgr.state.lock().unwrap().clone();
    let table_present = run_nft(&["list", "table", "inet", "w420_em"]).is_ok();
    EmergencyStatus {
        enabled: st.enabled,
        level: st.level,
        egress_strict: st.egress_strict,
        auto_on_alert: st.auto_on_alert,
        table_present,
    }
}

/// Предпросмотр правил nft для уровня (для UI и тестов, root не нужен).
#[tauri::command]
pub fn emergency_rules_preview(level: String, egress_strict: bool) -> String {
    match build_rules(&level, egress_strict) {
        Some(r) => r,
        None => "# monitor: таблица w420_em будет удалена, фильтры сняты\n".into(),
    }
}

#[derive(Serialize)]
pub struct EmergencyApplyResult {
    pub saved: bool,
    pub applied: bool,
    pub needs_root: bool,
    pub detail: String,
    pub rules: String,
}

/// Включить/настроить аварийный режим. Состояние сохраняется всегда,
/// применение в ядро — если есть права (иначе needs_root).
#[tauri::command]
pub fn emergency_set(
    mgr: State<EmergencyManager>,
    enabled: bool,
    level: Option<String>,
    egress_strict: Option<bool>,
    auto_on_alert: Option<bool>,
) -> EmergencyApplyResult {
    let mut st = mgr.state.lock().unwrap().clone();
    if let Some(l) = level {
        st.level = l;
    }
    if let Some(e) = egress_strict {
        st.egress_strict = e;
    }
    if let Some(a) = auto_on_alert {
        st.auto_on_alert = a;
    }
    st.enabled = enabled && st.level != "monitor";
    mgr.persist(&st);
    drop(st);

    let cur = mgr.state.lock().unwrap().clone();
    let (lvl, eg) = if cur.enabled {
        (cur.level.clone(), cur.egress_strict)
    } else {
        ("monitor".to_string(), false)
    };
    let rules = emergency_rules_preview(lvl.clone(), eg);
    match apply_rules(&lvl, eg) {
        Ok(detail) => EmergencyApplyResult {
            saved: true,
            applied: true,
            needs_root: false,
            detail,
            rules,
        },
        Err(e) => {
            let needs_root = e.contains("Operation not permitted") || e.contains("permission");
            EmergencyApplyResult {
                saved: true,
                applied: false,
                needs_root,
                detail: e,
                rules,
            }
        }
    }
}

/// Переприменить сохранённое состояние (например, после старта приложения).
#[tauri::command]
pub fn emergency_apply_saved(mgr: State<EmergencyManager>) -> EmergencyApplyResult {
    let st = mgr.state.lock().unwrap().clone();
    emergency_set_inner(&mgr, st.enabled, Some(st.level), Some(st.egress_strict), Some(st.auto_on_alert))
}

pub(crate) fn emergency_set_inner(
    mgr: &EmergencyManager,
    enabled: bool,
    level: Option<String>,
    egress_strict: Option<bool>,
    auto_on_alert: Option<bool>,
) -> EmergencyApplyResult {
    // та же логика, что в emergency_set, но без State-обёртки (для внутренних вызовов)
    let mut st = mgr.state.lock().unwrap().clone();
    if let Some(l) = level {
        st.level = l;
    }
    if let Some(e) = egress_strict {
        st.egress_strict = e;
    }
    if let Some(a) = auto_on_alert {
        st.auto_on_alert = a;
    }
    st.enabled = enabled && st.level != "monitor";
    mgr.persist(&st);
    let (lvl, eg) = if st.enabled {
        (st.level.clone(), st.egress_strict)
    } else {
        ("monitor".to_string(), false)
    };
    let rules = build_rules(&lvl, eg).unwrap_or_else(|| "# monitor\n".into());
    match apply_rules(&lvl, eg) {
        Ok(detail) => EmergencyApplyResult {
            saved: true,
            applied: true,
            needs_root: false,
            detail,
            rules,
        },
        Err(e) => EmergencyApplyResult {
            saved: true,
            applied: false,
            needs_root: e.contains("Operation not permitted") || e.contains("permission"),
            detail: e,
            rules,
        },
    }
}

/// Авто-включение аварийного режима при критическом алерте (вызывается из IDS).
pub fn auto_emergency_on_critical(mgr: &EmergencyManager) -> Option<String> {
    let st = mgr.state.lock().unwrap().clone();
    if st.auto_on_alert && st.enabled == false && st.level == "emergency" {
        let r = emergency_set_inner(mgr, true, None, None, None);
        return Some(r.detail);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_clears_table() {
        assert!(build_rules("monitor", false).is_none());
    }

    #[test]
    fn test_alert_blocks_c2_ports() {
        let r = build_rules("alert", false).unwrap();
        assert!(r.contains("tcp dport { 1234, 4444, 5555, 6666, 7777, 9001, 31337, 12345, 27374 } drop"));
        assert!(r.contains("policy accept"));
        assert!(r.contains("inet w420_em"));
    }

    #[test]
    fn test_emergency_drops_input_all_interfaces() {
        let r = build_rules("emergency", false).unwrap();
        assert!(r.contains("hook input priority 0; policy drop;"));
        assert!(r.contains("ct state established,related accept"));
        assert!(r.contains("iif \"lo\" accept"));
        // без egress_strict исходящий открыт
        assert!(r.contains("hook output priority 0; policy accept;"));
    }

    #[test]
    fn test_emergency_egress_strict_allows_only_dns_https() {
        let r = build_rules("emergency", true).unwrap();
        assert!(r.contains("hook output priority 0; policy drop;"));
        assert!(r.contains("udp dport 53 accept"));
        assert!(r.contains("tcp dport { 80, 443 } accept"));
    }
}

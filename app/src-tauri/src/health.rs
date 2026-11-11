//! health.rs — Этап 38 (финал паритета DameWare): dashboard здоровья хоста.
//!
//! `hosts_health(host_id)` собирает метрики удалённого хоста через SSH
//! (load, память, диск, упавшие службы) + локальные события SIEM/EDR по IP хоста
//! и считает интегральный score 0..100 (чистая функция `health_score` — тестируется без сети).
//! `hosts_health_all()` — то же для всех хостов инвентаря.

use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

use crate::hosts::HostsManager;

// ============================================================================
// Чистая логика: парсинг метрик и score
// ============================================================================

/// Сырые метрики хоста (собираются по SSH или локально).
#[derive(Default, Debug, Clone, Serialize)]
pub struct HealthMetrics {
    pub online: bool,
    pub load1: f64,          // load average 1 мин
    pub mem_used_pct: f64,   // 0..100
    pub disk_root_pct: f64,  // 0..100
    pub failed_services: u32,
    pub siem_events_1h: u32, // локальные события SIEM за час по этому хосту
    pub edr_alerts_open: u32,
}

/// Парсинг `uptime`-вывода: "load average: 0.52, 0.58, 0.59"
pub fn parse_load1(uptime_out: &str) -> Option<f64> {
    let idx = uptime_out.to_lowercase().find("load average")?;
    let rest = &uptime_out[idx..];
    let num = rest
        .split([',', ':'])
        .nth(1)
        .or_else(|| rest.split_whitespace().nth(3))?;
    num.trim().parse::<f64>().ok()
}

/// Парсинг `free -m`: used/total в процентах.
pub fn parse_mem_pct(free_out: &str) -> Option<f64> {
    for line in free_out.lines() {
        let l = line.to_lowercase();
        if l.starts_with("mem:") {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() >= 3 {
                let total: f64 = parts[1].parse().ok()?;
                let used: f64 = parts[2].parse().ok()?;
                if total > 0.0 {
                    return Some(used / total * 100.0);
                }
            }
        }
    }
    None
}

/// Парсинг `df -P /`: процент занятости корня (колонка Use%).
pub fn parse_disk_root_pct(df_out: &str) -> Option<f64> {
    for line in df_out.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 && parts[parts.len() - 1] == "/" {
            return parts[parts.len() - 2].trim_end_matches('%').parse::<f64>().ok();
        }
    }
    // df -P может выдать "/" не последним — ищем по полю Filesystem
    for line in df_out.lines().skip(1) {
        if line.trim_end().ends_with(" /") || line.contains(" / ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            for p in &parts {
                if p.ends_with('%') {
                    return p.trim_end_matches('%').parse::<f64>().ok();
                }
            }
        }
    }
    None
}

/// Парсинг `systemctl --failed --no-legend`: число строк = число упавших юнитов.
pub fn parse_failed_services(systemctl_out: &str) -> u32 {
    systemctl_out
        .lines()
        .filter(|l| !l.trim().is_empty() && l.contains("failed"))
        .count() as u32
}

/// Интегральный score здоровья 0..100 + текстовый грейд.
///.online=false → 0. Штрафы: load, mem, disk, failed services, события SIEM, открытые алерты EDR.
pub fn health_score(m: &HealthMetrics) -> (u8, &'static str) {
    if !m.online {
        return (0, "OFFLINE");
    }
    let mut score = 100.0_f64;
    // load: >n_cores-ish эвристика — штрафуем пропорционально, 4.0 и выше = 0 баллов за load
    score -= (m.load1 * 6.0).min(24.0);
    score -= (m.mem_used_pct - 70.0).max(0.0) * 0.8; // после 70% — штраф
    score -= (m.disk_root_pct - 80.0).max(0.0) * 1.2; // после 80% — штраф
    score -= (m.failed_services as f64) * 5.0;
    score -= (m.siem_events_1h as f64) * 1.0;
    score -= (m.edr_alerts_open as f64) * 8.0;
    let s = score.round().clamp(0.0, 100.0) as u8;
    let grade = match s {
        90..=100 => "HEALTHY",
        70..=89 => "OK",
        50..=69 => "DEGRADED",
        1..=49 => "CRITICAL",
        _ => "OFFLINE",
    };
    (s, grade)
}

/// Сбор метрик удалённого хоста по SSH (best-effort: каждая метрика независима).
pub fn collect_remote_metrics(hosts: &HostsManager, host_id: &str, ip: &str) -> HealthMetrics {
    let mut m = HealthMetrics::default();
    let probe = |cmd: &str| -> Option<String> {
        hosts
            .exec_command(host_id, cmd)
            .ok()
            .filter(|r| r.success)
            .map(|r| r.stdout)
    };
    if let Some(out) = probe("uptime") {
        m.online = true;
        m.load1 = parse_load1(&out).unwrap_or(0.0);
    } else {
        return m; // оффлайн — дальше не опрашиваем
    }
    if let Some(out) = probe("free -m") {
        m.mem_used_pct = parse_mem_pct(&out).unwrap_or(0.0);
    }
    if let Some(out) = probe("df -P /") {
        m.disk_root_pct = parse_disk_root_pct(&out).unwrap_or(0.0);
    }
    if let Some(out) = probe("systemctl --failed --no-legend --type=service 2>/dev/null || true") {
        m.failed_services = parse_failed_services(&out);
    }
    // Локальные события SIEM/EDR по IP хоста за последний час
    m.siem_events_1h = count_siem_events_for_ip(ip);
    m.edr_alerts_open = count_edr_open_for_ip(ip);
    m
}

fn count_siem_events_for_ip(ip: &str) -> u32 {
    let path = std::env::var("HOME").map(std::path::PathBuf::from).unwrap_or_else(|_| "/tmp".into());
    let db = path.join(".w420").join("siem.db");
    let Ok(conn) = rusqlite::Connection::open(db) else { return 0 };
    let cutoff = chrono::Utc::now() - chrono::Duration::hours(1);
    let Ok(mut stmt) = conn.prepare(
        "SELECT COUNT(*) FROM events WHERE ts >= ?1 AND (src_ip = ?2 OR message LIKE ?3)",
    ) else { return 0 };
    stmt.query_row(
        rusqlite::params![cutoff.to_rfc3339(), ip, format!("%{ip}%")],
        |r| r.get::<_, i64>(0).map(|v| v.max(0) as u32),
    )
    .unwrap_or(0)
}

fn count_edr_open_for_ip(ip: &str) -> u32 {
    let path = std::env::var("HOME").map(std::path::PathBuf::from).unwrap_or_else(|_| "/tmp".into());
    let db = path.join(".w420").join("edr.db");
    let Ok(conn) = rusqlite::Connection::open(db) else { return 0 };
    // эвристика: события EDR с этим IP в деталях и без закрытия
    let Ok(mut stmt) = conn.prepare(
        "SELECT COUNT(*) FROM events WHERE detail LIKE ?1",
    ) else { return 0 };
    stmt.query_row(rusqlite::params![format!("%{ip}%")], |r| {
        r.get::<_, i64>(0).map(|v| v.max(0) as u32)
    })
    .unwrap_or(0)
}

// ============================================================================
// Tauri-команды
// ============================================================================

#[derive(Serialize)]
pub struct HealthReport {
    pub host_id: String,
    pub ip: String,
    pub metrics: HealthMetrics,
    pub score: u8,
    pub grade: String,
    /// Что видит Madre: свой/чужой хост по allowlist Матери
    pub madre_verdict: String,
}

fn report_for(hosts: &HostsManager, host_id: &str) -> Result<HealthReport, String> {
    let info = hosts.get_host(host_id)?;
    let ip = info.ip.clone();
    let m = collect_remote_metrics(hosts, host_id, &ip);
    let (score, grade) = health_score(&m);
    let allow: Vec<String> = crate::madre::parse_allowlist(
        &hosts_madre_allow(),
    );
    let verdict = crate::madre::verdict(&ip, &allow).to_string();
    Ok(HealthReport {
        host_id: host_id.to_string(),
        ip,
        metrics: m,
        score,
        grade: grade.to_string(),
        madre_verdict: verdict,
    })
}

fn hosts_madre_allow() -> Vec<String> {
    let path = std::env::var("HOME").map(std::path::PathBuf::from).unwrap_or_else(|_| "/tmp".into());
    let file = path.join(".w420").join("madre.json");
    std::fs::read_to_string(file)
        .ok()
        .and_then(|s| serde_json::from_str::<crate::madre::MadreConfig>(&s).ok())
        .map(|c| c.allow)
        .unwrap_or_default()
}

/// Сводка здоровья одного хоста ( для карточки в UI и аудита паритета ).
#[tauri::command]
pub fn hosts_health(
    hosts: tauri::State<'_, HostsManager>,
    host_id: String,
) -> Result<HealthReport, String> {
    report_for(&hosts, &host_id)
}

/// Сводка здоровья всех хостов инвентаря — сводная таблица для аудита паритета.
#[tauri::command]
pub fn hosts_health_all(
    hosts: tauri::State<'_, HostsManager>,
) -> Result<Value, String> {
    let list = hosts.list_hosts()?;
    let mut reports = Vec::new();
    let mut by_grade: BTreeMap<String, u32> = BTreeMap::new();
    for h in &list {
        let r = report_for(&hosts, &h.id).unwrap_or_else(|e| HealthReport {
            host_id: h.id.clone(),
            ip: h.ip.clone(),
            metrics: HealthMetrics::default(),
            score: 0,
            grade: format!("ERROR: {e}"),
            madre_verdict: "drop".into(),
        });
        *by_grade.entry(r.grade.clone()).or_insert(0) += 1;
        reports.push(r);
    }
    Ok(json!({
        "total": reports.len(),
        "by_grade": by_grade,
        "reports": reports,
    }))
}

// ============================================================================
// Тесты
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_load1() {
        assert_eq!(parse_load1(" 12:01:02 up 3 days, load average: 0.52, 0.58, 0.59"), Some(0.52));
        assert_eq!(parse_load1("load average: 2.00, 1.00, 0.50"), Some(2.0));
        assert_eq!(parse_load1("no load here"), None);
    }

    #[test]
    fn test_parse_mem_pct() {
        let free = "              total        used        free      shared  buff/cache   available\nMem:           16000        9600        4000         200        2400       6000\nSwap:          2048           0        2048\n";
        assert!((parse_mem_pct(free).unwrap() - 60.0).abs() < 0.01);
        assert_eq!(parse_mem_pct("ничего"), None);
    }

    #[test]
    fn test_parse_disk_root_pct() {
        let df = "Filesystem     1024-blocks    Used Available Capacity Mounted on\n/dev/sda1        51475068 40000000   8000000      84% /\n";
        assert_eq!(parse_disk_root_pct(df), Some(84.0));
        assert_eq!(parse_disk_root_pct("нет"), None);
    }

    #[test]
    fn test_parse_failed_services() {
        let out = "● foo.service loaded failed failed Foo\n● bar.service loaded failed failed Bar\n";
        assert_eq!(parse_failed_services(out), 2);
        assert_eq!(parse_failed_services(""), 0);
    }

    #[test]
    fn test_health_score_offline_and_healthy() {
        let off = HealthMetrics { online: false, ..Default::default() };
        assert_eq!(health_score(&off), (0, "OFFLINE"));
        let ok = HealthMetrics { online: true, load1: 0.3, mem_used_pct: 40.0, disk_root_pct: 50.0, failed_services: 0, siem_events_1h: 0, edr_alerts_open: 0 };
        let (s, g) = health_score(&ok);
        assert!(s >= 95 && g == "HEALTHY");
    }

    #[test]
    fn test_health_score_degraded_and_critical() {
        let bad = HealthMetrics { online: true, load1: 3.0, mem_used_pct: 95.0, disk_root_pct: 97.0, failed_services: 3, siem_events_1h: 10, edr_alerts_open: 2 };
        let (s, g) = health_score(&bad);
        assert!(s < 50, "score={s}");
        assert!(g == "CRITICAL" || g == "DEGRADED");
        // чем хуже метрики, тем ниже score (монотонность)
        let worse = HealthMetrics { edr_alerts_open: 5, ..bad.clone() };
        assert!(health_score(&worse).0 <= s);
    }
}

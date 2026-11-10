//! Модуль сетевого сканирования (Фаза 6 плана эволюции).
//!
//! Чисто-Rust сканер сети на базе tokio (без внешних бинарников):
//!   - Парсинг CIDR (IPv4) и перечисление IP-адресов подсети
//!   - Асинхронное TCP connect-сканирование портов (с семафором-лимитом)
//!   - Banner grabbing — чтение первых байтов с открытых портов для определения сервиса
//!   - Сопоставление с известными портами (карта порт→сервис)
//!   - Сохранение результатов в SQLite (~/.w420/net_scan.db)
//!   - Сравнение с инвентарём хостов (hosts.db) — алерт на «новое устройство в сети»
//!
//! Все команды экспонируются через Tauri invoke. Комментарии на русском.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

// ============================================================================
// Типы данных
// ============================================================================

/// Обнаруженный хост в сети.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedHost {
    pub ip: String,
    pub hostname: Option<String>,
    pub open_ports: Vec<ScannedPort>,
    pub is_known: bool,          // есть ли в инвентаре hosts.db
    /// Предполагаемая ОС по TTL ping-ответа (64=Linux, 128=Windows, 255=роутер/сетевое)
    #[serde(default)]
    pub os_guess: String,
    pub scanned_at: String,
}

/// Открытый порт с определённым сервисом.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedPort {
    pub port: u16,
    pub service: String,         // определённый сервис (ssh, http, ...)
    pub banner: Option<String>,  // banner grabbing
}

/// Результат сканирования подсети.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub cidr: String,
    pub started_at: String,
    pub finished_at: String,
    pub hosts_up: u32,
    pub hosts_total: u32,
    pub new_hosts: Vec<String>,  // IP новых устройств (не из hosts.db)
    pub hosts: Vec<ScannedHost>,
}

/// Запись в БД результатов сканирования.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub scan_id: String,
    pub ip: String,
    pub ports_json: String,
    pub is_known: bool,
    pub scanned_at: String,
}

/// Результат сравнения двух последних сканов (diff).
#[derive(Debug, Clone, Serialize)]
pub struct ScanDiff {
    pub prev_scan_id: String,
    pub cur_scan_id: String,
    pub prev_at: String,
    pub cur_at: String,
    /// Хосты, появившиеся в сети с прошлого скана (пишутся и в siem.db)
    pub new_hosts: Vec<String>,
    /// Хосты, исчезнувшие из сети
    pub removed_hosts: Vec<String>,
}

// ============================================================================
// CIDR-парсинг (IPv4)
// ============================================================================

/// Разбирает строку вида "192.168.1.0/24" и возвращает список IP-адресов подсети.
/// Поддерживает только IPv4. Для /32 — один адрес.
pub fn parse_cidr(cidr: &str) -> Result<Vec<Ipv4Addr>, String> {
    let (ip_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| format!("CIDR должен быть вида a.b.c.d/prefix, получено: {cidr}"))?;

    let base: Ipv4Addr = ip_str
        .parse()
        .map_err(|e| format!("неверный IP {ip_str}: {e}"))?;

    let prefix: u32 = prefix_str
        .parse()
        .map_err(|e| format!("неверный prefix /{prefix_str}: {e}"))?;
    if prefix > 32 {
        return Err(format!("prefix должен быть 0..=32, получен {prefix}"));
    }

    let base_u32 = u32::from(base);
    let host_bits = 32 - prefix;
    let count = if host_bits >= 32 { 1u64 } else { 1u64 << host_bits };
    // Ограничиваем размер, чтобы не сканировать /0 целый интернет
    if count > 65536 {
        return Err(format!(
            "подсеть /{prefix} слишком большая ({count} адресов), максимум /16"
        ));
    }

    let mask = if host_bits >= 32 { 0u32 } else { u32::MAX << host_bits };
    let network = base_u32 & mask;

    let mut ips = Vec::new();
    for i in 0..count {
        ips.push(Ipv4Addr::from(network + (i as u32)));
    }
    Ok(ips)
}

// ============================================================================
// Карта портов → сервисы
// ============================================================================

/// Возвращает название сервиса по номеру порта (наиболее распространённые).
pub fn service_by_port(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        587 => "smtp-submission",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        9200 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        _ => "unknown",
    }
}

// ============================================================================
// TCP-сканирование
// ============================================================================

/// Асинхронно проверяет, открыт ли TCP-порт на хосте.
async fn is_port_open(ip: Ipv4Addr, port: u16, timeout: Duration) -> bool {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

/// Читает banner с открытого порта (до 256 байт, таймаут 3 сек).
async fn grab_banner(ip: Ipv4Addr, port: u16) -> Option<String> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let mut stream = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // Для некоторых протоколов отправляем триггер (HTTP, FTP и т.д. сами ответят)
    if port == 80 || port == 8080 || port == 8443 {
        use tokio::io::AsyncWriteExt;
        let _ = stream
            .write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            .await;
    }

    let mut buf = [0u8; 256];
    match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let banner = String::from_utf8_lossy(&buf[..n]).to_string();
            Some(banner.chars().take(200).collect::<String>().trim().to_string())
        }
        _ => None,
    }
}

/// Предполагаемая ОС хоста по TTL ответа на ping (64=Linux, 128=Windows, 255=роутер/сетевое устр-во).
fn guess_os(ip: &str) -> String {
    let out = std::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", ip])
        .output();
    if let Ok(o) = out {
        let s = String::from_utf8_lossy(&o.stdout);
        if let Some(pos) = s.find("ttl=") {
            let ttl: String = s[pos + 4..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(t) = ttl.parse::<u32>() {
                return match t {
                    0..=32 => "BSD/old Unix (TTL~32)".to_string(),
                    33..=127 => "Linux/Unix (TTL~64)".to_string(),
                    128..=200 => "Windows (TTL~128)".to_string(),
                    _ => "Сетевое устройство (TTL~255)".to_string(),
                };
            }
        }
    }
    "неизвестно".to_string()
}

/// Reverse DNS через getent (быстрый системный резолвер).
fn lookup_hostname(ip: &str) -> Option<String> {
    let out = std::process::Command::new("getent")
        .args(["hosts", ip])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.split_whitespace().nth(1).map(|s| s.to_string())
}

/// Сканирует один хост на список портов. Возвращает открытые порты с баннерами.
async fn scan_host(ip: Ipv4Addr, ports: &[u16], semaphore: &Semaphore, timeout: Duration) -> Vec<ScannedPort> {
    let mut open = Vec::new();
    for &port in ports {
        let _permit = semaphore.acquire().await.unwrap();
        if is_port_open(ip, port, timeout).await {
            let banner = grab_banner(ip, port).await;
            open.push(ScannedPort {
                port,
                service: service_by_port(port).to_string(),
                banner,
            });
        }
    }
    open
}

/// Сканирует всю подсеть. `ports` — список портов для проверки каждого хоста.
/// `concurrency` — максимум одновременных соединений.
pub async fn scan_subnet(
    cidr: &str,
    ports: Vec<u16>,
    concurrency: usize,
    timeout_ms: u64,
) -> Result<Vec<(Ipv4Addr, Vec<ScannedPort>)>, String> {
    let ips = parse_cidr(cidr)?;
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let timeout = Duration::from_millis(timeout_ms.max(100));

    let mut tasks = Vec::new();
    for ip in ips {
        let ports = ports.clone();
        let sem = Arc::clone(&semaphore);
        tasks.push(tokio::spawn(async move {
            let open = scan_host(ip, &ports, &sem, timeout).await;
            (ip, open)
        }));
    }

    let mut results = Vec::new();
    for t in tasks {
        if let Ok((ip, open)) = t.await {
            if !open.is_empty() {
                results.push((ip, open));
            }
        }
    }
    Ok(results)
}

/// Стандартный набор портов для сканирования (топ-20 + специфичные для инфраструктуры).
pub fn default_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432,
        5900, 6379, 8080, 8443, 9200, 11211, 27017,
    ]
}

// ============================================================================
// Менеджер сканирования (БД + diff с инвентарём)
// ============================================================================

pub struct NetScanManager {
    db_path: PathBuf,
    last_scan: Mutex<Option<ScanResult>>,
}

impl NetScanManager {
    pub fn new() -> Result<Self, String> {
        let home = std::env::var("HOME").map_err(|e| format!("HOME не задан: {e}"))?;
        let w420_dir = Path::new(&home).join(".w420");
        std::fs::create_dir_all(&w420_dir).map_err(|e| format!("не удалось создать {w420_dir:?}: {e}"))?;
        let db_path = w420_dir.join("net_scan.db");
        let mgr = Self {
            db_path,
            last_scan: Mutex::new(None),
        };
        mgr.init_db()?;
        Ok(mgr)
    }

    fn init_db(&self) -> Result<(), String> {
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| format!("не удалось открыть БД net_scan: {e}"))?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS scan_results (
                scan_id TEXT NOT NULL,
                ip TEXT NOT NULL,
                ports_json TEXT NOT NULL,
                is_known INTEGER NOT NULL DEFAULT 0,
                scanned_at TEXT NOT NULL,
                PRIMARY KEY (scan_id, ip)
            );
            CREATE INDEX IF NOT EXISTS idx_scan_ip ON scan_results(ip);
            CREATE INDEX IF NOT EXISTS idx_scan_time ON scan_results(scanned_at);
        "#,
        )
        .map_err(|e| format!("не удалось создать схему net_scan: {e}"))?;
        Ok(())
    }

    /// Возвращает множество IP из инвентаря хостов (hosts.db).
    fn known_ips(&self) -> Result<std::collections::HashSet<String>, String> {
        let home = std::env::var("HOME").map_err(|e| e.to_string())?;
        let hosts_db = Path::new(&home).join(".w420").join("hosts.db");
        let mut set = std::collections::HashSet::new();
        if hosts_db.exists() {
            let conn = rusqlite::Connection::open(&hosts_db)
                .map_err(|e| format!("не удалось открыть hosts.db: {e}"))?;
            let mut stmt = conn
                .prepare("SELECT ip FROM hosts")
                .map_err(|e| format!("ошибка запроса hosts: {e}"))?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| format!("ошибка чтения hosts: {e}"))?;
            for r in rows {
                if let Ok(ip) = r {
                    set.insert(ip);
                }
            }
        }
        Ok(set)
    }

    /// Сохраняет результаты сканирования в БД.
    fn save_scan(&self, result: &ScanResult) -> Result<(), String> {
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| format!("не удалось открыть БД net_scan: {e}"))?;
        for host in &result.hosts {
            let ports_json = serde_json::to_string(&host.open_ports)
                .map_err(|e| format!("ошибка сериализации портов: {e}"))?;
            conn.execute(
                "INSERT OR REPLACE INTO scan_results (scan_id, ip, ports_json, is_known, scanned_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    result.scan_id,
                    host.ip,
                    ports_json,
                    host.is_known as i32,
                    host.scanned_at,
                ],
            )
            .map_err(|e| format!("не удалось сохранить результат: {e}"))?;
        }
        Ok(())
    }

    /// Выполняет сканирование, сохраняет в БД, возвращает результат.
    pub async fn run_scan(
        &self,
        cidr: &str,
        ports: Option<Vec<u16>>,
        concurrency: Option<usize>,
        timeout_ms: Option<u64>,
    ) -> Result<ScanResult, String> {
        let ports = ports.unwrap_or_else(default_ports);
        let concurrency = concurrency.unwrap_or(500);
        let timeout_ms = timeout_ms.unwrap_or(1500);

        let scan_id = uuid::Uuid::new_v4().to_string();
        let started_at = chrono::Utc::now().to_rfc3339();

        let raw = scan_subnet(cidr, ports, concurrency, timeout_ms).await?;
        let known = self.known_ips()?;
        let now = chrono::Utc::now().to_rfc3339();

        let mut hosts = Vec::new();
        let mut new_hosts = Vec::new();
        let total = parse_cidr(cidr)?.len() as u32;

        for (ip, open_ports) in raw {
            let ip_str = ip.to_string();
            let is_known = known.contains(&ip_str);
            if !is_known {
                new_hosts.push(ip_str.clone());
            }
            hosts.push(ScannedHost {
                ip: ip_str.clone(),
                hostname: lookup_hostname(&ip_str),
                open_ports,
                is_known,
                os_guess: guess_os(&ip_str),
                scanned_at: now.clone(),
            });
        }

        let result = ScanResult {
            scan_id: scan_id.clone(),
            cidr: cidr.to_string(),
            started_at,
            finished_at: chrono::Utc::now().to_rfc3339(),
            hosts_up: hosts.len() as u32,
            hosts_total: total,
            new_hosts,
            hosts,
        };

        self.save_scan(&result)?;
        {
            let mut last = self.last_scan.lock().map_err(|_| "мьютекс отравлен")?;
            *last = Some(result.clone());
        }
        Ok(result)
    }

    /// Возвращает последний результат сканирования.
    pub fn last_scan(&self) -> Option<ScanResult> {
        self.last_scan.lock().ok().and_then(|g| g.clone())
    }

    /// Возвращает историю сканов из БД (последние N сканов, агрегировано по хостам).
    pub fn history(&self, limit: u32) -> Result<Vec<ScanRecord>, String> {
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| format!("не удалось открыть БД net_scan: {e}"))?;
        let mut stmt = conn
            .prepare("SELECT scan_id, ip, ports_json, is_known, scanned_at FROM scan_results ORDER BY scanned_at DESC LIMIT ?1")
            .map_err(|e| format!("ошибка подготовки запроса: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![limit as i64], |row| {
                Ok(ScanRecord {
                    scan_id: row.get(0)?,
                    ip: row.get(1)?,
                    ports_json: row.get(2)?,
                    is_known: row.get::<_, i32>(3)? != 0,
                    scanned_at: row.get(4)?,
                })
            })
            .map_err(|e| format!("ошибка запроса: {e}"))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| format!("ошибка чтения: {e}"))?);
        }
        Ok(out)
    }

    /// Diff двух последних сканов из БД: какие хосты появились, какие исчезли.
    /// Новые хосты дополнительно пишутся в siem.db как события source='net_scan' (их подхватит AI SOC playbook new_host_alert).
    pub fn diff_last_two(&self) -> Result<Option<ScanDiff>, String> {
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| format!("не удалось открыть БД net_scan: {e}"))?;
        // два последних scan_id по времени
        let mut st = conn
            .prepare("SELECT scan_id, MAX(scanned_at) FROM scan_results GROUP BY scan_id ORDER BY MAX(scanned_at) DESC LIMIT 2")
            .map_err(|e| e.to_string())?;
        let scans: Vec<(String, String)> = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| e.to_string())?
            .flatten()
            .collect();
        if scans.len() < 2 {
            return Ok(None); // нужно минимум два скана
        }
        let (cur_id, cur_at) = scans[0].clone();
        let (prev_id, prev_at) = scans[1].clone();
        let ips_of = |scan_id: &str| -> Result<Vec<String>, String> {
            let mut s = conn.prepare("SELECT ip FROM scan_results WHERE scan_id=?1").map_err(|e| e.to_string())?;
            let rows = s.query_map([scan_id], |r| r.get::<_, String>(0)).map_err(|e| e.to_string())?;
            let mut out = Vec::new();
            for r in rows.flatten() { out.push(r); }
            Ok(out)
        };
        let cur = ips_of(&cur_id)?;
        let prev = ips_of(&prev_id)?;
        let (new_hosts, removed_hosts) = diff_ip_sets(&prev, &cur);
        let diff = ScanDiff {
            prev_scan_id: prev_id,
            cur_scan_id: cur_id.clone(),
            prev_at,
            cur_at,
            new_hosts: new_hosts.clone(),
            removed_hosts,
        };
        // алерты в SIEM про новые хосты
        if !new_hosts.is_empty() {
            if let Ok(home) = std::env::var("HOME") {
                let siem_db = Path::new(&home).join(".w420").join("siem.db");
                if let Ok(sc) = rusqlite::Connection::open(&siem_db) {
                    let _ = sc.execute_batch(
                        "CREATE TABLE IF NOT EXISTS events (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ts TEXT NOT NULL, source TEXT NOT NULL, category TEXT NOT NULL,
                            severity TEXT NOT NULL, src_ip TEXT NOT NULL DEFAULT '', message TEXT NOT NULL, raw TEXT NOT NULL DEFAULT ''
                        );",
                    );
                    let now = chrono::Utc::now().to_rfc3339();
                    for ip in &new_hosts {
                        let _ = sc.execute(
                            "INSERT INTO events (ts, source, category, severity, src_ip, message) VALUES (?1,'net_scan','new_host','medium',?2,?3)",
                            rusqlite::params![now, ip, format!("Новый хост в сети: {ip} (скан {cur_id})")],
                        );
                    }
                }
            }
        }
        Ok(Some(diff))
    }
}

/// Чистая функция diff: (новые в cur, исчезнувшие из prev), обе — отсортированы.
pub fn diff_ip_sets(prev: &[String], cur: &[String]) -> (Vec<String>, Vec<String>) {
    let mut new_hosts: Vec<String> = cur.iter().filter(|ip| !prev.contains(ip)).cloned().collect();
    let mut removed: Vec<String> = prev.iter().filter(|ip| !cur.contains(ip)).cloned().collect();
    new_hosts.sort();
    removed.sort();
    (new_hosts, removed)
}

impl Default for NetScanManager {
    fn default() -> Self {
        Self::new().expect("не удалось инициализировать NetScanManager")
    }
}

// ============================================================================
// Tauri команды
// ============================================================================

/// Запускает сканирование подсети. Возвращает результат со списком живых хостов.
#[tauri::command]
pub async fn net_scan_subnet(
    state: tauri::State<'_, NetScanManager>,
    cidr: String,
    ports: Option<Vec<u16>>,
    concurrency: Option<usize>,
    timeout_ms: Option<u64>,
) -> Result<ScanResult, String> {
    state.run_scan(&cidr, ports, concurrency, timeout_ms).await
}

/// Возвращает результат последнего сканирования.
#[tauri::command]
pub fn net_scan_last(state: tauri::State<'_, NetScanManager>) -> Result<Option<ScanResult>, String> {
    Ok(state.last_scan())
}

/// Возвращает историю сканирований из БД.
#[tauri::command]
pub fn net_scan_history(
    state: tauri::State<'_, NetScanManager>,
    limit: Option<u32>,
) -> Result<Vec<ScanRecord>, String> {
    state.history(limit.unwrap_or(500))
}

/// Разбирает CIDR и возвращает количество адресов (для UI-превью до сканирования).
#[tauri::command]
pub fn net_parse_cidr(cidr: String) -> Result<u32, String> {
    Ok(parse_cidr(&cidr)?.len() as u32)
}

/// Возвращает карту стандартных портов → сервисы.
#[tauri::command]
pub fn net_default_ports() -> Vec<u16> {
    default_ports()
}

/// Diff двух последних сканов: новые/исчезнувшие хосты (None, если сканов < 2).
/// Новые хосты уходят алертами в siem.db — их обрабатывает AI SOC (playbook new_host_alert).
#[tauri::command]
pub fn net_scan_diff(state: tauri::State<'_, NetScanManager>) -> Result<Option<ScanDiff>, String> {
    state.diff_last_two()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_slash24() {
        let ips = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(ips.len(), 256);
        assert_eq!(ips[0], Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(ips[255], Ipv4Addr::new(192, 168, 1, 255));
    }

    #[test]
    fn test_parse_cidr_slash32() {
        let ips = parse_cidr("10.0.0.5/32").unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], Ipv4Addr::new(10, 0, 0, 5));
    }

    #[test]
    fn test_parse_cidr_slash30() {
        let ips = parse_cidr("10.0.0.0/30").unwrap();
        assert_eq!(ips.len(), 4);
    }

    #[test]
    fn test_parse_cidr_rejects_too_big() {
        assert!(parse_cidr("0.0.0.0/8").is_err());
    }

    #[test]
    fn test_parse_cidr_invalid() {
        assert!(parse_cidr("not-an-ip").is_err());
        assert!(parse_cidr("10.0.0.0/33").is_err());
    }

    #[test]
    fn test_diff_ip_sets() {
        let prev = vec!["10.0.0.1".to_string(), "10.0.0.2".to_string(), "10.0.0.3".to_string()];
        let cur = vec!["10.0.0.2".to_string(), "10.0.0.3".to_string(), "10.0.0.9".to_string()];
        let (new, removed) = diff_ip_sets(&prev, &cur);
        assert_eq!(new, vec!["10.0.0.9".to_string()]);
        assert_eq!(removed, vec!["10.0.0.1".to_string()]);
        // идентичные сканы — пустой diff
        let (n2, r2) = diff_ip_sets(&prev, &prev);
        assert!(n2.is_empty() && r2.is_empty());
    }

    #[test]
    fn test_service_by_port() {
        assert_eq!(service_by_port(22), "ssh");
        assert_eq!(service_by_port(443), "https");
        assert_eq!(service_by_port(9999), "unknown");
    }

    #[test]
    fn test_default_ports_contains_common() {
        let ports = default_ports();
        assert!(ports.contains(&22));
        assert!(ports.contains(&443));
        assert!(ports.contains(&3389));
    }

    /// Живой тест: сканируем localhost на реально открытых портах (8080, 6379, 3000, 53).
    #[tokio::test]
    async fn test_live_scan_localhost() {
        let res = scan_subnet("127.0.0.1/32", vec![8080, 6379, 3000, 53, 22], 50, 800).await.unwrap();
        println!("live scan 127.0.0.1: {:?}", res);
        assert!(!res.is_empty(), "на localhost должны быть открыты порты из [8080,6379,3000,53]");
        let ports: Vec<u16> = res[0].1.iter().map(|p| p.port).collect();
        assert!(ports.contains(&8080) || ports.contains(&6379) || ports.contains(&3000) || ports.contains(&53));
    }
}

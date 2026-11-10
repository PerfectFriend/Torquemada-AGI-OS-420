//! Модуль анализа трафика и IDS/IPS (Фаза 7 плана эволюции).
//!
//! Что делает:
//!   - Запуск/останов IDS-перехвата через `tcpdump` (sidecar-бинарник): режим IDS на выбранном интерфейсе
//!   - Pure-Rust детектор угроз поверх потока пакетов: горизонтальное сканирование портов,
//!     флуд/DoS, обращения к «плохим» портам (C2/бэкдоры)
//!   - Сохранение алертов в SQLite (~/.w420/traffic.db)
//!   - Разовый захват трафика в .pcap (для последующего анализа в Wireshark/tshark)
//!   - Статистика интерфейсов из /proc/net/dev (скорости rx/tx, топ-говорящих)
//!   - Режим IPS: блокировка IP через nftables (таблица inet w420_block)
//!   - Импорт алертов Suricata из EVE JSON (forward-compatibility, если Suricata установят)
//!   - AI-анализ накопленных алертов через w420-ai (NVIDIA NIM / Mistral Large 4 по умолчанию)
//!
//! Все комментарии на русском. Команды экспонируются через Tauri invoke.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};

use w420_ai::db::AIProviderDB;
use w420_ai::rotation::KeyRotation;
use w420_ai::{ChatMessage, ChatRequest};

// ============================================================================
// Типы данных
// ============================================================================

/// Один алерт IDS/IPS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficAlert {
    pub id: String,
    pub ts: String,
    /// high | medium | low
    pub severity: String,
    /// port_scan | c2_port | flood | suricata
    pub category: String,
    pub signature: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: Option<u16>,
    pub description: String,
    /// w420-ids | suricata
    pub source: String,
}

/// Разобранный пакет (из строки tcpdump).
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: Option<u16>,
    pub flags: String,
    pub raw: String,
}

/// Состояние перехвата.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStatus {
    pub running: bool,
    pub interface: String,
    pub filter: String,
    pub auto_block: bool,
    pub started_at: Option<String>,
    pub packets_seen: u64,
    pub alerts_generated: u64,
}

/// Итог остановки перехвата.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSummary {
    pub interface: String,
    pub started_at: Option<String>,
    pub duration_secs: u64,
    pub packets_seen: u64,
    pub alerts_generated: u64,
}

/// Результат разового захвата в .pcap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureResult {
    pub path: String,
    pub bytes: u64,
    pub duration_secs: u64,
}

/// Статистика одного интерфейса.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IfaceStat {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_rate_bps: f64,
    pub tx_rate_bps: f64,
}

/// Топ-говорящий (по числу пакетов в текущей сессии).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Talker {
    pub src_ip: String,
    pub packets: u64,
}

/// Общая статистика трафика.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    pub interfaces: Vec<IfaceStat>,
    pub top_talkers: Vec<Talker>,
    pub alerts_total: u64,
    pub capture_running: bool,
    pub capture_interface: String,
}

/// Заблокированный IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedIp {
    pub ip: String,
    pub blocked_at: String,
    pub reason: String,
}

// ============================================================================
// Разбор строки tcpdump
// ============================================================================

/// Делит "10.0.0.2.443" на ("10.0.0.2", 443). Для IPv6 не применяется.
fn split_host_port(s: &str) -> Option<(String, u16)> {
    let (ip, port) = s.rsplit_once('.')?;
    let port: u16 = port.parse().ok()?;
    // грубая проверка, что это IPv4-адрес
    if ip.split('.').count() != 4 {
        return None;
    }
    Some((ip.to_string(), port))
}

/// Разбирает строку вывода tcpdump (`-n -l -q`) в структуру пакета.
/// Пример: `12:00:00.123456 IP 192.168.1.5.54321 > 10.0.0.1.80: Flags [S], seq 1, length 0`
pub fn parse_tcpdump_line(line: &str) -> Option<ParsedPacket> {
    let line = line.trim();
    let toks: Vec<&str> = line.split_whitespace().collect();
    let ip_idx = toks.iter().position(|t| *t == "IP")?;
    if toks.len() < ip_idx + 4 {
        return None;
    }
    let src_full = toks[ip_idx + 1].trim_end_matches(':');
    let arrow = toks[ip_idx + 2];
    // У конечного адреса tcpdump добавляет ':' перед протокольной частью — убираем
    let dst_full = toks[ip_idx + 3].trim_end_matches(':');
    if arrow != ">" {
        return None;
    }
    let (src_ip, _src_port) = split_host_port(src_full)?;
    let (dst_ip, dst_port) = split_host_port(dst_full)?;
    let flags = toks
        .iter()
        .position(|t| *t == "Flags")
        .and_then(|i| toks.get(i + 1))
        .map(|s| s.trim_end_matches(',').to_string())
        .unwrap_or_default();
    Some(ParsedPacket {
        src_ip,
        dst_ip,
        dst_port: Some(dst_port),
        flags,
        raw: line.to_string(),
    })
}

/// Определяет «плохой» порт (C2/бэкдоры/старые небезопасные сервисы).
/// Возвращает описание сигнатуры, если порт подозрительный.
pub fn c2_signature(port: u16) -> Option<&'static str> {
    match port {
        23 => Some("Telnet-порт открыт (небезопасный протокол)"),
        1234 | 12345 => Some("Порт NetBus/бэкдор"),
        31337 => Some("Порт Back Orifice (троян)"),
        4444 => Some("Порт Metasploit/шелов (типовой C2)"),
        5555 => Some("Порт Android Debug Bridge (ADB)"),
        6666 | 6667 => Some("IRC-порт (часто C2 ботнетов)"),
        27374 => Some("Порт SubSeven (троян)"),
        _ => None,
    }
}

// ============================================================================
// Детектор угроз (pure Rust)
// ============================================================================

/// Порог: сколько РАЗНЫХ портов с одного IP за окно считаем сканированием.
const PORT_SCAN_DISTINCT: usize = 15;
/// Окно для детекции сканирования портов.
const PORT_SCAN_WINDOW: Duration = Duration::from_secs(60);
/// Порог пакетов от одного источника для детекции флуда.
const FLOOD_PACKETS: usize = 500;
/// Окно для детекции флуда.
const FLOOD_WINDOW: Duration = Duration::from_secs(10);
/// Не чаще одного алерта данного типа на источник за это время.
const ALERT_COOLDOWN: Duration = Duration::from_secs(30);

/// Детектор: накапливает скользящие окна и порождает алерты.
#[derive(Default)]
struct Detector {
    /// src -> (время, dst_port) за окно сканирования
    port_window: HashMap<String, VecDeque<(Instant, u16)>>,
    /// src -> времена пакетов за окно флуда
    flood_window: HashMap<String, VecDeque<Instant>>,
    /// Общее число пакетов по источникам (топ-говорящие)
    talkers: HashMap<String, u64>,
    /// Время последнего алерта по ключу, чтобы не спамить
    last_alert: HashMap<String, Instant>,
}

impl Detector {
    fn cooldown_ok(&mut self, key: &str) -> bool {
        let now = Instant::now();
        match self.last_alert.get(key) {
            Some(t) if now.duration_since(*t) < ALERT_COOLDOWN => false,
            _ => {
                self.last_alert.insert(key.to_string(), now);
                true
            }
        }
    }

    /// Обрабатывает пакет, возвращает новые алерты.
    fn ingest(&mut self, p: &ParsedPacket) -> Vec<TrafficAlert> {
        let now = Instant::now();
        let mut alerts = Vec::new();

        *self.talkers.entry(p.src_ip.clone()).or_insert(0) += 1;

        // --- Детекция обращений к «плохим» портам ---
        if let Some(port) = p.dst_port {
            if let Some(sig) = c2_signature(port) {
                let key = format!("c2:{}:{}", p.src_ip, port);
                if self.cooldown_ok(&key) {
                    alerts.push(make_alert(
                        "high",
                        "c2_port",
                        sig,
                        &p.src_ip,
                        &p.dst_ip,
                        Some(port),
                        &format!(
                            "Обнаружено обращение к подозрительному порту {} с {} на {}. {}",
                            port, p.src_ip, p.dst_ip, sig
                        ),
                        "w420-ids",
                    ));
                }
            }

            // --- Детекция сканирования портов ---
            let w = self.port_window.entry(p.src_ip.clone()).or_default();
            w.push_back((now, port));
            while let Some((t, _)) = w.front() {
                if now.duration_since(*t) > PORT_SCAN_WINDOW {
                    w.pop_front();
                } else {
                    break;
                }
            }
            let distinct: HashSet<u16> = w.iter().map(|(_, pt)| *pt).collect();
            if distinct.len() >= PORT_SCAN_DISTINCT {
                let key = format!("scan:{}", p.src_ip);
                if self.cooldown_ok(&key) {
                    alerts.push(make_alert(
                        "high",
                        "port_scan",
                        "Горизонтальное сканирование портов",
                        &p.src_ip,
                        &p.dst_ip,
                        None,
                        &format!(
                            "Источник {} обратился к {} разным портам за {} с — признак сканирования сети",
                            p.src_ip,
                            distinct.len(),
                            PORT_SCAN_WINDOW.as_secs()
                        ),
                        "w420-ids",
                    ));
                }
            }
        }

        // --- Детекция флуда ---
        // Считаем «в окне» в отдельном блоке, чтобы заимствование self.flood_window
        // завершилось до обращения к self.cooldown_ok().
        let flood_len = {
            let fw = self.flood_window.entry(p.src_ip.clone()).or_default();
            fw.push_back(now);
            while let Some(t) = fw.front() {
                if now.duration_since(*t) > FLOOD_WINDOW {
                    fw.pop_front();
                } else {
                    break;
                }
            }
            fw.len()
        };
        if flood_len >= FLOOD_PACKETS {
            let key = format!("flood:{}", p.src_ip);
            if self.cooldown_ok(&key) {
                alerts.push(make_alert(
                    "medium",
                    "flood",
                    "Возможный флуд/DoS",
                    &p.src_ip,
                    &p.dst_ip,
                    p.dst_port,
                    &format!(
                        "Источник {} отправил {} пакетов за {} с — возможен флуд",
                        p.src_ip,
                        flood_len,
                        FLOOD_WINDOW.as_secs()
                    ),
                    "w420-ids",
                ));
            }
        }

        alerts
    }

    /// Топ-N говорящих по числу пакетов.
    fn top_talkers(&self, n: usize) -> Vec<Talker> {
        let mut v: Vec<Talker> = self
            .talkers
            .iter()
            .map(|(ip, c)| Talker {
                src_ip: ip.clone(),
                packets: *c,
            })
            .collect();
        v.sort_by(|a, b| b.packets.cmp(&a.packets));
        v.into_iter().take(n).collect()
    }
}

/// Создаёт алерт с текущей меткой времени.
fn make_alert(
    severity: &str,
    category: &str,
    signature: &str,
    src_ip: &str,
    dst_ip: &str,
    dst_port: Option<u16>,
    description: &str,
    source: &str,
) -> TrafficAlert {
    TrafficAlert {
        id: uuid::Uuid::new_v4().to_string(),
        ts: chrono::Utc::now().to_rfc3339(),
        severity: severity.to_string(),
        category: category.to_string(),
        signature: signature.to_string(),
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        dst_port,
        description: description.to_string(),
        source: source.to_string(),
    }
}

// ============================================================================
// Статистика интерфейсов (/proc/net/dev)
// ============================================================================

/// Читает счётчики байтов по интерфейсам из /proc/net/dev.
pub fn read_net_dev() -> Result<Vec<(String, u64, u64)>, String> {
    let content = std::fs::read_to_string("/proc/net/dev")
        .map_err(|e| format!("не удалось прочитать /proc/net/dev: {e}"))?;
    let mut out = Vec::new();
    for line in content.lines().skip(2) {
        if let Some((iface, rest)) = line.split_once(':') {
            let fields: Vec<&str> = rest.split_whitespace().collect();
            if fields.len() >= 16 {
                let rx = fields[0].parse::<u64>().unwrap_or(0);
                let tx = fields[8].parse::<u64>().unwrap_or(0);
                out.push((iface.trim().to_string(), rx, tx));
            }
        }
    }
    Ok(out)
}

// ============================================================================
// nftables: блокировка/разблокировка IP (IPS)
// ============================================================================

/// Выполняет команду nft: сначала напрямую (нужен CAP_NET_ADMIN), затем через `sudo -n`.
pub(crate) fn run_nft(args: &[&str]) -> Result<String, String> {
    if let Ok(o) = std::process::Command::new("nft").args(args).output() {
        if o.status.success() {
            return Ok(String::from_utf8_lossy(&o.stdout).to_string());
        }
    }
    let out = std::process::Command::new("sudo")
        .arg("-n")
        .arg("nft")
        .args(args)
        .output()
        .map_err(|e| format!("не удалось запустить sudo nft: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(format!(
            "nft {:?} → {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Создаёт инфраструктуру nftables (таблица, набор, цепочка, правило) — идемпотентно.
fn ensure_nft_infra() {
    // Ошибки «уже существует» игнорируем.
    let _ = run_nft(&["add", "table", "inet", "w420_block"]);
    let _ = run_nft(&[
        "add",
        "set",
        "inet",
        "w420_block",
        "w420_blocked",
        "{",
        "type",
        "ipv4_addr;",
        "}",
    ]);
    let _ = run_nft(&[
        "add",
        "chain",
        "inet",
        "w420_block",
        "w420_input",
        "{",
        "type",
        "filter",
        "hook",
        "input",
        "priority",
        "0;",
        "policy",
        "accept;",
        "}",
    ]);
    let _ = run_nft(&[
        "add",
        "rule",
        "inet",
        "w420_block",
        "w420_input",
        "ip",
        "saddr",
        "@w420_blocked",
        "counter",
        "drop",
    ]);
}

/// Блокирует IP в nftables. Возвращает текст успеха или ошибку.
pub fn block_ip(ip: &str, reason: &str) -> Result<String, String> {
    // Валидация IPv4 — защита от инъекции в аргументы nft
    let parsed: std::net::Ipv4Addr = ip
        .parse()
        .map_err(|e| format!("некорректный IPv4 '{ip}': {e}"))?;
    let ip = parsed.to_string();

    ensure_nft_infra();
    run_nft(&[
        "add",
        "element",
        "inet",
        "w420_block",
        "w420_blocked",
        &format!("{{ {ip} }}"),
    ])?;
    Ok(format!("IP {ip} заблокирован в nftables ({reason})"))
}

/// Разблокирует IP в nftables.
pub fn unblock_ip(ip: &str) -> Result<String, String> {
    let parsed: std::net::Ipv4Addr = ip
        .parse()
        .map_err(|e| format!("некорректный IPv4 '{ip}': {e}"))?;
    let ip = parsed.to_string();
    run_nft(&[
        "delete",
        "element",
        "inet",
        "w420_block",
        "w420_blocked",
        &format!("{{ {ip} }}"),
    ])?;
    Ok(format!("IP {ip} разблокирован"))
}

// ============================================================================
// Менеджер трафика
// ============================================================================

/// Внутреннее состояние (в Arc, чтобы жить в фоновой задаче чтения).
struct TrafficInner {
    db: Mutex<rusqlite::Connection>,
    state: Mutex<CaptureState>,
    detector: Mutex<Detector>,
    last_stats: Mutex<Option<(Instant, Vec<(String, u64, u64)>)>>,
    pcap_dir: PathBuf,
}

/// Текущее состояние перехвата (процесс + задача чтения).
struct CaptureState {
    running: bool,
    interface: String,
    filter: String,
    auto_block: bool,
    started_at: Option<String>,
    started_instant: Option<Instant>,
    packets_seen: u64,
    alerts_generated: u64,
    child: Option<tokio::process::Child>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Default for CaptureState {
    fn default() -> Self {
        Self {
            running: false,
            interface: String::new(),
            filter: String::new(),
            auto_block: false,
            started_at: None,
            started_instant: None,
            packets_seen: 0,
            alerts_generated: 0,
            child: None,
            task: None,
        }
    }
}

pub struct TrafficManager {
    inner: Arc<TrafficInner>,
}

impl TrafficManager {
    /// Менеджер с каталогом ~/.w420 (обычный путь приложения).
    pub fn new() -> Result<Self, String> {
        let home = std::env::var("HOME").map_err(|e| format!("HOME не задан: {e}"))?;
        Self::new_at(Path::new(&home).join(".w420"))
    }

    /// Менеджер с произвольным каталогом состояния (используется в тестах).
    pub fn new_at(w420_dir: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&w420_dir).map_err(|e| format!("не удалось создать {w420_dir:?}: {e}"))?;
        let pcap_dir = w420_dir.join("pcap");
        std::fs::create_dir_all(&pcap_dir).map_err(|e| format!("не удалось создать {pcap_dir:?}: {e}"))?;

        let db_path = w420_dir.join("traffic.db");
        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| format!("не удалось открыть traffic.db: {e}"))?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                signature TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER,
                description TEXT NOT NULL,
                source TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_traffic_alerts_ts ON alerts(ts);
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                blocked_at TEXT NOT NULL,
                reason TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            );
        "#,
        )
        .map_err(|e| format!("не удалось создать схему traffic.db: {e}"))?;

        Ok(Self {
            inner: Arc::new(TrafficInner {
                db: Mutex::new(conn),
                state: Mutex::new(CaptureState::default()),
                detector: Mutex::new(Detector::default()),
                last_stats: Mutex::new(None),
                pcap_dir,
            }),
        })
    }

    /// Сохраняет алерт в БД.
    fn save_alert(&self, a: &TrafficAlert) {
        if let Ok(conn) = self.inner.db.lock() {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO alerts (id, ts, severity, category, signature, src_ip, dst_ip, dst_port, description, source) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                rusqlite::params![
                    a.id, a.ts, a.severity, a.category, a.signature,
                    a.src_ip, a.dst_ip, a.dst_port, a.description, a.source
                ],
            );
        }
    }

    /// Список последних алертов.
    pub fn list_alerts(&self, limit: u32) -> Result<Vec<TrafficAlert>, String> {
        let conn = self.inner.db.lock().map_err(|_| "мьютекс БД отравлен")?;
        let mut stmt = conn
            .prepare("SELECT id, ts, severity, category, signature, src_ip, dst_ip, dst_port, description, source FROM alerts ORDER BY ts DESC LIMIT ?1")
            .map_err(|e| format!("ошибка подготовки запроса: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![limit as i64], |row| {
                Ok(TrafficAlert {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    severity: row.get(2)?,
                    category: row.get(3)?,
                    signature: row.get(4)?,
                    src_ip: row.get(5)?,
                    dst_ip: row.get(6)?,
                    dst_port: row.get(7)?,
                    description: row.get(8)?,
                    source: row.get(9)?,
                })
            })
            .map_err(|e| format!("ошибка запроса: {e}"))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| format!("ошибка чтения: {e}"))?);
        }
        Ok(out)
    }

    /// Количество алертов в БД.
    fn alerts_count(&self) -> u64 {
        self.inner
            .db
            .lock()
            .ok()
            .and_then(|c| {
                c.query_row("SELECT COUNT(*) FROM alerts", [], |r| r.get::<_, i64>(0))
                    .ok()
            })
            .unwrap_or(0) as u64
    }

    /// Текущий статус перехвата.
    pub fn status(&self) -> CaptureStatus {
        let st = self.inner.state.lock();
        match st {
            Ok(st) => CaptureStatus {
                running: st.running,
                interface: st.interface.clone(),
                filter: st.filter.clone(),
                auto_block: st.auto_block,
                started_at: st.started_at.clone(),
                packets_seen: st.packets_seen,
                alerts_generated: st.alerts_generated,
            },
            Err(_) => CaptureStatus {
                running: false,
                interface: String::new(),
                filter: String::new(),
                auto_block: false,
                started_at: None,
                packets_seen: 0,
                alerts_generated: 0,
            },
        }
    }

    /// Запускает IDS-перехват на интерфейсе.
    pub async fn start_ids(
        &self,
        interface: String,
        filter: String,
        auto_block: bool,
    ) -> Result<CaptureStatus, String> {
        // Проверяем, что не запущено
        {
            let st = self.inner.state.lock().map_err(|_| "мьютекс состояния отравлен")?;
            if st.running {
                return Err("IDS уже запущен — сначала остановите (traffic_stop)".to_string());
            }
        }

        // Собираем команду tcpdump. Фильтр разбиваем по пробелам (BPF принимает отдельные аргументы).
        let mut cmd = tokio::process::Command::new("tcpdump");
        cmd.arg("-i")
            .arg(&interface)
            .arg("-n")
            .arg("-l")
            .arg("-q")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for tok in filter.split_whitespace() {
            cmd.arg(tok);
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(_) => {
                // Попытка через sudo -n (если нет прав на raw-сокет)
                let mut sudo_cmd = tokio::process::Command::new("sudo");
                sudo_cmd
                    .arg("-n")
                    .arg("tcpdump")
                    .arg("-i")
                    .arg(&interface)
                    .arg("-n")
                    .arg("-l")
                    .arg("-q")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null());
                for tok in filter.split_whitespace() {
                    sudo_cmd.arg(tok);
                }
                sudo_cmd.spawn().map_err(|e| {
                    format!("не удалось запустить tcpdump на {interface}: {e} (нужен root/CAP_NET_RAW)")
                })?
            }
        };

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "не удалось получить stdout tcpdump".to_string())?;

        // Фоновая задача чтения и анализа потока пакетов
        let inner = Arc::clone(&self.inner);
        let task = tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        if let Some(p) = parse_tcpdump_line(&line) {
                            {
                                if let Ok(mut st) = inner.state.lock() {
                                    st.packets_seen += 1;
                                }
                            }
                            let alerts = {
                                match inner.detector.lock() {
                                    Ok(mut det) => det.ingest(&p),
                                    Err(_) => Vec::new(),
                                }
                            };
                            for a in alerts {
                                let do_block = auto_block && a.severity == "high";
                                if let Ok(conn) = inner.db.lock() {
                                    let _ = conn.execute(
                                        "INSERT OR REPLACE INTO alerts (id, ts, severity, category, signature, src_ip, dst_ip, dst_port, description, source) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                                        rusqlite::params![
                                            a.id, a.ts, a.severity, a.category, a.signature,
                                            a.src_ip, a.dst_ip, a.dst_port, a.description, a.source
                                        ],
                                    );
                                }
                                if let Ok(mut st) = inner.state.lock() {
                                    st.alerts_generated += 1;
                                }
                                if do_block {
                                    // Авто-блокировка через nftables (режим IPS)
                                    let _ = block_ip(&a.src_ip, &a.signature);
                                }
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
            // Поток закончился — снимаем признак работы
            if let Ok(mut st) = inner.state.lock() {
                st.running = false;
            }
        });

        // Фиксируем состояние
        {
            let mut st = self.inner.state.lock().map_err(|_| "мьютекс состояния отравлен")?;
            st.running = true;
            st.interface = interface;
            st.filter = filter;
            st.auto_block = auto_block;
            st.started_at = Some(chrono::Utc::now().to_rfc3339());
            st.started_instant = Some(Instant::now());
            st.child = Some(child);
            st.task = Some(task);
        }

        Ok(self.status())
    }

    /// Останавливает IDS-перехват.
    pub async fn stop(&self) -> Result<CaptureSummary, String> {
        let (child, task, iface, started_at, started_instant, packets, alerts) = {
            let mut st = self.inner.state.lock().map_err(|_| "мьютекс состояния отравлен")?;
            st.running = false;
            (
                st.child.take(),
                st.task.take(),
                st.interface.clone(),
                st.started_at.clone(),
                st.started_instant,
                st.packets_seen,
                st.alerts_generated,
            )
        };

        if let Some(mut c) = child {
            let _ = c.kill().await;
        }
        if let Some(t) = task {
            t.abort();
        }

        let duration_secs = started_instant
            .map(|i| i.elapsed().as_secs())
            .unwrap_or(0);

        Ok(CaptureSummary {
            interface: iface,
            started_at,
            duration_secs,
            packets_seen: packets,
            alerts_generated: alerts,
        })
    }

    /// Разовый захват трафика в .pcap на заданное время.
    async fn capture_pcap(
        &self,
        interface: String,
        filter: String,
        duration_secs: u64,
        name: String,
    ) -> Result<CaptureResult, String> {
        // Санитизация имени файла
        let safe: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
            .collect();
        let safe = if safe.is_empty() {
            format!("capture-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"))
        } else {
            safe
        };
        let out = self.inner.pcap_dir.join(format!("{safe}.pcap"));
        // ВАЖНО: AppArmor-профиль tcpdump разрешает запись только в /tmp —
        // поэтому пишем во временный файл, а в итоговый путь копируем сами.
        let tmp = std::env::temp_dir().join(format!("w420_{safe}.pcap"));

        let mut cmd = tokio::process::Command::new("tcpdump");
        cmd.arg("-i")
            .arg(&interface)
            .arg("-n")
            .arg("-w")
            .arg(&tmp)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for tok in filter.split_whitespace() {
            cmd.arg(tok);
        }
        let mut child = cmd.spawn().map_err(|e| {
            format!("не удалось запустить tcpdump: {e} (нужен root/CAP_NET_RAW)")
        })?;

        tokio::time::sleep(Duration::from_secs(duration_secs.max(1))).await;
        let _ = child.kill().await;
        let _ = child.wait().await;

        // Переносим pcap из /tmp (куда tcpdump имеет право писать по AppArmor) в pcap_dir
        let _ = std::fs::create_dir_all(&self.inner.pcap_dir);
        let _ = std::fs::copy(&tmp, &out);
        let _ = std::fs::remove_file(&tmp);

        let bytes = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
        Ok(CaptureResult {
            path: out.to_string_lossy().to_string(),
            bytes,
            duration_secs,
        })
    }

    /// Собирает статистику трафика.
    fn stats(&self) -> Result<TrafficStats, String> {
        let now = Instant::now();
        let current = read_net_dev()?;

        let mut interfaces = Vec::new();
        {
            let mut last = self.inner.last_stats.lock().map_err(|_| "мьютекс статистики отравлен")?;
            if let Some((prev_time, prev)) = last.as_ref() {
                let elapsed = now.duration_since(*prev_time).as_secs_f64().max(0.001);
                for (name, rx, tx) in &current {
                    let (prx, ptx) = prev
                        .iter()
                        .find(|(n, _, _)| n == name)
                        .map(|(_, r, t)| (*r, *t))
                        .unwrap_or((*rx, *tx));
                    interfaces.push(IfaceStat {
                        name: name.clone(),
                        rx_bytes: *rx,
                        tx_bytes: *tx,
                        rx_rate_bps: rx.saturating_sub(prx) as f64 / elapsed,
                        tx_rate_bps: tx.saturating_sub(ptx) as f64 / elapsed,
                    });
                }
            } else {
                for (name, rx, tx) in &current {
                    interfaces.push(IfaceStat {
                        name: name.clone(),
                        rx_bytes: *rx,
                        tx_bytes: *tx,
                        rx_rate_bps: 0.0,
                        tx_rate_bps: 0.0,
                    });
                }
            }
            *last = Some((now, current));
        }

        let top_talkers = self
            .inner
            .detector
            .lock()
            .map(|d| d.top_talkers(10))
            .unwrap_or_default();

        let status = self.status();
        Ok(TrafficStats {
            interfaces,
            top_talkers,
            alerts_total: self.alerts_count(),
            capture_running: status.running,
            capture_interface: status.interface,
        })
    }

    /// Список активных заблокированных IP из БД.
    pub fn blocked_list(&self) -> Result<Vec<BlockedIp>, String> {
        let conn = self.inner.db.lock().map_err(|_| "мьютекс БД отравлен")?;
        let mut stmt = conn
            .prepare("SELECT ip, blocked_at, reason FROM blocked_ips WHERE active = 1 ORDER BY blocked_at DESC")
            .map_err(|e| format!("ошибка запроса: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(BlockedIp {
                    ip: row.get(0)?,
                    blocked_at: row.get(1)?,
                    reason: row.get(2)?,
                })
            })
            .map_err(|e| format!("ошибка запроса: {e}"))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| format!("ошибка чтения: {e}"))?);
        }
        Ok(out)
    }

    /// Блокирует IP: добавляет в nftables и в БД.
    pub fn do_block(&self, ip: &str, reason: &str) -> Result<String, String> {
        let msg = block_ip(ip, reason)?;
        if let Ok(conn) = self.inner.db.lock() {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, reason, active) VALUES (?1, ?2, ?3, 1)",
                rusqlite::params![ip, chrono::Utc::now().to_rfc3339(), reason],
            );
        }
        Ok(msg)
    }

    /// Разблокирует IP: убирает из nftables и помечает в БД.
    pub fn do_unblock(&self, ip: &str) -> Result<String, String> {
        let msg = unblock_ip(ip)?;
        if let Ok(conn) = self.inner.db.lock() {
            let _ = conn.execute(
                "UPDATE blocked_ips SET active = 0 WHERE ip = ?1",
                rusqlite::params![ip],
            );
        }
        Ok(msg)
    }

    /// Импортирует алерты Suricata из EVE JSON-файла. Возвращает число импортированных.
    fn eve_sync(&self, path: &str) -> Result<u64, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("не удалось прочитать {path}: {e}"))?;
        let mut count = 0u64;
        for line in content.lines() {
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v.get("event_type").and_then(|e| e.as_str()) != Some("alert") {
                continue;
            }
            let sev_num = v
                .get("alert")
                .and_then(|a| a.get("severity"))
                .and_then(|s| s.as_u64())
                .unwrap_or(3);
            let severity = match sev_num {
                1 => "high",
                2 => "medium",
                _ => "low",
            };
            let alert = make_alert(
                severity,
                "suricata",
                v.get("alert").and_then(|a| a.get("signature")).and_then(|s| s.as_str()).unwrap_or("Suricata alert"),
                v.get("src_ip").and_then(|s| s.as_str()).unwrap_or(""),
                v.get("dest_ip").and_then(|s| s.as_str()).unwrap_or(""),
                v.get("dest_port").and_then(|s| s.as_u64()).map(|p| p as u16),
                v.get("alert").and_then(|a| a.get("category")).and_then(|s| s.as_str()).unwrap_or("Suricata"),
                "suricata",
            );
            self.save_alert(&alert);
            count += 1;
        }
        Ok(count)
    }

    /// AI-анализ последних алертов через w420-ai.
    async fn ai_analyze(&self, limit: u32) -> Result<String, String> {
        let alerts = self.list_alerts(limit)?;
        if alerts.is_empty() {
            return Ok("Нет алертов для анализа.".to_string());
        }

        let mut body = String::new();
        for a in &alerts {
            body.push_str(&format!(
                "- [{}][{}] {}: {} -> {}:{:?} — {}\n",
                a.ts, a.severity, a.category, a.src_ip, a.dst_ip, a.dst_port, a.description
            ));
        }
        let prompt = format!(
            "Ты — эксперт по кибербезопасности (AI SOC). Проанализируй список алертов IDS и дай:\n\
             1) общую оценку угрозы (низкая/средняя/высокая),\n\
             2) приоритизацию алертов (какие критичны, какие ложные срабатывания),\n\
             3) конкретные рекомендации по реагированию (блокировать/изолировать/наблюдать).\n\
             Отвечай по-русски, структурно.\n\nАлерты:\n{body}"
        );

        // Загружаем провайдера и ключи (блок синхронный, БД дропается до await)
        let (providers, keys, model) = {
            let home = std::env::var("HOME").map_err(|e| e.to_string())?;
            let cfg_path = Path::new(&home).join(".w420").join("security_ai.json");
            let default_provider = std::fs::read_to_string(&cfg_path)
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .and_then(|v| v.get("default_provider").and_then(|d| d.as_str()).map(|s| s.to_string()))
                .unwrap_or_else(|| "NVIDIA NIM (default)".to_string());

            let db = AIProviderDB::open().map_err(|e| format!("БД провайдеров: {e}"))?;
            let providers = db.list_providers().map_err(|e| format!("провайдеры: {e}"))?;
            let keys = db.list_all_keys().map_err(|e| format!("ключи: {e}"))?;
            let model = providers
                .iter()
                .find(|p| p.name == default_provider)
                .and_then(|p| p.models.first().cloned())
                .unwrap_or_else(|| "mistralai/mistral-large-4-1t-a52b".to_string());
            (providers, keys, model)
        };

        let rotation = KeyRotation::new();
        for p in providers {
            rotation.add_provider(p).await;
        }
        for k in keys {
            if k.is_active {
                rotation.add_key(k).await;
            }
        }

        let request = ChatRequest {
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: "Ты — опытный аналитик безопасности (AI SOC), отвечаешь по-русски.".to_string(),
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: prompt,
                },
            ],
            model,
            temperature: 0.2,
            max_tokens: Some(1024),
            stream: false,
        };

        let result = rotation
            .chat_completion_with_rotation(request, None)
            .await
            .map_err(|e| format!("ошибка запроса к AI: {e}"))?;
        Ok(result.response.content)
    }
}

// ============================================================================
// Tauri команды
// ============================================================================

/// Запускает IDS-перехват: tcpdump на интерфейсе + детектор поверх потока.
#[tauri::command]
pub async fn traffic_start_ids(
    state: tauri::State<'_, TrafficManager>,
    interface: String,
    filter: Option<String>,
    auto_block: Option<bool>,
) -> Result<CaptureStatus, String> {
    state
        .start_ids(interface, filter.unwrap_or_default(), auto_block.unwrap_or(false))
        .await
}

/// Останавливает IDS-перехват.
#[tauri::command]
pub async fn traffic_stop(state: tauri::State<'_, TrafficManager>) -> Result<CaptureSummary, String> {
    state.stop().await
}

/// Текущий статус перехвата.
#[tauri::command]
pub fn traffic_status(state: tauri::State<'_, TrafficManager>) -> CaptureStatus {
    state.status()
}

/// Последние алерты.
#[tauri::command]
pub fn traffic_alerts(
    state: tauri::State<'_, TrafficManager>,
    limit: Option<u32>,
) -> Result<Vec<TrafficAlert>, String> {
    state.list_alerts(limit.unwrap_or(200))
}

/// Статистика трафика (интерфейсы, топ-говорящие, алерты).
#[tauri::command]
pub fn traffic_stats(state: tauri::State<'_, TrafficManager>) -> Result<TrafficStats, String> {
    state.stats()
}

/// Разовый захват трафика в .pcap.
#[tauri::command]
pub async fn traffic_capture(
    state: tauri::State<'_, TrafficManager>,
    interface: String,
    filter: Option<String>,
    duration_secs: Option<u64>,
    name: Option<String>,
) -> Result<CaptureResult, String> {
    state
        .capture_pcap(
            interface,
            filter.unwrap_or_default(),
            duration_secs.unwrap_or(10),
            name.unwrap_or_default(),
        )
        .await
}

/// Блокирует IP (режим IPS, nftables).
#[tauri::command]
pub fn traffic_block_ip(
    state: tauri::State<'_, TrafficManager>,
    ip: String,
    reason: Option<String>,
) -> Result<String, String> {
    state.do_block(&ip, &reason.unwrap_or_else(|| "ручная блокировка".to_string()))
}

/// Разблокирует IP.
#[tauri::command]
pub fn traffic_unblock_ip(
    state: tauri::State<'_, TrafficManager>,
    ip: String,
) -> Result<String, String> {
    state.do_unblock(&ip)
}

/// Список активных блокировок.
#[tauri::command]
pub fn traffic_blocked_list(state: tauri::State<'_, TrafficManager>) -> Result<Vec<BlockedIp>, String> {
    state.blocked_list()
}

/// Импорт алертов Suricata из EVE JSON.
#[tauri::command]
pub fn traffic_eve_sync(
    state: tauri::State<'_, TrafficManager>,
    path: String,
) -> Result<u64, String> {
    state.eve_sync(&path)
}

/// AI-анализ накопленных алертов.
#[tauri::command]
pub async fn traffic_ai_analyze(
    state: tauri::State<'_, TrafficManager>,
    limit: Option<u32>,
) -> Result<String, String> {
    state.ai_analyze(limit.unwrap_or(50)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcpdump_line_basic() {
        let line = "12:00:00.123456 IP 192.168.1.5.54321 > 10.0.0.1.80: Flags [S], seq 1, length 0";
        let p = parse_tcpdump_line(line).expect("должен распарситься");
        assert_eq!(p.src_ip, "192.168.1.5");
        assert_eq!(p.dst_ip, "10.0.0.1");
        assert_eq!(p.dst_port, Some(80));
        assert_eq!(p.flags, "[S]");
    }

    #[test]
    fn test_parse_tcpdump_skips_arp() {
        let line = "12:00:00.123456 ARP, Request who-has 10.0.0.1 tell 10.0.0.2, length 28";
        assert!(parse_tcpdump_line(line).is_none());
    }

    #[test]
    fn test_c2_signature() {
        assert!(c2_signature(4444).is_some());
        assert!(c2_signature(31337).is_some());
        assert!(c2_signature(443).is_none());
        assert!(c2_signature(8080).is_none());
    }

    #[test]
    fn test_split_host_port() {
        assert_eq!(split_host_port("10.0.0.2.443"), Some(("10.0.0.2".to_string(), 443)));
        assert_eq!(split_host_port("garbage"), None);
        assert_eq!(split_host_port("10.0.0.2.notaport"), None);
    }

    #[test]
    fn test_detector_port_scan() {
        let mut det = Detector::default();
        let mut saw_scan = false;
        for port in 1..=30u16 {
            let p = ParsedPacket {
                src_ip: "10.0.0.66".to_string(),
                dst_ip: "10.0.0.1".to_string(),
                dst_port: Some(1000 + port),
                flags: "[S]".to_string(),
                raw: String::new(),
            };
            for a in det.ingest(&p) {
                if a.category == "port_scan" {
                    saw_scan = true;
                    assert_eq!(a.severity, "high");
                }
            }
        }
        assert!(saw_scan, "детектор должен обнаружить сканирование портов");
    }

    #[test]
    fn test_detector_flood() {
        let mut det = Detector::default();
        let mut saw_flood = false;
        for _ in 0..(FLOOD_PACKETS + 10) {
            let p = ParsedPacket {
                src_ip: "10.0.0.77".to_string(),
                dst_ip: "10.0.0.1".to_string(),
                dst_port: Some(80),
                flags: "[S]".to_string(),
                raw: String::new(),
            };
            for a in det.ingest(&p) {
                if a.category == "flood" {
                    saw_flood = true;
                }
            }
        }
        assert!(saw_flood, "детектор должен обнаружить флуд");
    }

    #[test]
    fn test_detector_c2_port() {
        let mut det = Detector::default();
        let p = ParsedPacket {
            src_ip: "10.0.0.88".to_string(),
            dst_ip: "10.0.0.1".to_string(),
            dst_port: Some(4444),
            flags: "[S]".to_string(),
            raw: String::new(),
        };
        let alerts = det.ingest(&p);
        assert!(alerts.iter().any(|a| a.category == "c2_port" && a.severity == "high"));
    }

    /// Сквозной тест импорта Suricata EVE JSON в БД (root не требуется).
    #[test]
    fn test_eve_sync_imports_alerts() {
        let dir = std::env::temp_dir().join(format!("w420-traffic-test-{}", uuid::Uuid::new_v4()));
        let mgr = TrafficManager::new_at(dir.clone()).expect("менеджер должен создаться");

        let eve = dir.join("eve.json");
        let content = concat!(
            r#"{"event_type":"alert","src_ip":"10.1.1.5","dest_ip":"10.1.1.1","dest_port":445,"alert":{"signature":"SMB attack","severity":1,"category":"attempted-admin"}}"#,
            "\n",
            r#"{"event_type":"flow","src_ip":"10.1.1.6","dest_ip":"10.1.1.1"}"#,
            "\n",
            r#"{"event_type":"alert","src_ip":"10.1.1.7","dest_ip":"10.1.1.1","dest_port":22,"alert":{"signature":"SSH brute force","severity":2,"category":"attempted-user"}}"#,
            "\n"
        );
        std::fs::write(&eve, content).expect("eve.json должен записаться");

        let imported = mgr.eve_sync(eve.to_str().unwrap()).expect("импорт должен пройти");
        assert_eq!(imported, 2, "должны импортироваться только alert-события");

        let alerts = mgr.list_alerts(10).expect("список алертов");
        assert_eq!(alerts.len(), 2);
        assert!(alerts.iter().any(|a| a.severity == "high" && a.dst_port == Some(445)));
        assert!(alerts.iter().any(|a| a.severity == "medium" && a.dst_port == Some(22)));
        assert!(alerts.iter().all(|a| a.source == "suricata"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Проверка сохранения/чтения алертов и списка блокировок через БД.
    #[test]
    fn test_alert_db_roundtrip() {
        let dir = std::env::temp_dir().join(format!("w420-traffic-db-{}", uuid::Uuid::new_v4()));
        let mgr = TrafficManager::new_at(dir.clone()).expect("менеджер должен создаться");

        let a = make_alert("high", "c2_port", "test", "10.0.0.5", "10.0.0.1", Some(4444), "описание", "w420-ids");
        mgr.save_alert(&a);
        let alerts = mgr.list_alerts(5).expect("список алертов");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].src_ip, "10.0.0.5");
        assert_eq!(mgr.alerts_count(), 1);

        assert!(mgr.blocked_list().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_read_net_dev_has_lo() {
        let ifaces = read_net_dev().expect("/proc/net/dev должен читаться");
        assert!(ifaces.iter().any(|(n, _, _)| n == "lo"), "должен быть интерфейс lo");
    }

    #[test]
    fn test_top_talkers_sorted() {
        let mut det = Detector::default();
        for _ in 0..5 {
            det.ingest(&ParsedPacket {
                src_ip: "10.0.0.1".to_string(),
                dst_ip: "10.0.0.9".to_string(),
                dst_port: Some(80),
                flags: String::new(),
                raw: String::new(),
            });
        }
        for _ in 0..2 {
            det.ingest(&ParsedPacket {
                src_ip: "10.0.0.2".to_string(),
                dst_ip: "10.0.0.9".to_string(),
                dst_port: Some(80),
                flags: String::new(),
                raw: String::new(),
            });
        }
        let top = det.top_talkers(2);
        assert_eq!(top[0].src_ip, "10.0.0.1");
        assert_eq!(top[0].packets, 5);
    }
}

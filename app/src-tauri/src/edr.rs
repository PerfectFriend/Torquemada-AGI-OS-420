//! Фаза 10 (ядро, локальный агент): EDR — мониторинг процессов и сетевых соединений хоста,
//! baseline, события, реагирование (kill процесса, изоляция IP через firewall, аварийный режим).
//!
//! БД `~/.w420/edr.db`: processes_snap (снимки), events (события EDR), baseline (эталон процессов).
//! Источники данных: sysinfo 0.30 (процессы) + `ss -tunp` (соединения с PID).
//! Внешний агент на удалённых хостах — Phase 10 (remote), здесь локальное ядро + команды.

use rusqlite::Connection;
use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use sysinfo::{ProcessRefreshKind, System};

use crate::traffic::run_nft;

pub struct EdrManager {
    pub db: Mutex<PathBuf>,
    pub watching: Arc<AtomicBool>,
}

fn home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"))
}

#[derive(Serialize, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub exe: String,
    pub cmd: String,
    pub cpu: f32,
    pub mem_kb: u64,
    pub parent: Option<u32>,
}

#[derive(Serialize, Clone)]
pub struct ConnInfo {
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub pid: u32,
    pub process: String,
}

impl EdrManager {
    pub fn new() -> Self {
        let db = home().join(".w420").join("edr.db");
        let m = Self { db: Mutex::new(db.clone()), watching: Arc::new(AtomicBool::new(false)) };
        m.init(&db);
        m
    }

    fn init(&self, db: &PathBuf) {
        if let Ok(c) = Connection::open(db) {
            let _ = c.execute_batch(
                "CREATE TABLE IF NOT EXISTS processes_snap (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL, pid INTEGER NOT NULL, name TEXT, exe TEXT, cpu REAL, mem_kb INTEGER
                );
                CREATE TABLE IF NOT EXISTS baseline (pid_key TEXT PRIMARY KEY, name TEXT, exe TEXT);
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL,
                    pid INTEGER, process TEXT, detail TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_edr_ev ON events(ts);",
            );
        }
    }

    pub fn conn(&self) -> Result<Connection, String> {
        let p = self.db.lock().unwrap().clone();
        Connection::open(p).map_err(|e| e.to_string())
    }

    fn add_event(&self, category: &str, severity: &str, pid: Option<u32>, process: &str, detail: &str) {
        if let Ok(c) = self.conn() {
            let _ = c.execute(
                "INSERT INTO events (ts, category, severity, pid, process, detail) VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![chrono::Utc::now().to_rfc3339(), category, severity, pid.unwrap_or(0), process, detail],
            );
        }
    }

    /// Снимок процессов через sysinfo.
    pub fn scan_processes(&self) -> Result<Vec<ProcInfo>, String> {
        let mut sys = System::new_all();
        sys.refresh_processes_specifics(ProcessRefreshKind::everything());
        let mut out: Vec<ProcInfo> = sys
            .processes()
            .iter()
            .map(|(pid, p)| ProcInfo {
                pid: pid.as_u32(),
                name: p.name().to_string(),
                exe: p.exe().map(|e| e.to_string_lossy().into_owned()).unwrap_or_default(),
                cmd: p.cmd().join(" "),
                cpu: p.cpu_usage(),
                mem_kb: p.memory(),
                parent: p.parent().map(|p| p.as_u32()),
            })
            .collect();
        out.sort_by_key(|p| p.pid);
        // сохраняем снимок
        if let Ok(c) = self.conn() {
            let ts = chrono::Utc::now().to_rfc3339();
            for p in &out {
                let _ = c.execute(
                    "INSERT INTO processes_snap (ts, pid, name, exe, cpu, mem_kb) VALUES (?1,?2,?3,?4,?5,?6)",
                    rusqlite::params![ts, p.pid as i64, &p.name, &p.exe, p.cpu, p.mem_kb as i64],
                );
            }
        }
        Ok(out)
    }

    /// Установить baseline процессов (по exe+name). Возвращает число записей.
    pub fn set_baseline(&self, procs: &[ProcInfo]) -> Result<usize, String> {
        let c = self.conn()?;
        let _ = c.execute("DELETE FROM baseline", []);
        let mut n = 0;
        for p in procs {
            let key = format!("{}|{}", p.exe, p.name);
            let _ = c.execute(
                "INSERT OR IGNORE INTO baseline (pid_key, name, exe) VALUES (?1,?2,?3)",
                rusqlite::params![key, &p.name, &p.exe],
            );
            n += 1;
        }
        Ok(n)
    }

    /// Дифф против baseline: новые процессы → события new_process (severity medium, high если есть внешнее соединение).
    pub fn diff_baseline(&self, procs: &[ProcInfo], conns: &[ConnInfo]) -> Result<usize, String> {
        let c = self.conn()?;
        let mut stmt = c.prepare("SELECT pid_key FROM baseline").map_err(|e| e.to_string())?;
        let base: std::collections::HashSet<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?
            .flatten()
            .collect();
        let mut new_count = 0;
        for p in procs {
            let key = format!("{}|{}", p.exe, p.name);
            if base.contains(&key) || p.exe.is_empty() {
                continue;
            }
            let ext = conns.iter().any(|cn| cn.pid == p.pid && is_external(&cn.remote));
            let sev = if ext { "high" } else { "medium" };
            self.add_event("new_process", sev, Some(p.pid), &p.name, &format!("{} ({}){}", p.exe, p.cmd, if ext { " — есть внешнее соединение" } else { "" }));
            new_count += 1;
        }
        Ok(new_count)
    }

    pub fn events(&self, limit: u32) -> Result<Vec<serde_json::Value>, String> {
        let c = self.conn()?;
        let mut st = c
            .prepare("SELECT id, ts, category, severity, pid, process, detail FROM events ORDER BY id DESC LIMIT ?1")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map([limit.min(500)], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, i64>(0)?, "ts": r.get::<_, String>(1)?, "category": r.get::<_, String>(2)?,
                    "severity": r.get::<_, String>(3)?, "pid": r.get::<_, i64>(4)?, "process": r.get::<_, String>(5)?,
                    "detail": r.get::<_, String>(6)?,
                }))
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }

    /// фоновый watch: каждые interval_secs — scan + connections + diff baseline
    pub fn start_watch(&self, interval_secs: u32) {
        if self.watching.swap(true, Ordering::SeqCst) {
            return; // уже запущен
        }
        let db = self.db.lock().unwrap().clone();
        let watching = self.watching.clone();
        std::thread::spawn(move || {
            let mgr = EdrManager { db: Mutex::new(db), watching: watching.clone() };
            while watching.load(Ordering::SeqCst) {
                if let Ok(procs) = mgr.scan_processes() {
                    let conns = parse_ss(&ss_tunp().unwrap_or_default());
                    let _ = mgr.diff_baseline(&procs, &conns);
                }
                std::thread::sleep(std::time::Duration::from_secs(interval_secs.max(10) as u64));
            }
        });
    }

    pub fn stop_watch(&self) {
        self.watching.store(false, Ordering::SeqCst);
    }
}

/// true, если remote-адрес внешний (не loopback/RFC1918/link-local)
pub fn is_external(remote: &str) -> bool {
    let addr = remote.split(':').next().unwrap_or("");
    if addr.is_empty() || addr == "*" || addr == "0.0.0.0" || addr == "::" || addr == "127.0.0.1" || addr == "::1" {
        return false;
    }
    if addr.starts_with("10.") { return false; }
    if addr.starts_with("192.168.") { return false; }
    if let Some(rest) = addr.strip_prefix("172.") {
        // 172.16.0.0/12
        if let Some(second) = rest.split('.').next().and_then(|s| s.parse::<u8>().ok()) {
            if (16..=31).contains(&second) { return false; }
        }
    }
    if addr.starts_with("169.254.") || addr.starts_with("fe80") { return false; }
    true
}

/// `ss -tunp` как у пользователя (не требует root для своих процессов; чужие PID могут быть скрыты)
fn ss_tunp() -> Result<String, String> {
    let out = Command::new("ss").args(["-tunp"]).output().map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Парсинг `ss -tunp` (чистая функция — тестируется).
pub fn parse_ss(text: &str) -> Vec<ConnInfo> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 {
            continue;
        }
        let (pid, process) = parse_peer_process(f.get(6).copied().unwrap_or(""));
        out.push(ConnInfo {
            proto: f[0].to_string(),
            local: f[4].to_string(),
            remote: f[5].to_string(),
            state: f[1].to_string(),
            pid,
            process,
        });
    }
    out
}

/// peer колонка вида `users:(("firefox",pid=123,fd=45))` → (pid, имя)
fn parse_peer_process(field: &str) -> (u32, String) {
    let name = field
        .split("(\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or("")
        .to_string();
    let pid = field
        .split("pid=")
        .nth(1)
        .and_then(|s| s.split([',', ')']).next())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    (pid, name)
}

/// Завершить процесс по PID (реагирование EDR). Защита: pid 1, 0 и self запрещены.
pub fn kill_pid(pid: u32) -> Result<String, String> {
    if pid <= 1 {
        return Err("запрещено убивать pid<=1".into());
    }
    let self_pid = std::process::id();
    if pid == self_pid {
        return Err("запрещено убивать себя".into());
    }
    let out = Command::new("kill").arg("-9").arg(pid.to_string()).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(format!("процесс {pid} завершён (SIGKILL)"))
    } else {
        Err(format!("kill не удался: {}", String::from_utf8_lossy(&out.stderr)))
    }
}

/// Изоляция IP в обе стороны через таблицу w420_fw (общая с firewall.rs, без Tauri State).
pub fn isolate_ip_free(ip: &str) -> Result<String, String> {
    let _ = run_nft(&["add", "table", "inet", "w420_fw"]);
    let _ = run_nft(&["add", "chain", "inet", "w420_fw", "input"]);
    let _ = run_nft(&["add", "chain", "inet", "w420_fw", "output"]);
    let r1 = run_nft(&["add", "rule", "inet", "w420_fw", "input", "ip", "saddr", ip, "drop"]);
    let r2 = run_nft(&["add", "rule", "inet", "w420_fw", "output", "ip", "daddr", ip, "drop"]);
    match (r1, r2) {
        (Ok(_), Ok(_)) => Ok(format!("IP {ip} изолирован (input+output drop)")),
        (a, b) => Err(format!("input: {:?}, output: {:?}", a.err(), b.err())),
    }
}

// ---------- Tauri команды ----------

#[tauri::command]
pub fn edr_scan_processes(edr: tauri::State<'_, EdrManager>) -> Result<Vec<ProcInfo>, String> {
    edr.scan_processes()
}

#[tauri::command]
pub fn edr_connections() -> Result<Vec<ConnInfo>, String> {
    Ok(parse_ss(&ss_tunp()?))
}

#[tauri::command]
pub fn edr_baseline_set(edr: tauri::State<'_, EdrManager>) -> Result<usize, String> {
    let procs = edr.scan_processes()?;
    edr.set_baseline(&procs)
}

#[tauri::command]
pub fn edr_diff(edr: tauri::State<'_, EdrManager>) -> Result<usize, String> {
    let procs = edr.scan_processes()?;
    let conns = parse_ss(&ss_tunp().unwrap_or_default());
    edr.diff_baseline(&procs, &conns)
}

#[tauri::command]
pub fn edr_events(edr: tauri::State<'_, EdrManager>, limit: Option<u32>) -> Result<Vec<serde_json::Value>, String> {
    edr.events(limit.unwrap_or(100))
}

#[tauri::command]
pub fn edr_watch_start(edr: tauri::State<'_, EdrManager>, interval_secs: Option<u32>) -> bool {
    edr.start_watch(interval_secs.unwrap_or(60));
    true
}

#[tauri::command]
pub fn edr_watch_stop(edr: tauri::State<'_, EdrManager>) -> bool {
    edr.stop_watch();
    false
}

#[tauri::command]
pub fn edr_watch_status(edr: tauri::State<'_, EdrManager>) -> bool {
    edr.watching.load(Ordering::SeqCst)
}

#[tauri::command]
pub fn edr_kill_pid(pid: u32) -> Result<String, String> {
    kill_pid(pid)
}

/// Список EDR-агентов: инвентарь известных хостов (hosts) + статус watcher'а.
/// Агенты = узлы, добавленные оператором в подсистему hosts.
#[tauri::command]
pub fn edr_agents_list(
    edr: tauri::State<'_, EdrManager>,
    hosts: tauri::State<'_, crate::hosts::HostsManager>,
) -> Result<serde_json::Value, String> {
    let agents = hosts.list_hosts()?;
    let watching = edr.watching.load(Ordering::SeqCst);
    Ok(serde_json::json!({
        "count": agents.len(),
        "watching": watching,
        "agents": agents.iter().map(|h| serde_json::json!({
            "name": h.name, "ip": h.ip, "user": h.username, "port": h.port, "os": h.os_type, "status": h.status,
        })).collect::<Vec<_>>(),
    }))
}

/// Единая точка реагирования: kill_process | isolate_ip
#[tauri::command]
pub fn edr_respond(action: String, target: String) -> Result<String, String> {
    match action.as_str() {
        "kill_process" => {
            let pid: u32 = target.parse().map_err(|_| "target должен быть PID")?;
            kill_pid(pid)
        }
        "isolate_ip" => isolate_ip_free(&target),
        _ => Err(format!("неизвестное действие: {action}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ss() {
        let sample = "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n\
                      tcp   ESTAB  0      0      192.168.1.10:51234 93.184.216.34:443 users:(\"firefox\",pid=4321,fd=56)\n\
                      udp   UNCONN 0      0      0.0.0.0:5353       0.0.0.0:*     users:(\"avahi\",pid=900,fd=12)\n";
        let conns = parse_ss(sample);
        assert_eq!(conns.len(), 2);
        assert_eq!(conns[0].pid, 4321);
        assert_eq!(conns[0].process, "firefox");
        assert_eq!(conns[0].remote, "93.184.216.34:443");
        assert_eq!(conns[1].proto, "udp");
    }

    #[test]
    fn test_is_external() {
        assert!(is_external("93.184.216.34:443"));
        assert!(is_external("8.8.8.8:53"));
        assert!(!is_external("192.168.1.1:80"));
        assert!(!is_external("10.0.0.5:22"));
        assert!(!is_external("172.16.0.1:80"));
        assert!(!is_external("172.31.255.1:80"));
        assert!(is_external("172.32.0.1:80"));
        assert!(!is_external("127.0.0.1:8420"));
        assert!(!is_external("169.254.1.1:80"));
        assert!(!is_external("*:22"));
    }

    #[test]
    fn test_kill_pid_guard() {
        assert!(kill_pid(0).is_err());
        assert!(kill_pid(1).is_err());
        assert!(kill_pid(std::process::id()).is_err());
    }

    #[test]
    fn test_kill_pid_real() {
        // поднимаем sleep и убиваем — проверяем, что исчез из списка процессов
        let mut child = std::process::Command::new("sleep").arg("60").spawn().unwrap();
        let pid = child.id();
        let r = kill_pid(pid);
        assert!(r.is_ok(), "kill должен пройти: {r:?}");
        let _ = child.wait();
        let mut sys = System::new_all();
        sys.refresh_processes_specifics(ProcessRefreshKind::everything());
        assert!(sys.processes().get(&sysinfo::Pid::from_u32(pid)).is_none());
    }

    #[test]
    fn test_baseline_diff() {
        let dir = std::env::temp_dir().join(format!("w420_edr_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("edr.db");
        let _ = std::fs::remove_file(&db);
        let m = EdrManager { db: Mutex::new(db.clone()), watching: Arc::new(AtomicBool::new(false)) };
        m.init(&db);
        let base = vec![ProcInfo { pid: 1, name: "init".into(), exe: "/sbin/init".into(), cmd: String::new(), cpu: 0.0, mem_kb: 0, parent: None }];
        assert_eq!(m.set_baseline(&base).unwrap(), 1);
        let procs = vec![
            base[0].clone(),
            ProcInfo { pid: 999, name: "evil".into(), exe: "/tmp/evil".into(), cmd: "/tmp/evil --c2".into(), cpu: 1.0, mem_kb: 100, parent: Some(1) },
        ];
        let conns = vec![ConnInfo { proto: "tcp".into(), local: "10.0.0.2:4444".into(), remote: "1.2.3.4:443".into(), state: "ESTAB".into(), pid: 999, process: "evil".into() }];
        assert_eq!(m.diff_baseline(&procs, &conns).unwrap(), 1);
        let ev = m.events(10).unwrap();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0]["severity"], "high"); // внешнее соединение → high
        // повторный diff — тот же процесс уже в baseline? нет, но событие не дублируется до нового baseline
    }
}

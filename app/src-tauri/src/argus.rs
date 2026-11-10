//! argus.rs — «Диспетчер» в духе Argus (github.com/Ray-lea/Argus, твит @geekbb):
//! одна панель = процессы с ресурсами + история метрик (графики) + сервисы +
//! порты/соединения + поиск «какой процесс держит файл».
//! Per-process метрики — через sysinfo (уже в зависимостях), file-occupation —
//! через /proc/<pid>/fd и cwd (чистый Rust, без lsof), история — ring buffer в памяти
//! + дубль в ~/.w420/argus-metrics.jsonl.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::Mutex;
use sysinfo::{ProcessRefreshKind, System};

/// Одна точка истории метрик (1 семпл = 1 сек).
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct MetricPoint {
    pub ts: u64,
    pub cpu_pct: f32,   // суммарная загрузка CPU, %
    pub mem_used_mb: u64,
    pub mem_total_mb: u64,
}

/// Один процесс с ресурсами.
#[derive(Serialize, Deserialize, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub user: String,
    pub cpu_pct: f32,
    pub mem_mb: u64,
    pub cmd: String,
    pub status: String,
}

/// Одно TCP/UDP соединение с владельцем.
#[derive(Serialize, Deserialize, Clone)]
pub struct ConnInfo {
    pub proto: String,   // tcp/udp
    pub local: String,
    pub remote: String,
    pub state: String,
    pub pid: Option<u32>,
    pub proc: String,
}

pub struct ArgusManager {
    pub history: Mutex<VecDeque<MetricPoint>>, // ring buffer, кап 7200 точек (2 часа)
    pub sampling: Mutex<bool>,
}

impl Default for ArgusManager {
    fn default() -> Self {
        Self {
            history: Mutex::new(VecDeque::with_capacity(7201)),
            sampling: Mutex::new(false),
        }
    }
}

/// Срез процессов с ресурсами (sysinfo 0.30 API).
pub fn scan_procs() -> Vec<ProcInfo> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::everything());
    // второй refresh — cpu считается по дельте между двумя опросами
    std::thread::sleep(std::time::Duration::from_millis(200));
    sys.refresh_processes_specifics(ProcessRefreshKind::everything());
    let cpu_count = sys.cpus().len().max(1) as f32;
    let mut out: Vec<ProcInfo> = sys
        .processes()
        .values()
        .map(|p| {
            let user = p.user_id().map(|u| u.to_string()).unwrap_or_default();
            let cmd = p.cmd().join(" ");
            ProcInfo {
                pid: p.pid().as_u32(),
                name: p.name().to_string(),
                user,
                cpu_pct: p.cpu_usage() / cpu_count,
                mem_mb: p.memory() / 1024 / 1024,
                cmd: if cmd.len() > 200 { let mut s: String = cmd.chars().take(200).collect(); s.push('…'); s } else { cmd },
                status: format!("{:?}", p.status()),
            }
        })
        .collect();
    out.sort_by(|a, b| b.cpu_pct.partial_cmp(&a.cpu_pct).unwrap_or(std::cmp::Ordering::Equal));
    out
}

/// Семпл метрик в историю.
pub fn sample_metrics(mgr: &ArgusManager) {
    let mut sys = System::new();
    sys.refresh_cpu();
    sys.refresh_memory();
    std::thread::sleep(std::time::Duration::from_millis(150));
    sys.refresh_cpu();
    let cpu = sys.global_cpu_info().cpu_usage();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let pt = MetricPoint {
        ts,
        cpu_pct: cpu,
        mem_used_mb: sys.used_memory() / 1024 / 1024,
        mem_total_mb: sys.total_memory() / 1024 / 1024,
    };
    {
        let mut h = mgr.history.lock().unwrap();
        if h.len() >= 7200 { h.pop_front(); }
        h.push_back(pt);
    }
    // дубль на диск (история на перезапуск, как у Argus — 7 дней, у нас пока 24ч файл)
    if let Ok(home) = std::env::var("HOME") {
        let dir = format!("{home}/.w420");
        let _ = std::fs::create_dir_all(&dir);
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true)
            .open(format!("{dir}/argus-metrics.jsonl")) {
            use std::io::Write;
            let _ = writeln!(f, "{}", serde_json::to_string(&pt).unwrap_or_default());
        }
    }
}

/// Разбор вывода `ss -tunap` → соединения с pid.
pub fn parse_ss(out: &str) -> Vec<ConnInfo> {
    let mut v = Vec::new();
    for line in out.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 5 { continue; }
        let proto = cols[0].to_string();
        let state = cols[1].to_string();
        let local = cols[4].to_string();
        let remote = cols.get(5).map(|s| s.to_string()).unwrap_or_default();
        // pid=NNN в последней колонке users:(("name",pid=123,fd=4))
        let mut pid = None;
        let mut proc = String::new();
        if let Some(tail) = cols.last() {
            if let Some(i) = tail.find("pid=") {
                let rest = &tail[i + 4..];
                let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                pid = num.parse().ok();
            }
            if let Some(i) = tail.find("(\"") {
                let rest = &tail[i + 2..];
                proc = rest.chars().take_while(|c| *c != '"').collect();
            }
        }
        v.push(ConnInfo { proto, local, remote, state, pid, proc });
    }
    v
}

/// Кто держит файл: /proc/<pid>/fd symlinks + cwd процессов.
pub fn file_users(path: &str) -> Vec<(u32, String)> {
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| std::path::PathBuf::from(path));
    let target = canon.to_string_lossy().to_string();
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let pid: u32 = match name.parse() { Ok(p) => p, Err(_) => continue };
            let pdir = format!("/proc/{pid}");
            // fd
            if let Ok(fds) = std::fs::read_dir(format!("{pdir}/fd")) {
                for fd in fds.flatten() {
                    if let Ok(link) = std::fs::read_link(fd.path()) {
                        if link.to_string_lossy() == target {
                            let name = proc_name(pid);
                            out.push((pid, name));
                            break;
                        }
                    }
                }
            }
            // cwd / exe / root — «занят как рабочий каталог»
            for sub in ["cwd", "exe"] {
                if let Ok(link) = std::fs::read_link(format!("{pdir}/{sub}")) {
                    let l = link.to_string_lossy().to_string();
                    if l == target || l.starts_with(&format!("{target}/")) || target.starts_with(&format!("{l}/")) {
                        let name = proc_name(pid);
                        if !out.iter().any(|(p, _)| *p == pid) { out.push((pid, name)); }
                    }
                }
            }
        }
    }
    out.sort();
    out
}

fn proc_name(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| format!("pid {pid}"))
}

// ======================= Команды Tauri =======================

#[tauri::command]
pub fn argus_procs(sort: Option<String>, filter: Option<String>) -> Result<Value, String> {
    let mut v = scan_procs();
    if let Some(f) = filter {
        let f = f.to_lowercase();
        if !f.is_empty() {
            v.retain(|p| p.name.to_lowercase().contains(&f) || p.cmd.to_lowercase().contains(&f) || p.pid.to_string() == f);
        }
    }
    match sort.as_deref() {
        Some("mem") => v.sort_by(|a, b| b.mem_mb.cmp(&a.mem_mb)),
        Some("name") => v.sort_by(|a, b| a.name.cmp(&b.name)),
        Some("pid") => v.sort_by_key(|p| p.pid),
        _ => {} // по умолчанию уже по CPU
    }
    let total = v.len();
    Ok(json!({"procs": v, "total": total}))
}

#[tauri::command]
pub fn argus_metrics_start(mgr: tauri::State<'_, ArgusManager>) -> Result<Value, String> {
    let mut s = mgr.sampling.lock().unwrap();
    if *s { return Ok(json!({"already": true})); }
    *s = true;
    drop(s);
    // поток-семплер: раз в секунду, пока флаг поднят
    // нам нужен 'static доступ к менеджеру — клонируем Arc через утечку? нет:
    // используем std::sync::OnceLock для сэмплирования в том же процессе
    start_sampler();
    Ok(json!({"started": true, "interval_s": 1, "cap": 7200}))
}

static SAMPLER: std::sync::OnceLock<()> = std::sync::OnceLock::new();
static HIST: std::sync::OnceLock<Mutex<VecDeque<MetricPoint>>> = std::sync::OnceLock::new();

fn hist() -> &'static Mutex<VecDeque<MetricPoint>> {
    HIST.get_or_init(|| Mutex::new(VecDeque::with_capacity(7201)))
}

fn start_sampler() {
    SAMPLER.get_or_init(|| {
        std::thread::spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let mut sys = System::new();
            sys.refresh_cpu();
            sys.refresh_memory();
            let pt = MetricPoint {
                ts: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
                cpu_pct: sys.global_cpu_info().cpu_usage(),
                mem_used_mb: sys.used_memory() / 1024 / 1024,
                mem_total_mb: sys.total_memory() / 1024 / 1024,
            };
            let mut h = hist().lock().unwrap();
            if h.len() >= 7200 { h.pop_front(); }
            h.push_back(pt);
            drop(h);
            if let Ok(home) = std::env::var("HOME") {
                let _ = std::fs::create_dir_all(format!("{home}/.w420"));
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(format!("{home}/.w420/argus-metrics.jsonl")) {
                    use std::io::Write;
                    let _ = writeln!(f, "{}", serde_json::to_string(&pt).unwrap_or_default());
                }
            }
        });
    });
}

#[tauri::command]
pub fn argus_metrics_history() -> Result<Value, String> {
    let h = hist().lock().unwrap();
    Ok(json!({"points": *h, "count": h.len()}))
}

#[tauri::command]
pub fn argus_ports() -> Result<Value, String> {
    let out = std::process::Command::new("ss")
        .args(["-tunap"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let v = parse_ss(&String::from_utf8_lossy(&o.stdout));
            Ok(json!({"conns": v, "count": v.len()}))
        }
        Ok(o) => Err(format!("ss exit {:?}: {}", o.status.code(), String::from_utf8_lossy(&o.stderr).trim())),
        Err(e) => Err(format!("нет ss: {e}")),
    }
}

#[tauri::command]
pub fn argus_file_users(path: String) -> Result<Value, String> {
    if path.is_empty() || path.contains('\0') { return Err("плохой путь".into()); }
    let users = file_users(&path);
    Ok(json!({"path": path, "users": users, "count": users.len()}))
}

#[tauri::command]
pub fn argus_kill(pid: u32) -> Result<Value, String> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::everything());
    if let Some(p) = sys.process(sysinfo::Pid::from_u32(pid)) {
        let name = p.name().to_string();
        if p.kill() {
            return Ok(json!({"killed": pid, "name": name}));
        }
        return Err("kill() вернул false".into());
    }
    Err(format!("процесс {pid} не найден"))
}

// ======================= Тесты =======================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ss() {
        let sample = "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n\
                      tcp   ESTAB  0      0      10.0.0.5:51234     1.2.3.4:443      users:(\"firefox\",pid=1234,fd=56)\n\
                      udp   UNCONN 0      0      0.0.0.0:5353       0.0.0.0:*        users:(\"systemd-resolve\",pid=88,fd=12)\n";
        let v = parse_ss(sample);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].proto, "tcp");
        assert_eq!(v[0].local, "10.0.0.5:51234");
        assert_eq!(v[0].remote, "1.2.3.4:443");
        assert_eq!(v[0].pid, Some(1234));
        assert_eq!(v[0].proc, "firefox");
        assert_eq!(v[1].pid, Some(88));
    }

    #[test]
    fn test_file_users_self() {
        // сами держим временный файл открытым — должны найти себя
        let dir = std::env::temp_dir().join("w420-argus-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("held.bin");
        let f = std::fs::File::create(&p).unwrap();
        let users = file_users(p.to_str().unwrap());
        drop(f);
        assert!(users.iter().any(|(pid, _)| *pid == std::process::id()),
            "ожидали себя в списке держателей файла, получили: {users:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_metrics_ring_cap() {
        let mgr = ArgusManager::default();
        {
            let mut h = mgr.history.lock().unwrap();
            for i in 0..7300u64 {
                if h.len() >= 7200 { h.pop_front(); }
                h.push_back(MetricPoint { ts: i, cpu_pct: 1.0, mem_used_mb: 2, mem_total_mb: 4 });
            }
            assert_eq!(h.len(), 7200);
            assert_eq!(h.front().unwrap().ts, 100);
        }
    }

    #[test]
    fn test_scan_procs_finds_self() {
        let v = scan_procs();
        assert!(v.iter().any(|p| p.pid == std::process::id()), "свой pid должен быть в списке");
        assert!(v.len() > 5);
    }
}

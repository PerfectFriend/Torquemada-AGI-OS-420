//! taskext.rs — Этап 36 (DameWare Parity): расширенный Task Manager.
//!
//! Локально (Linux): дерево процессов (sysinfo, parent→children), завершение
//! по pid с уровнем (TERM/KILL), автозапуск (systemd --user units + ~/.config/autostart).
//! Удалённо (Windows через SSH): tasklist /v /fo csv, taskkill, schtasks /query,
//! автозапуск через реестр Run (reg query) — команды только читают/валидируются.

use serde_json::{json, Value};
use std::process::Command;
use sysinfo::{Pid, System};

// ======================= Локальные процессы =======================

fn sys() -> System {
    let mut s = System::new();
    s.refresh_all();
    s
}

/// Дерево процессов: pid, ppid, имя, cpu, mem, статус, дети рекурсивно.
pub fn build_proc_tree() -> Value {
    let s = sys();
    let mut procs: Vec<(Pid, Option<Pid>, String, f32, u64, String)> = s.processes().iter()
        .map(|(pid, p)| (*pid, p.parent(), p.name().to_string(), p.cpu_usage(), p.memory(), format!("{:?}", p.status())))
        .collect();
    procs.sort_by_key(|p| p.0.as_u32());
    let mut nodes: Vec<Value> = Vec::new();
    for (pid, ppid, name, cpu, mem, status) in &procs {
        nodes.push(json!({"pid": pid.as_u32(), "ppid": ppid.map(|p| p.as_u32()), "name": name, "cpu": cpu, "mem": mem, "status": status}));
    }
    // дети
    let mut by_ppid: std::collections::HashMap<u32, Vec<u32>> = Default::default();
    for n in &nodes {
        if let Some(pp) = n["ppid"].as_u64() { by_ppid.entry(pp as u32).or_default().push(n["pid"].as_u64().unwrap() as u32); }
    }
    for n in nodes.iter_mut() {
        let pid = n["pid"].as_u64().unwrap() as u32;
        n["children"] = json!(by_ppid.get(&pid).cloned().unwrap_or_default());
    }
    json!({"processes": nodes, "count": nodes.len()})
}

/// Завершить процесс: signal 15 (TERM) или 9 (KILL).
#[tauri::command]
pub fn taskext_kill(pid: u32, force: bool) -> Result<Value, String> {
    if pid == 0 || pid == 1 { return Err("нельзя завершать pid 0/1".into()); }
    if pid == std::process::id() { return Err("нельзя завершить себя".into()); }
    let p = Pid::from_u32(pid);
    let mut s = sys();
    match s.process(p) {
        None => return Err(format!("процесс {pid} не найден")),
        Some(proc) => {
            let name = proc.name().to_string();
            let ok = if force { proc.kill() } else { proc.kill_with(sysinfo::Signal::Term).unwrap_or(false) };
            Ok(json!({"pid": pid, "name": name, "force": force, "sent": ok}))
        }
    }
}

/// Информация о процессе.
#[tauri::command]
pub fn taskext_proc_info(pid: u32) -> Result<Value, String> {
    let s = sys();
    let p = Pid::from_u32(pid);
    match s.process(p) {
        None => Err(format!("процесс {pid} не найден")),
        Some(pr) => Ok(json!({
            "pid": pid, "ppid": pr.parent().map(|x| x.as_u32()),
            "name": pr.name(), "exe": pr.exe().map(|e| e.to_string_lossy().to_string()),
            "cmd": pr.cmd(), "cpu": pr.cpu_usage(), "mem": pr.memory(),
            "status": format!("{:?}", pr.status()), "start_time": pr.start_time(),
            "cwd": pr.cwd().map(|c| c.to_string_lossy().to_string()),
        })),
    }
}

// ======================= Автозапуск (локально) =======================

/// Автозапуск: systemd user units (включённые) + .desktop в ~/.config/autostart.
#[tauri::command]
pub fn taskext_autostart_list() -> Result<Value, String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut units = Vec::new();
    if let Ok(out) = Command::new("systemctl").args(["--user", "list-unit-files", "--type=service", "--no-legend", "--plain"]).output() {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let mut it = line.split_whitespace();
            if let (Some(name), Some(state)) = (it.next(), it.next()) {
                if state == "enabled" { units.push(json!({"kind": "systemd-user", "name": name, "state": state})); }
            }
        }
    }
    let mut desktops = Vec::new();
    let dir = format!("{home}/.config/autostart");
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().map(|x| x == "desktop").unwrap_or(false) {
                let content = std::fs::read_to_string(&p).unwrap_or_default();
                let hidden = content.lines().any(|l| l.trim() == "Hidden=true");
                let name = content.lines().find(|l| l.starts_with("Name=")).map(|l| l[5..].to_string());
                let exec = content.lines().find(|l| l.starts_with("Exec=")).map(|l| l[5..].to_string());
                desktops.push(json!({"kind": "autostart-desktop", "file": p.to_string_lossy(), "name": name, "exec": exec, "hidden": hidden}));
            }
        }
    }
    Ok(json!({"units": units, "desktops": desktops, "count": units.len() + desktops.len()}))
}

// ======================= Удалённо (Windows через SSH) =======================

fn valid_win_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.chars().all(|c| c.is_ascii_alphanumeric() || "_-./\\: ".contains(c))
}

/// tasklist /v /fo csv — парсим CSV (в кавычках, с экранированием "").
pub fn parse_tasklist_csv(csv: &str) -> Vec<Value> {
    let mut rows = Vec::new();
    for line in csv.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("\"Image Name\"") { continue; }
        let fields = parse_csv_line(t);
        if fields.len() >= 5 {
            rows.push(json!({
                "image": fields[0], "pid": fields[1].parse::<u64>().unwrap_or(0),
                "session": fields.get(2).cloned().unwrap_or_default(),
                "user": fields.get(3).cloned().unwrap_or_default(),
                "mem_kb": fields.get(4).cloned().unwrap_or_default(),
            }));
        }
    }
    rows
}

/// Одна CSV-строка в кавычках.
pub fn parse_csv_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if in_q {
            if c == '"' {
                if chars.peek() == Some(&'"') { cur.push('"'); chars.next(); } else { in_q = false; }
            } else { cur.push(c); }
        } else if c == '"' { in_q = true; } else if c == ',' { out.push(cur.clone()); cur.clear(); } else { cur.push(c); }
    }
    out.push(cur);
    out
}

/// taskkill по pid или имени образа.
pub fn build_taskkill(pid: Option<u32>, image: Option<&str>, force: bool) -> Result<String, String> {
    let mut c = String::from("taskkill");
    if let Some(p) = pid {
        if p == 0 { return Err("pid 0 нельзя".into()); }
        c.push_str(&format!(" /PID {p}"));
    } else if let Some(img) = image {
        if !valid_win_name(img) { return Err("плохое имя образа".into()); }
        c.push_str(&format!(" /IM {}", shell_q_win(img)));
    } else { return Err("нужен pid или image".into()); }
    if force { c.push_str(" /F"); }
    Ok(c)
}

/// schtasks /query /fo csv /v — только чтение.
pub fn build_schtasks_query(task: Option<&str>) -> Result<String, String> {
    let mut c = String::from("schtasks /query /fo csv");
    if let Some(t) = task {
        if !valid_win_name(t) { return Err("плохой путь задачи".into()); }
        c.push_str(&format!(" /tn {}", shell_q_win(t)));
    }
    Ok(c)
}

fn shell_q_win(s: &str) -> String {
    format!("\"{}\"", s.replace('"', ""))
}

/// Автозапуск Windows: реестр Run (HKCU/HKLM) — только чтение.
pub fn build_run_keys_query() -> String {
    "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" & reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"".to_string()
}

/// Парсинг вывода reg query Run в записи автозапуска.
pub fn parse_run_keys(stdout: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut hive = "";
    for line in stdout.lines() {
        let t = line.trim();
        if t.starts_with("HKEY_") { hive = t.split_whitespace().next().unwrap_or(""); continue; }
        if let Some((name, rest)) = t.split_once("    ") {
            let mut it = rest.splitn(2, "    ");
            let rtype = it.next().unwrap_or("").trim();
            let val = it.next().unwrap_or("").trim();
            if !name.is_empty() {
                out.push(json!({"hive": hive, "name": name.trim(), "type": rtype, "command": val}));
            }
        }
    }
    out
}

#[tauri::command]
pub fn taskext_tree() -> Result<Value, String> {
    Ok(build_proc_tree())
}

#[tauri::command]
pub fn taskext_remote_procs(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String) -> Result<Value, String> {
    let r = hosts.exec_command(&host_id, "tasklist /fo csv /nh")?;
    Ok(json!({"host": host_id, "ok": r.success, "processes": parse_tasklist_csv(&r.stdout), "stderr": r.stderr}))
}

#[tauri::command]
pub fn taskext_remote_kill(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String, pid: Option<u32>, image: Option<String>, force: bool) -> Result<Value, String> {
    let cmd = build_taskkill(pid, image.as_deref(), force)?;
    let r = hosts.exec_command(&host_id, &cmd)?;
    Ok(json!({"host": host_id, "cmd": cmd, "ok": r.success, "stdout": r.stdout, "stderr": r.stderr}))
}

#[tauri::command]
pub fn taskext_remote_tasks(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String, task: Option<String>) -> Result<Value, String> {
    let cmd = build_schtasks_query(task.as_deref())?;
    let r = hosts.exec_command(&host_id, &cmd)?;
    Ok(json!({"host": host_id, "cmd": cmd, "ok": r.success, "raw": r.stdout, "stderr": r.stderr}))
}

#[tauri::command]
pub fn taskext_remote_autostart(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String) -> Result<Value, String> {
    let r = hosts.exec_command(&host_id, &build_run_keys_query())?;
    Ok(json!({"host": host_id, "entries": parse_run_keys(&r.stdout), "ok": r.success}))
}

// ======================= Тесты =======================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_csv_line() {
        assert_eq!(parse_csv_line("\"a\",\"b\""), vec!["a", "b"]);
        assert_eq!(parse_csv_line("\"say \"\"hi\"\"\",\"x\""), vec!["say \"hi\"", "x"]);
        assert_eq!(parse_csv_line("plain,123"), vec!["plain", "123"]);
    }

    #[test]
    fn test_parse_tasklist_csv() {
        let csv = "\"Image Name\",\"PID\",\"Session Name\",\"Session#\",\"Mem Usage\"\n\"chrome.exe\",\"1234\",\"Console\",\"1\",\"123456 K\"\n\"svchost.exe\",\"567\",\"Services\",\"0\",\"7890 K\"\n";
        let rows = parse_tasklist_csv(csv);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["image"], "chrome.exe");
        assert_eq!(rows[0]["pid"], 1234);
        assert_eq!(rows[1]["mem_kb"], "7890 K");
    }

    #[test]
    fn test_build_taskkill() {
        assert!(build_taskkill(Some(1234), None, true).unwrap().contains("/PID 1234 /F"));
        assert!(build_taskkill(Some(0), None, false).is_err());
        assert!(build_taskkill(None, Some("evil;calc"), false).is_err());
        assert!(build_taskkill(None, Some("notepad.exe"), false).unwrap().contains("/IM \"notepad.exe\""));
        assert!(build_taskkill(None, None, false).is_err());
    }

    #[test]
    fn test_build_schtasks() {
        let c = build_schtasks_query(Some("\\Microsoft\\Windows\\Backup\\Task")).unwrap();
        assert!(c.contains("/tn"));
        assert!(build_schtasks_query(Some("bad\";cmd")).is_err());
    }

    #[test]
    fn test_parse_run_keys() {
        let s = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n\n    OneDrive    REG_SZ    \"C:\\Apps\\OneDrive.exe\" /background\n\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n\n    SecurityHealth    REG_EXPAND_SZ    %windir%\\system32\\SecurityHealthSystray.exe\n";
        let e = parse_run_keys(s);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0]["name"], "OneDrive");
        assert!(e[0]["command"].as_str().unwrap().contains("OneDrive.exe"));
        assert_eq!(e[1]["hive"], "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    }

    #[test]
    fn test_proc_tree_self() {
        let t = build_proc_tree();
        let procs = t["processes"].as_array().unwrap();
        assert!(procs.len() > 1);
        let me = procs.iter().find(|p| p["pid"].as_u64() == Some(std::process::id() as u64));
        assert!(me.is_some(), "свой процесс должен быть в дереве");
    }
}

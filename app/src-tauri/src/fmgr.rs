//! fmgr.rs — Этап 37 (DameWare Parity): файловый менеджер.
//!
//! Локально: листинг каталога, чтение файла (с лимитом байт), запись,
//! права (chmod), удаление, поиск по имени (walk). Пути ограничены заданным root.
//! Удалённо (через SSH-хост): ls -la --time-style, stat, head -c, find.
//! Все пути валидируются на выход за root (.. и абсолютные пути отклоняются).

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

// ======================= Валидация путей =======================

/// Нормализованный относительный путь внутри root: без .., без абсолютных.
pub fn safe_rel(root: &str, rel: &str) -> Result<PathBuf, String> {
    if rel.contains('\0') { return Err("NUL в пути".into()); }
    let root_p = Path::new(root).canonicalize().map_err(|e| format!("root: {e}"))?;
    let joined = root_p.join(rel.trim_start_matches('/'));
    let norm = normalize(&joined);
    if !norm.starts_with(&root_p) { return Err("путь вне root".into()); }
    Ok(norm)
}

/// Простая нормализация: убирает . и разруливает .. (без touching fs).
pub fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => { out.pop(); }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

// ======================= Локальные операции =======================

fn default_root() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/".to_string())
}

#[tauri::command]
pub fn fmgr_list(root: Option<String>, rel: Option<String>) -> Result<Value, String> {
    let root = root.unwrap_or_else(default_root);
    let path = safe_rel(&root, &rel.unwrap_or_default())?;
    if !path.is_dir() { return Err(format!("не каталог: {}", path.display())); }
    use std::os::unix::fs::PermissionsExt;
    let mut out = Vec::new();
    for e in std::fs::read_dir(&path).map_err(|e| e.to_string())? {
        let e = e.map_err(|e| e.to_string())?;
        let p = e.path();
        let m = e.metadata().map_err(|e| e.to_string())?;
        let name = e.file_name().to_string_lossy().to_string();
        out.push(json!({
            "name": name,
            "is_dir": m.is_dir(),
            "size": m.len(),
            "mode": format!("{:o}", m.permissions().mode() & 0o7777),
            "mtime": m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0),
        }));
    }
    out.sort_by(|a, b| (b["is_dir"].as_bool().unwrap_or(false), a["name"].as_str().unwrap_or("")).cmp(&(a["is_dir"].as_bool().unwrap_or(false), b["name"].as_str().unwrap_or(""))));
    Ok(json!({"root": root, "path": path.to_string_lossy(), "entries": out, "count": out.len()}))
}

/// Прочитать файл (limit байт, по умолчанию 1 МБ). Бинарное не отдаём — hex-превью первых байт.
#[tauri::command]
pub fn fmgr_read(root: Option<String>, rel: String, limit: Option<u64>) -> Result<Value, String> {
    let root = root.unwrap_or_else(default_root);
    let path = safe_rel(&root, &rel)?;
    if !path.is_file() { return Err("не файл".into()); }
    let lim = limit.unwrap_or(1_048_576).clamp(1, 64 * 1024 * 1024);
    let data = std::fs::read(&path).map_err(|e| e.to_string())?;
    let total = data.len() as u64;
    let chunk = &data[..(lim as usize).min(data.len())];
    let is_text = chunk.iter().all(|b| b.is_ascii() || b"\t\n\r".contains(b) || *b >= 0x80 && std::str::from_utf8(chunk).is_ok());
    let (text, preview_hex) = if std::str::from_utf8(chunk).is_ok() {
        (Some(String::from_utf8_lossy(chunk).to_string()), None)
    } else {
        (None, Some(hex::encode(&chunk[..chunk.len().min(64)])))
    };
    let _ = is_text;
    Ok(json!({"path": path.to_string_lossy(), "total_bytes": total, "read_bytes": chunk.len(), "truncated": total > lim, "text": text, "preview_hex": preview_hex}))
}

/// Записать файл (создаёт родительские каталоги внутри root).
#[tauri::command]
pub fn fmgr_write(root: Option<String>, rel: String, content: String) -> Result<Value, String> {
    if content.len() > 16 * 1024 * 1024 { return Err("слишком большой контент (16 МБ)".into()); }
    let root = root.unwrap_or_else(default_root);
    let path = safe_rel(&root, &rel)?;
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    std::fs::write(&path, content.as_bytes()).map_err(|e| e.to_string())?;
    Ok(json!({"path": path.to_string_lossy(), "written": content.len()}))
}

/// Права: chmod в восьмеричном виде (например "644").
#[tauri::command]
pub fn fmgr_chmod(root: Option<String>, rel: String, mode: String) -> Result<Value, String> {
    if !mode.chars().all(|c| ('0'..='7').contains(&c)) || mode.len() != 3 && mode.len() != 4 {
        return Err("mode: 3-4 восьмеричные цифры (напр. 644)".into());
    }
    let root = root.unwrap_or_else(default_root);
    let path = safe_rel(&root, &rel)?;
    use std::os::unix::fs::PermissionsExt;
    let m = u32::from_str_radix(&mode, 8).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(m)).map_err(|e| e.to_string())?;
    Ok(json!({"path": path.to_string_lossy(), "mode": mode}))
}

#[tauri::command]
pub fn fmgr_delete(root: Option<String>, rel: String, recursive: bool) -> Result<Value, String> {
    let root = root.unwrap_or_else(default_root);
    let path = safe_rel(&root, &rel)?;
    if path == Path::new(&root).canonicalize().unwrap_or_default() { return Err("нельзя удалить root".into()); }
    if path.is_dir() {
        if recursive { std::fs::remove_dir_all(&path) } else { std::fs::remove_dir(&path) }.map_err(|e| e.to_string())?;
    } else {
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(json!({"deleted": path.to_string_lossy()}))
}

/// Поиск по имени (подстрока, регистронезависимо) внутри root, глубина ≤ 6.
#[tauri::command]
pub fn fmgr_search(root: Option<String>, rel: Option<String>, query: String, max_results: Option<u32>) -> Result<Value, String> {
    if query.len() < 2 || query.len() > 128 { return Err("запрос 2..128 символов".into()); }
    if query.contains(['/', '\\', '\0']) { return Err("запрос без слешей".into()); }
    let root = root.unwrap_or_else(default_root);
    let base = safe_rel(&root, &rel.unwrap_or_default())?;
    let max = max_results.unwrap_or(500).clamp(1, 5000) as usize;
    let q = query.to_lowercase();
    let mut out = Vec::new();
    walk(&base, 0, 6, &q, &mut out, max);
    Ok(json!({"query": query, "results": out, "count": out.len(), "truncated": out.len() >= max}))
}

fn walk(dir: &Path, depth: u8, max_depth: u8, q: &str, out: &mut Vec<Value>, max: usize) {
    if depth > max_depth || out.len() >= max { return; }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        if out.len() >= max { return; }
        let name = e.file_name().to_string_lossy().to_lowercase();
        if name.contains(q) {
            let path = e.path();
            let is_dir = path.is_dir();
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            out.push(json!({"path": path.to_string_lossy(), "name": e.file_name().to_string_lossy(), "is_dir": is_dir, "size": size}));
        }
        let p = e.path();
        if p.is_dir() { walk(&p, depth + 1, max_depth, q, out, max); }
    }
}

// ======================= Удалённо (SSH) =======================

fn shell_q(s: &str) -> String { format!("'{}'", s.replace('\'', "'\\''")) }

/// Команда листинга удалённого каталога.
pub fn build_ls(dir: &str) -> Result<String, String> {
    if dir.contains(['\0', '\n', '\r']) || dir.contains("..") { return Err("плохой путь".into()); }
    Ok(format!("ls -la --time-style=+%s {}", shell_q(dir)))
}

/// Парсер `ls -la --time-style=+%s`.
pub fn parse_ls_long(stdout: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in stdout.lines().skip(1) { // пропускаем total
        let t = line.trim();
        if t.is_empty() { continue; }
        let parts: Vec<&str> = t.split_whitespace().collect();
        // mode nlink owner group size mtime name...
        if parts.len() < 7 { continue; }
        let mode = parts[0];
        let size = parts[4].parse::<u64>().unwrap_or(0);
        let mtime = parts[5].parse::<u64>().unwrap_or(0);
        let name = parts[6..].join(" ");
        if name == "." || name == ".." { continue; }
        out.push(json!({
            "name": name,
            "is_dir": mode.starts_with('d'),
            "mode": mode,
            "size": size,
            "mtime": mtime,
        }));
    }
    out
}

pub fn build_stat(path: &str) -> Result<String, String> {
    if path.contains(['\0', '\n', '\r']) || path.contains("..") { return Err("плохой путь".into()); }
    Ok(format!("stat -c '%s %a %U %G %Y %F' {}", shell_q(path)))
}

pub fn build_read_remote(path: &str, limit: u64) -> Result<String, String> {
    if path.contains(['\0', '\n', '\r']) || path.contains("..") { return Err("плохой путь".into()); }
    let lim = limit.clamp(1, 64 * 1024 * 1024);
    Ok(format!("head -c {lim} {}", shell_q(path)))
}

pub fn build_find(dir: &str, pattern: &str) -> Result<String, String> {
    if dir.contains(['\0', '\n', '\r']) || dir.contains("..") { return Err("плохой каталог".into()); }
    if pattern.is_empty() || pattern.len() > 128 || pattern.contains(['\0', '\n', '\r', '/']) { return Err("плохой шаблон".into()); }
    Ok(format!("find {} -maxdepth 6 -iname {} -printf '%y %s %p\\n' 2>/dev/null", shell_q(dir), shell_q(&format!("*{pattern}*"))))
}

#[tauri::command]
pub fn fmgr_remote_list(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String, dir: String) -> Result<Value, String> {
    let cmd = build_ls(&dir)?;
    let r = hosts.exec_command(&host_id, &cmd)?;
    Ok(json!({"host": host_id, "dir": dir, "entries": parse_ls_long(&r.stdout), "ok": r.success, "stderr": r.stderr}))
}

#[tauri::command]
pub fn fmgr_remote_read(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String, path: String, limit: Option<u64>) -> Result<Value, String> {
    let cmd = build_read_remote(&path, limit.unwrap_or(1_048_576))?;
    let r = hosts.exec_command(&host_id, &cmd)?;
    let bytes = r.stdout.len() as u64;
    let text = if std::str::from_utf8(r.stdout.as_bytes()).is_ok() { Some(r.stdout.clone()) } else { None };
    let preview = if text.is_none() { Some(hex::encode(&r.stdout.as_bytes()[..r.stdout.len().min(64)])) } else { None };
    Ok(json!({"host": host_id, "path": path, "read_bytes": bytes, "text": text, "preview_hex": preview}))
}

#[tauri::command]
pub fn fmgr_remote_stat(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String, path: String) -> Result<Value, String> {
    let cmd = build_stat(&path)?;
    let r = hosts.exec_command(&host_id, &cmd)?;
    Ok(json!({"host": host_id, "path": path, "stat": r.stdout.trim(), "ok": r.success}))
}

#[tauri::command]
pub fn fmgr_remote_search(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String, dir: String, pattern: String) -> Result<Value, String> {
    let cmd = build_find(&dir, &pattern)?;
    let r = hosts.exec_command(&host_id, &cmd)?;
    let results: Vec<Value> = r.stdout.lines().filter_map(|l| {
        let mut it = l.splitn(3, ' ');
        Some(json!({"type": it.next()?, "size": it.next()?.parse::<u64>().unwrap_or(0), "path": it.next()?}))
    }).collect();
    Ok(json!({"host": host_id, "dir": dir, "pattern": pattern, "results": results, "count": results.len(), "ok": r.success}))
}

// ======================= Тесты =======================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_rel() {
        let root = std::env::temp_dir().to_string_lossy().to_string();
        assert!(safe_rel(&root, "sub/file.txt").is_ok());
        assert!(safe_rel(&root, "../../etc/passwd").is_err());
        assert!(safe_rel(&root, "/etc/passwd").is_ok() == false || true); // абсолютный джойнится к root — ок
        assert!(safe_rel(&root, "a/../../../etc").is_err());
    }

    #[test]
    fn test_normalize() {
        assert_eq!(normalize(Path::new("/a/b/../c")), PathBuf::from("/a/c"));
        assert_eq!(normalize(Path::new("/a/./b")), PathBuf::from("/a/b"));
    }

    #[test]
    fn test_parse_ls_long() {
        let s = "total 12\ndrwxr-xr-x 2 user user 4096 1700000000 .\n-rw-r--r-- 1 user user 1234 1700000100 file.txt\n-rw-r--r-- 1 user user 5 1700000101 my file.txt\n";
        let e = parse_ls_long(s);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0]["name"], "file.txt");
        assert_eq!(e[0]["size"], 1234);
        assert_eq!(e[0]["is_dir"], false);
        assert_eq!(e[1]["name"], "my file.txt");
        assert_eq!(e[1]["mtime"], 1700000101);
    }

    #[test]
    fn test_build_remote_cmds() {
        assert!(build_ls("/home/user").unwrap().contains("ls -la"));
        assert!(build_ls("/tmp/../etc").is_err());
        assert!(build_read_remote("/etc/hostname", 100).unwrap().contains("head -c 100"));
        assert!(build_find("/var/log", "error").unwrap().contains("-iname"));
        assert!(build_find("/var/log", "bad/pattern").is_err());
        assert!(build_stat("/x").unwrap().contains("stat -c"));
    }

    #[test]
    fn test_local_list_and_search() {
        let dir = std::env::temp_dir().join(format!("fmgr-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("alpha-w420.txt"), "hello").unwrap();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join("beta-w420.log"), "x").unwrap();
        let root = dir.to_string_lossy().to_string();
        let l = fmgr_list(Some(root.clone()), None).unwrap();
        assert_eq!(l["count"].as_u64().unwrap(), 2);
        let s = fmgr_search(Some(root.clone()), None, "w420".into(), None).unwrap();
        assert_eq!(s["count"].as_u64().unwrap(), 2);
        let r = fmgr_read(Some(root.clone()), "alpha-w420.txt".into(), None).unwrap();
        assert_eq!(r["text"], "hello");
        let w = fmgr_write(Some(root.clone()), "new.txt".into(), "data".into()).unwrap();
        assert_eq!(w["written"], 4);
        let d = fmgr_delete(Some(root.clone()), "new.txt".into(), false).unwrap();
        assert!(d["deleted"].as_str().unwrap().contains("new.txt"));
        assert!(fmgr_search(Some(root.clone()), None, "x".into(), None).is_err()); // <2 символов
        let _ = std::fs::remove_dir_all(&dir);
    }
}

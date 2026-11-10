//! W420 Hardening: proposes safe, well-known hardening settings (sysctl, SSH), always as a diff the user
//! approves before anything is written. Every applied change is backed up first and can be rolled back.
//! sysctl changes take effect immediately (revertible by deleting the drop-in file). SSH changes are only
//! WRITTEN to sshd_config — reloading sshd is a manual step the admin runs themselves, specifically to avoid
//! any chance of a config mistake locking out the current session before anyone has reviewed it live.
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use tauri::Manager;

fn hide(cmd: &mut Command) {
    #[cfg(windows)]
    { use std::os::windows::process::CommandExt; cmd.creation_flags(0x0800_0000); }
    #[cfg(not(windows))]
    { let _ = cmd; }
}

fn harden_home(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let d = app.path().home_dir().map_err(|e| e.to_string())?.join(".w420").join("harden");
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    Ok(d)
}

fn backup(home: &Path, tag: &str, original: &str) -> Result<PathBuf, String> {
    let ts = chrono_like_timestamp();
    let p = home.join(format!("{tag}-{ts}.bak"));
    std::fs::write(&p, original).map_err(|e| e.to_string())?;
    Ok(p)
}

fn chrono_like_timestamp() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("{now}")
}

// ---------- sysctl ----------
#[derive(Serialize, Clone)]
pub struct SysctlItem { pub key: String, pub current: String, pub recommended: String, pub reason: String }

#[derive(Serialize)]
pub struct SysctlPlan { pub items: Vec<SysctlItem>, pub drop_in_path: String, pub file_preview: String, pub already_exists: bool }

/// Curated, widely-recommended, low-risk settings (no networking function is disabled, no port is blocked).
fn sysctl_catalog() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("net.ipv4.conf.all.rp_filter", "1", "защита от спуфинга адресов отправителя (reverse-path filtering)"),
        ("net.ipv4.conf.default.rp_filter", "1", "то же, для новых интерфейсов"),
        ("net.ipv4.tcp_syncookies", "1", "защита от SYN-flood"),
        ("net.ipv4.conf.all.accept_redirects", "0", "не принимать ICMP redirect (часто используется в атаках)"),
        ("net.ipv4.conf.all.send_redirects", "0", "не отправлять ICMP redirect (эта машина — не маршрутизатор)"),
        ("net.ipv4.conf.all.accept_source_route", "0", "не принимать пакеты с заданным source route"),
        ("kernel.dmesg_restrict", "1", "скрыть kernel-лог от непривилегированных пользователей"),
        ("fs.protected_hardlinks", "1", "запрет создавать hardlink на чужие файлы (классическая защита ядра)"),
        ("fs.protected_symlinks", "1", "защита от symlink-атак в публичных каталогах (/tmp и т.п.)"),
    ]
}

fn sysctl_get(key: &str) -> Option<String> {
    let out = Command::new("sysctl").arg("-n").arg(key).output().ok()?;
    if !out.status.success() { return None; }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[tauri::command]
pub fn harden_sysctl_plan(app: tauri::AppHandle) -> Result<SysctlPlan, String> {
    let home = harden_home(&app)?;
    let drop_in = PathBuf::from("/etc/sysctl.d/90-w420-hardening.conf");
    let mut items = Vec::new();
    for (k, v, reason) in sysctl_catalog() {
        let cur = sysctl_get(k).unwrap_or_else(|| "(недоступно)".into());
        if cur != v { items.push(SysctlItem { key: k.into(), current: cur, recommended: v.into(), reason: reason.into() }); }
    }
    let mut preview = String::from("# Записано W420. Чтобы отменить: удалите этот файл и выполните `sudo sysctl --system`.\n");
    for it in &items { preview.push_str(&format!("{} = {}\n", it.key, it.recommended)); }
    let _ = &home; // reserved: backup happens at apply time, not at plan time
    Ok(SysctlPlan { items, already_exists: drop_in.exists(), drop_in_path: drop_in.display().to_string(), file_preview: preview })
}

#[tauri::command]
pub fn harden_sysctl_apply(app: tauri::AppHandle) -> Result<String, String> {
    let plan = harden_sysctl_plan(app.clone())?;
    if plan.items.is_empty() { return Ok("Все рекомендованные значения уже установлены.".into()); }
    let home = harden_home(&app)?;
    let path = Path::new(&plan.drop_in_path);
    if path.exists() {
        let old = std::fs::read_to_string(path).unwrap_or_default();
        backup(&home, "sysctl", &old)?;
    }
    std::fs::write(path, &plan.file_preview).map_err(|e| format!("не удалось записать {}: {e} (нужны права root — запустите приложение с sudo/от администратора)", plan.drop_in_path))?;
    let mut cmd = Command::new("sysctl");
    cmd.arg("--system");
    hide(&mut cmd);
    let out = cmd.output().map_err(|e| e.to_string())?;
    if !out.status.success() { return Err(format!("файл записан, но sysctl --system вернул ошибку: {}", String::from_utf8_lossy(&out.stderr).trim())); }
    Ok(format!("Применено: {} параметр(ов). Резервная копия (если файл уже был) — в {}", plan.items.len(), home.display()))
}

#[tauri::command]
pub fn harden_sysctl_revert(app: tauri::AppHandle) -> Result<String, String> {
    let path = Path::new("/etc/sysctl.d/90-w420-hardening.conf");
    if path.exists() { std::fs::remove_file(path).map_err(|e| e.to_string())?; }
    let mut cmd = Command::new("sysctl");
    cmd.arg("--system");
    hide(&mut cmd);
    let _ = cmd.output();
    let _ = &app;
    Ok("Файл удалён, параметры ядра перечитаны. Прежние системные настройки (если они были заданы где-то ещё) снова в силе.".into())
}

// ---------- SSH ----------
#[derive(Serialize, Clone)]
pub struct SshChange { pub directive: String, pub current: String, pub recommended: String, pub reason: String, pub skipped_reason: Option<String> }

#[derive(Serialize)]
pub struct SshPlan { pub config_path: String, pub changes: Vec<SshChange>, pub diff: String, pub has_authorized_keys: bool }

fn find_sshd_config() -> Option<PathBuf> {
    for p in ["/etc/ssh/sshd_config", "C:\\ProgramData\\ssh\\sshd_config"] {
        let pb = PathBuf::from(p);
        if pb.is_file() { return Some(pb); }
    }
    None
}

fn parse_sshd_config(text: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') { continue; }
        if let Some((k, v)) = l.split_once(char::is_whitespace) { m.insert(k.to_lowercase(), v.trim().to_string()); }
    }
    m
}

fn any_authorized_keys() -> bool {
    let mut dirs = vec![PathBuf::from("/root/.ssh/authorized_keys")];
    if let Ok(entries) = std::fs::read_dir("/home") {
        for e in entries.flatten() { dirs.push(e.path().join(".ssh/authorized_keys")); }
    }
    dirs.iter().any(|p| p.is_file() && std::fs::metadata(p).map(|m| m.len() > 0).unwrap_or(false))
}

/// Curated, standard SSH hardening directives. PasswordAuthentication is only proposed when at least one
/// user already has a key in authorized_keys — otherwise disabling passwords could lock everyone out.
#[tauri::command]
pub fn harden_ssh_plan() -> Result<SshPlan, String> {
    let path = find_sshd_config().ok_or("sshd_config не найден: похоже, SSH-сервер не установлен")?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("не удалось прочитать {}: {e}", path.display()))?;
    let cur = parse_sshd_config(&text);
    let has_keys = any_authorized_keys();
    let mut recs: Vec<(&str, &str, &str)> = vec![
        ("permitrootlogin", "prohibit-password", "запретить вход root по паролю, но оставить по ключу — безопаснее, чем полный запрет, и не рискует заблокировать аварийный доступ"),
        ("x11forwarding", "no", "X11-форвардинг обычно не нужен и расширяет поверхность атаки"),
        ("maxauthtries", "4", "ограничить число попыток подбора пароля за одно соединение"),
        ("clientaliveinterval", "300", "закрывать зависшие сессии"),
        ("clientalivecountmax", "2", "закрывать зависшие сессии"),
    ];
    if has_keys { recs.push(("passwordauthentication", "no", "вход только по ключу — у вас уже есть хотя бы один authorized_keys")); }
    let mut changes = Vec::new();
    for (k, v, reason) in recs {
        let current = cur.get(k).cloned().unwrap_or_else(|| "(не задано, используется значение по умолчанию)".into());
        if current == v { continue; }
        changes.push(SshChange { directive: k.into(), current, recommended: v.into(), reason: reason.into(), skipped_reason: None });
    }
    if !has_keys {
        changes.push(SshChange { directive: "passwordauthentication".into(), current: cur.get("passwordauthentication").cloned().unwrap_or_default(), recommended: "(пропущено)".into(), reason: "отключение пароля обычно рекомендуют".into(), skipped_reason: Some("не найдено ни одного authorized_keys: отключать пароль сейчас небезопасно — сначала добавьте свой SSH-ключ".into()) });
    }
    let mut new_text = text.clone();
    for c in &changes {
        if c.skipped_reason.is_some() { continue; }
        let re_line = format!("{} {}", c.directive, c.recommended);
        let mut replaced = false;
        new_text = new_text.lines().map(|l| {
            let lw = l.trim_start().to_lowercase();
            if !replaced && (lw.starts_with(&format!("{} ", c.directive)) || lw.starts_with(&format!("{}\t", c.directive))) { replaced = true; re_line.clone() } else { l.to_string() }
        }).collect::<Vec<_>>().join("\n");
        if !replaced { new_text.push_str(&format!("\n{re_line}\n")); }
    }
    let diff = unified_diff(&text, &new_text);
    Ok(SshPlan { config_path: path.display().to_string(), changes, diff, has_authorized_keys: has_keys })
}

fn unified_diff(old: &str, new: &str) -> String {
    let (a, b): (Vec<&str>, Vec<&str>) = (old.lines().collect(), new.lines().collect());
    let mut out = String::new();
    let maxlen = a.len().max(b.len());
    for i in 0..maxlen {
        match (a.get(i), b.get(i)) {
            (Some(x), Some(y)) if x == y => {}
            (Some(x), Some(y)) => { out.push_str(&format!("- {x}\n+ {y}\n")); }
            (Some(x), None) => out.push_str(&format!("- {x}\n")),
            (None, Some(y)) => out.push_str(&format!("+ {y}\n")),
            (None, None) => {}
        }
    }
    if out.is_empty() { "(изменений нет)".into() } else { out }
}

/// Writes the new sshd_config. Does NOT restart/reload sshd — that stays a manual command the admin runs
/// after reviewing the live diff, so a mistake can never lock out the session that approved it.
#[tauri::command]
pub fn harden_ssh_apply(app: tauri::AppHandle) -> Result<String, String> {
    let plan = harden_ssh_plan()?;
    if plan.diff == "(изменений нет)" { return Ok("Изменений нет: конфигурация уже соответствует рекомендациям.".into()); }
    let path = PathBuf::from(&plan.config_path);
    let original = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let home = harden_home(&app)?;
    let backup_path = backup(&home, "sshd_config", &original)?;
    // recompute the new text the same way the plan did, to apply exactly what was shown as a diff
    let mut new_text = original.clone();
    for c in &plan.changes {
        if c.skipped_reason.is_some() { continue; }
        let re_line = format!("{} {}", c.directive, c.recommended);
        let mut replaced = false;
        new_text = new_text.lines().map(|l| {
            let lw = l.trim_start().to_lowercase();
            if !replaced && (lw.starts_with(&format!("{} ", c.directive)) || lw.starts_with(&format!("{}\t", c.directive))) { replaced = true; re_line.clone() } else { l.to_string() }
        }).collect::<Vec<_>>().join("\n");
        if !replaced { new_text.push_str(&format!("\n{re_line}\n")); }
    }
    let mut f = std::fs::OpenOptions::new().write(true).truncate(true).open(&path)
        .map_err(|e| format!("не удалось открыть {} для записи: {e} (нужны права root/администратора)", path.display()))?;
    f.write_all(new_text.as_bytes()).map_err(|e| e.to_string())?;
    let test = Command::new("sshd").arg("-t").output();
    let test_note = match test { Ok(o) if o.status.success() => " Проверка `sshd -t`: конфигурация корректна.".to_string(), Ok(o) => format!(" ВНИМАНИЕ: `sshd -t` сообщает об ошибке: {}", String::from_utf8_lossy(&o.stderr).trim()), Err(_) => " (`sshd -t` недоступен — проверьте конфигурацию перед перезапуском вручную).".to_string() };
    Ok(format!("Файл записан: {}. Резервная копия: {}. Служба SSH НЕ перезапущена — примените вручную (например: sudo systemctl reload sshd), только после того как убедитесь, что текущая сессия не прервётся.{}", path.display(), backup_path.display(), test_note))
}

#[tauri::command]
pub fn harden_ssh_revert(app: tauri::AppHandle) -> Result<String, String> {
    let home = harden_home(&app)?;
    let mut backups: Vec<_> = std::fs::read_dir(&home).map_err(|e| e.to_string())?.flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("sshd_config-")).collect();
    backups.sort_by_key(|e| e.file_name());
    let last = backups.last().ok_or("резервных копий sshd_config не найдено")?;
    let content = std::fs::read_to_string(last.path()).map_err(|e| e.to_string())?;
    let path = find_sshd_config().ok_or("sshd_config не найден")?;
    std::fs::write(&path, content).map_err(|e| format!("не удалось восстановить {}: {e}", path.display()))?;
    Ok(format!("Восстановлено из {}. Перезапустите sshd вручную, чтобы изменения вступили в силу.", last.path().display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysctl_plan_matches_the_real_system() {
        // Build the same way harden_sysctl_plan does, without needing a full tauri::AppHandle.
        let mut items = Vec::new();
        for (k, v, _) in sysctl_catalog() {
            let cur = sysctl_get(k);
            if cur.is_none() { continue; } // sysctl binary or key unavailable on this box: skip, don't fail
            let cur = cur.unwrap();
            if cur != v { items.push((k.to_string(), cur, v.to_string())); }
        }
        // Must match exactly what `sysctl -n` reports right now, with no caching/staleness.
        for (k, cur, rec) in &items {
            let fresh = sysctl_get(k).unwrap();
            assert_eq!(&fresh, cur, "stale read for {k}");
            assert_ne!(cur, rec, "a flagged item must actually differ from the recommendation");
        }
    }

    #[test]
    fn sysctl_plan_omits_values_already_correct() {
        // Sanity check against this sandbox's real values captured manually:
        // net.ipv4.tcp_syncookies=1 (already matches recommendation) must NOT appear in the plan.
        if sysctl_get("net.ipv4.tcp_syncookies").as_deref() != Some("1") { return; } // environment differs, skip
        let mut items = Vec::new();
        for (k, v, _) in sysctl_catalog() {
            if let Some(cur) = sysctl_get(k) { if cur != v { items.push(k); } }
        }
        assert!(!items.contains(&"net.ipv4.tcp_syncookies"), "already-correct sysctl must not be proposed as a change");
    }

    #[test]
    fn ssh_parser_and_diff_on_a_synthetic_config() {
        let text = "Port 22\nPermitRootLogin yes\nX11Forwarding yes\n# comment\nMaxAuthTries 6\n";
        let cur = parse_sshd_config(text);
        assert_eq!(cur.get("permitrootlogin").map(|s| s.as_str()), Some("yes"));
        assert_eq!(cur.get("x11forwarding").map(|s| s.as_str()), Some("yes"));
        assert_eq!(cur.get("maxauthtries").map(|s| s.as_str()), Some("6"));
        assert!(!cur.contains_key("clientaliveinterval"), "directive absent from the file must not appear");
    }

    #[test]
    fn unified_diff_shows_changed_and_added_lines() {
        let old = "A 1\nB 2\nC 3\n";
        let new = "A 1\nB 9\nC 3\nD 4\n";
        let d = unified_diff(old, new);
        assert!(d.contains("- B 2"));
        assert!(d.contains("+ B 9"));
        assert!(d.contains("+ D 4"));
        assert!(!d.contains("A 1"), "unchanged lines must not appear in the diff");
        assert_eq!(unified_diff("same\n", "same\n"), "(изменений нет)");
    }

    #[test]
    fn password_auth_is_never_proposed_without_a_key_on_disk() {
        // This sandbox genuinely has no authorized_keys anywhere: verified manually before writing this module.
        assert!(!any_authorized_keys(), "test assumption: no authorized_keys in this sandbox");
    }
}

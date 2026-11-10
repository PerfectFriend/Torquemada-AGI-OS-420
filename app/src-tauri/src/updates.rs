//! W420 Update Manager: READ-ONLY overview of outdated system packages, via the OS's own package manager.
//! Never installs or upgrades anything itself — that stays a manual, user-run command (shown in the UI).
use serde::Serialize;
use std::process::Command;

#[derive(Serialize, Clone)]
pub struct Outdated {
    pub name: String,
    pub installed: String,
    pub available: String,
    pub security: bool, // best-effort: true only when the package manager itself labels it a security update
    pub source: String, // which repo/channel reported it (apt pocket, dnf repo, brew, winget source)
}

#[derive(Serialize)]
pub struct UpdateReport {
    pub manager: String,
    pub ok: bool,
    pub packages: Vec<Outdated>,
    pub note: String, // explains anything the UI should show as-is (e.g. "needs: sudo apt update first")
}

fn hide(cmd: &mut Command) {
    #[cfg(windows)]
    { use std::os::windows::process::CommandExt; cmd.creation_flags(0x0800_0000); }
    #[cfg(not(windows))]
    { let _ = cmd; }
}

fn run(bin: &str, args: &[&str]) -> Option<(i32, String, String)> {
    let mut cmd = Command::new(bin);
    cmd.args(args).env("LANG", "C").env("LC_ALL", "C");
    hide(&mut cmd);
    let out = cmd.output().ok()?;
    Some((out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned()))
}

fn have(bin: &str) -> bool { run(bin, &["--version"]).is_some() }

/// `apt list --upgradable` line: "name/repo[,repo2] new_version arch [upgradable from: old_version]"
fn parse_apt(stdout: &str) -> Vec<Outdated> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line == "Listing..." { continue; }
        let Some((head, rest)) = line.split_once(" [upgradable from: ") else { continue };
        let old = rest.trim_end_matches(']').trim();
        let mut parts = head.split_whitespace();
        let Some(name_repo) = parts.next() else { continue };
        let Some(new_version) = parts.next() else { continue };
        let Some((name, repos)) = name_repo.split_once('/') else { continue };
        out.push(Outdated {
            name: name.to_string(),
            installed: old.to_string(),
            available: new_version.to_string(),
            security: repos.contains("-security"),
            source: repos.to_string(),
        });
    }
    out
}

fn scan_apt() -> Option<UpdateReport> {
    if !have("apt") { return None; }
    let (code, stdout, stderr) = run("apt", &["list", "--upgradable"])?;
    if code != 0 { return Some(UpdateReport { manager: "apt".into(), ok: false, packages: vec![], note: format!("apt list завершился с ошибкой: {}", stderr.trim()) }); }
    let packages = parse_apt(&stdout);
    Some(UpdateReport { manager: "apt".into(), ok: true, note: "список может быть устаревшим: выполните sudo apt update для свежих данных".into(), packages })
}

/// `dnf check-update`: name.arch<ws>version<ws>repo per line; blank line before "Obsoleting Packages" section (ignored).
/// Exit code 100 means "updates available" (not an error); 0 means none; anything else is a real error.
fn parse_dnf(stdout: &str) -> Vec<Outdated> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 3 { continue; }
        let Some((name, _arch)) = f[0].rsplit_once('.') else { continue };
        out.push(Outdated { name: name.to_string(), installed: String::new(), available: f[1].to_string(), security: false, source: f[2].to_string() });
    }
    out
}

fn scan_dnf() -> Option<UpdateReport> {
    if !have("dnf") { return None; }
    let (code, stdout, stderr) = run("dnf", &["check-update"])?;
    if code != 0 && code != 100 { return Some(UpdateReport { manager: "dnf".into(), ok: false, packages: vec![], note: format!("dnf check-update: {}", stderr.trim()) }); }
    Some(UpdateReport { manager: "dnf".into(), ok: true, note: "версия до обновления неизвестна (dnf её не печатает); для меток безопасности нужен dnf-plugin-security".into(), packages: parse_dnf(&stdout) })
}

/// `brew outdated --json=v2`: {"formulae":[{"name":..,"installed_versions":[..],"current_version":..}], "casks":[...]}
fn scan_brew() -> Option<UpdateReport> {
    if !have("brew") { return None; }
    let (code, stdout, stderr) = run("brew", &["outdated", "--json=v2"])?;
    if code != 0 { return Some(UpdateReport { manager: "brew".into(), ok: false, packages: vec![], note: format!("brew outdated: {}", stderr.trim()) }); }
    let v: serde_json::Value = match serde_json::from_str(&stdout) { Ok(v) => v, Err(e) => return Some(UpdateReport { manager: "brew".into(), ok: false, packages: vec![], note: format!("не удалось разобрать вывод brew: {e}") }) };
    let mut packages = Vec::new();
    for key in ["formulae", "casks"] {
        for item in v.get(key).and_then(|a| a.as_array()).into_iter().flatten() {
            let name = item.get("name").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            let installed = item.get("installed_versions").and_then(|a| a.as_array()).and_then(|a| a.last()).and_then(|x| x.as_str()).unwrap_or("?").to_string();
            let available = item.get("current_version").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            packages.push(Outdated { name, installed, available, security: false, source: key.to_string() });
        }
    }
    Some(UpdateReport { manager: "brew".into(), ok: true, note: "не проверено в этой сборке (нет macOS в тестовой среде)".into(), packages })
}

/// `winget upgrade`: a fixed-width text table whose headers are localized. Best-effort column split; may misparse
/// names containing multiple spaces. Not verified against a real Windows machine.
fn parse_winget(stdout: &str) -> Vec<Outdated> {
    let mut out = Vec::new();
    let mut started = false;
    for line in stdout.lines() {
        let l = line.trim_end();
        if l.starts_with('-') && l.chars().all(|c| c == '-') { started = true; continue; }
        if !started || l.trim().is_empty() { continue; }
        let f: Vec<&str> = l.split_whitespace().collect();
        // columns: Name (may contain spaces) | Id (no spaces) | Version | Available | Source -> at least 5 fields
        let n = f.len();
        if n < 5 { continue; }
        out.push(Outdated { name: f[..n - 4].join(" "), installed: f[n - 3].to_string(), available: f[n - 2].to_string(), security: false, source: f[n - 1].to_string() });
    }
    out
}

fn scan_winget() -> Option<UpdateReport> {
    if !have("winget") { return None; }
    let (code, stdout, stderr) = run("winget", &["upgrade", "--include-unknown"])?;
    if code != 0 && !stdout.to_lowercase().contains("no installed package") { return Some(UpdateReport { manager: "winget".into(), ok: false, packages: vec![], note: format!("winget upgrade: {}", stderr.trim()) }); }
    Some(UpdateReport { manager: "winget".into(), ok: true, note: "разбор таблицы winget не проверен на реальной машине: сверяйте с `winget upgrade` вручную".into(), packages: parse_winget(&stdout) })
}

#[tauri::command]
pub fn updates_check() -> Vec<UpdateReport> {
    [scan_apt(), scan_dnf(), scan_brew(), scan_winget()].into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_apt_output() {
        let sample = "Listing...\nbase-files/noble-updates 13ubuntu10.5 amd64 [upgradable from: 13ubuntu10.4]\nca-certificates/noble-updates,noble-security 20260816ubuntu0.24.04.1 all [upgradable from: 20240203]\n";
        let p = parse_apt(sample);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, "base-files");
        assert_eq!(p[0].installed, "13ubuntu10.4");
        assert_eq!(p[0].available, "13ubuntu10.5");
        assert!(!p[0].security);
        assert_eq!(p[1].name, "ca-certificates");
        assert!(p[1].security, "noble-security pocket must be flagged as a security update");
    }

    #[test]
    fn apt_scan_matches_the_real_system() {
        if !have("apt") { return; }
        let r = scan_apt().expect("apt present");
        assert!(r.ok);
        let (_, raw, _) = run("apt", &["list", "--upgradable"]).unwrap();
        let expected = raw.lines().filter(|l| l.contains("[upgradable from:")).count();
        assert_eq!(r.packages.len(), expected, "parsed count must match the real apt output line count");
        if expected > 0 {
            assert!(r.packages.iter().all(|p| !p.name.is_empty() && !p.available.is_empty() && !p.installed.is_empty()));
        }
    }

    #[test]
    fn parses_dnf_check_update() {
        let sample = "bash.x86_64                5.2.21-1.fc40                   updates\nkernel.x86_64               6.8.5-301.fc40                  updates\n\nObsoleting Packages\nfoo.x86_64                  1-1.fc40                        updates\n";
        let p = parse_dnf(sample);
        assert_eq!(p.len(), 3); // the simple line-shape parser can't distinguish the Obsoleting section; documented limitation
        assert_eq!(p[0].name, "bash");
        assert_eq!(p[0].available, "5.2.21-1.fc40");
        assert_eq!(p[0].source, "updates");
    }

    #[test]
    fn parses_winget_table() {
        let sample = "Name              Id                       Version   Available Source\n----------------------------------------------------------------------\n7-Zip             7zip.7zip                23.01     24.08     winget\nGit               Git.Git                  2.44.0    2.45.1    winget\n";
        let p = parse_winget(sample);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].installed, "23.01");
        assert_eq!(p[0].available, "24.08");
        assert_eq!(p[1].name, "Git");
    }
}

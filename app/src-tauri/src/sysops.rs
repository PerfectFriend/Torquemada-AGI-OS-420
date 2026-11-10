//! W420 SysOps: runs the bundled Trivy (vulnerabilities/secrets in files and dependency manifests) and
//! gitleaks (secrets in a folder, git history optional), plus a small file-integrity monitor (SHA-256 baseline).
//! Read-only: these tools only report. Every scan target must be inside a path the user explicitly approved (scope).
use crate::bridge::find_sidecar;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use tauri::Manager;

#[derive(Default)]
pub struct SysOps {
    pub scope: Mutex<Vec<PathBuf>>,
}

#[derive(Serialize, Deserialize)]
pub struct Finding {
    pub tool: String,
    pub severity: String, // critical | high | medium | low | info
    pub id: String,
    pub title: String,
    pub location: String,
    pub detail: String,
}

#[derive(Serialize)]
pub struct ScanReport {
    pub tool: String,
    pub ok: bool,
    pub findings: Vec<Finding>,
    pub raw_summary: String,
    pub duration_ms: u128,
}

fn hide(cmd: &mut Command) {
    #[cfg(windows)]
    { use std::os::windows::process::CommandExt; cmd.creation_flags(0x0800_0000); }
    #[cfg(not(windows))]
    { let _ = cmd; }
}

fn canon(p: &Path) -> Result<PathBuf, String> { std::fs::canonicalize(p).map_err(|e| format!("путь недоступен: {e}")) }

/// A target is in scope only if it is the same as, or lives inside, one of the paths the user approved.
fn in_scope(scope: &[PathBuf], target: &Path) -> bool {
    scope.iter().any(|s| target == s || target.starts_with(s))
}

fn sysops_home(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let d = app.path().home_dir().map_err(|e| e.to_string())?.join(".w420").join("sysops");
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    Ok(d)
}

#[tauri::command]
pub fn sysops_set_scope(state: tauri::State<SysOps>, paths: Vec<String>) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for p in paths {
        let c = canon(Path::new(&p))?;
        if !c.is_dir() { return Err(format!("{p}: не папка")); }
        out.push(c);
    }
    *state.scope.lock().map_err(|_| "внутренняя ошибка")? = out.clone();
    Ok(out.into_iter().map(|p| p.display().to_string()).collect())
}

#[tauri::command]
pub fn sysops_get_scope(state: tauri::State<SysOps>) -> Vec<String> {
    state.scope.lock().map(|s| s.iter().map(|p| p.display().to_string()).collect()).unwrap_or_default()
}

fn check_scope(state: &SysOps, target_raw: &str) -> Result<PathBuf, String> {
    let target = canon(Path::new(target_raw))?;
    let scope = state.scope.lock().map_err(|_| "внутренняя ошибка")?;
    if scope.is_empty() { return Err("Область проверки пуста: сначала добавьте папку во вкладке SYSOPS.".into()); }
    if !in_scope(&scope, &target) { return Err(format!("{} вне подтверждённой области проверки", target.display())); }
    Ok(target)
}

#[derive(Deserialize)]
struct TrivyOut { #[serde(rename = "Results")] results: Option<Vec<TrivyResult>> }
#[derive(Deserialize)]
struct TrivyResult {
    #[serde(rename = "Target")] target: String,
    #[serde(rename = "Vulnerabilities")] vulns: Option<Vec<TrivyVuln>>,
    #[serde(rename = "Secrets")] secrets: Option<Vec<TrivySecret>>,
}
#[derive(Deserialize)]
struct TrivyVuln {
    #[serde(rename = "VulnerabilityID")] id: String,
    #[serde(rename = "PkgName")] pkg: String,
    #[serde(rename = "InstalledVersion")] installed: String,
    #[serde(rename = "FixedVersion")] fixed: Option<String>,
    #[serde(rename = "Severity")] severity: String,
    #[serde(rename = "Title")] title: Option<String>,
}
#[derive(Deserialize)]
struct TrivySecret { #[serde(rename = "RuleID")] rule: String, #[serde(rename = "Title")] title: String, #[serde(rename = "StartLine")] line: u32 }

#[tauri::command]
pub fn sysops_scan_trivy(state: tauri::State<SysOps>, path: String) -> Result<ScanReport, String> {
    let target = check_scope(&state, &path)?;
    let bin = find_sidecar("trivy").ok_or("Не найден встроенный trivy. Запусти: node tools/fetch-sidecars.mjs")?;
    let t0 = std::time::Instant::now();
    let mut cmd = Command::new(&bin);
    cmd.args(["fs", "--scanners", "vuln,secret", "--format", "json", "--quiet"]).arg(&target);
    hide(&mut cmd);
    let out = cmd.output().map_err(|e| format!("не удалось запустить trivy: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() && stdout.trim().is_empty() {
        return Err(format!("trivy: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let parsed: TrivyOut = serde_json::from_str(&stdout).map_err(|e| format!("не удалось разобрать вывод trivy: {e}"))?;
    let mut findings = Vec::new();
    for r in parsed.results.unwrap_or_default() {
        for v in r.vulns.unwrap_or_default() {
            findings.push(Finding {
                tool: "trivy".into(),
                severity: v.severity.to_lowercase(),
                id: v.id.clone(),
                title: v.title.unwrap_or_else(|| v.id.clone()),
                location: format!("{} ({} {})", r.target, v.pkg, v.installed),
                detail: v.fixed.map(|f| format!("исправлено в {f}")).unwrap_or_else(|| "версии с исправлением не найдено".into()),
            });
        }
        for s in r.secrets.unwrap_or_default() {
            findings.push(Finding { tool: "trivy".into(), severity: "high".into(), id: s.rule, title: s.title, location: format!("{}:{}", r.target, s.line), detail: String::new() });
        }
    }
    Ok(ScanReport { tool: "trivy".into(), ok: true, raw_summary: format!("целей проверено: {}, находок: {}", 1, findings.len()), findings, duration_ms: t0.elapsed().as_millis() })
}

#[derive(Deserialize)]
struct GitleaksFinding {
    #[serde(rename = "RuleID")] rule: String,
    #[serde(rename = "File")] file: String,
    #[serde(rename = "StartLine")] line: i64,
    #[serde(rename = "Description")] desc: String,
}

#[tauri::command]
pub fn sysops_scan_gitleaks(app: tauri::AppHandle, state: tauri::State<SysOps>, path: String, include_git_history: bool) -> Result<ScanReport, String> {
    let target = check_scope(&state, &path)?;
    let bin = find_sidecar("gitleaks").ok_or("Не найден встроенный gitleaks. Запусти: node tools/fetch-sidecars.mjs")?;
    let report = sysops_home(&app)?.join("gitleaks.json");
    let t0 = std::time::Instant::now();
    let mut cmd = Command::new(&bin);
    cmd.arg("detect").arg("--source").arg(&target).args(["-f", "json", "-r"]).arg(&report).arg("--exit-code").arg("0");
    if !include_git_history { cmd.arg("--no-git"); }
    hide(&mut cmd);
    let out = cmd.output().map_err(|e| format!("не удалось запустить gitleaks: {e}"))?;
    if !out.status.success() && !report.exists() {
        return Err(format!("gitleaks: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let raw = std::fs::read_to_string(&report).unwrap_or_default();
    let items: Vec<GitleaksFinding> = if raw.trim().is_empty() { Vec::new() } else { serde_json::from_str(&raw).map_err(|e| format!("не удалось разобрать отчёт gitleaks: {e}"))? };
    let n = items.len();
    let findings = items.into_iter().map(|f| Finding { tool: "gitleaks".into(), severity: "high".into(), id: f.rule, title: f.desc, location: format!("{}:{}", f.file, f.line), detail: String::new() }).collect();
    Ok(ScanReport { tool: "gitleaks".into(), ok: true, raw_summary: format!("найдено секретов: {n}"), findings, duration_ms: t0.elapsed().as_millis() })
}

// ---------- file integrity monitor: SHA-256 baseline over a scope folder ----------
#[derive(Serialize, Deserialize, Default, Clone)]
struct Baseline(BTreeMap<String, String>); // relative path -> sha256

fn baseline_path(app: &tauri::AppHandle, tag: &str) -> Result<PathBuf, String> {
    Ok(sysops_home(app)?.join(format!("fim-{tag}.json")))
}

fn walk_hash(root: &Path, out: &mut BTreeMap<String, String>) -> std::io::Result<()> {
    for entry in walkdir_simple(root)? {
        let data = std::fs::read(&entry)?;
        let mut h = Sha256::new();
        h.update(&data);
        let rel = entry.strip_prefix(root).unwrap_or(&entry).to_string_lossy().replace('\\', "/");
        out.insert(rel, format!("{:x}", h.finalize()));
    }
    Ok(())
}

fn walkdir_simple(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut stack = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let p = entry.path();
            let name = entry.file_name();
            if name == ".git" || name == "node_modules" || name == "target" || name == ".venv" { continue; }
            if p.is_dir() { stack.push(p); } else if p.is_file() { files.push(p); }
        }
    }
    files.sort();
    Ok(files)
}

fn tag_for(path: &str) -> String { format!("{:x}", Sha256::digest(path.as_bytes()))[..16].to_string() }

#[tauri::command]
pub fn sysops_fim_baseline(app: tauri::AppHandle, state: tauri::State<SysOps>, path: String) -> Result<usize, String> {
    let target = check_scope(&state, &path)?;
    let mut map = BTreeMap::new();
    walk_hash(&target, &mut map).map_err(|e| e.to_string())?;
    let n = map.len();
    let bp = baseline_path(&app, &tag_for(&target.display().to_string()))?;
    let mut f = std::fs::File::create(&bp).map_err(|e| e.to_string())?;
    f.write_all(serde_json::to_string(&Baseline(map)).unwrap().as_bytes()).map_err(|e| e.to_string())?;
    Ok(n)
}

#[derive(Serialize)]
pub struct FimDiff { pub added: Vec<String>, pub removed: Vec<String>, pub changed: Vec<String>, pub has_baseline: bool }

#[tauri::command]
pub fn sysops_fim_check(app: tauri::AppHandle, state: tauri::State<SysOps>, path: String) -> Result<FimDiff, String> {
    let target = check_scope(&state, &path)?;
    let bp = baseline_path(&app, &tag_for(&target.display().to_string()))?;
    if !bp.exists() { return Ok(FimDiff { added: vec![], removed: vec![], changed: vec![], has_baseline: false }); }
    let old: Baseline = serde_json::from_str(&std::fs::read_to_string(&bp).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let mut now = BTreeMap::new();
    walk_hash(&target, &mut now).map_err(|e| e.to_string())?;
    let mut added = Vec::new(); let mut removed = Vec::new(); let mut changed = Vec::new();
    for (k, v) in &now { match old.0.get(k) { None => added.push(k.clone()), Some(h) if h != v => changed.push(k.clone()), _ => {} } }
    for k in old.0.keys() { if !now.contains_key(k) { removed.push(k.clone()); } }
    Ok(FimDiff { added, removed, changed, has_baseline: true })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_blocks_outside_paths() {
        let scope = vec![PathBuf::from("/tmp/scanme")];
        assert!(in_scope(&scope, Path::new("/tmp/scanme")));
        assert!(in_scope(&scope, Path::new("/tmp/scanme/sub/app.py")));
        assert!(!in_scope(&scope, Path::new("/etc/passwd")));
        assert!(!in_scope(&scope, Path::new("/tmp/scanme-other")));
    }

    #[test]
    fn gitleaks_finds_the_planted_secret() {
        let bin = find_sidecar("gitleaks").expect("run: node tools/fetch-sidecars.mjs");
        // самодостаточно: сами создаём директорию и «секрет» (раньше ждали /tmp/scanme извне).
        // ВАЖНО: gitleaks фильтрует allowlist/низкую энтропию — AKIAIOSFODNN7EXAMPLE там в allowlist,
        // поэтому сажаем высокоэнтропийный github-pat, который детектится как github-pat.
        let dir = std::env::temp_dir().join(format!("w420-gl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("creds.env"), "token = \"ghp_X9k2Qp7Zb4Nw8Ls3Md6Vj1Hc5Rt0Yg2Ef8Ua\"\n").unwrap();
        let report = std::env::temp_dir().join(format!("w420-test-gl-{}.json", std::process::id()));
        let out = Command::new(&bin).arg("detect").arg("--source").arg(&dir).arg("--no-git")
            .args(["-f", "json", "-r"]).arg(&report).arg("--exit-code").arg("0").output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let items: Vec<GitleaksFinding> = serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
        assert!(items.iter().any(|f| f.rule == "github-pat"), "github-pat not found: {:?}", items.iter().map(|f| &f.rule).collect::<Vec<_>>());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fim_detects_added_changed_removed() {
        let dir = std::env::temp_dir().join(format!("w420-fim-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "one").unwrap();
        std::fs::write(dir.join("b.txt"), "two").unwrap();
        let mut base = BTreeMap::new();
        walk_hash(&dir, &mut base).unwrap();
        assert_eq!(base.len(), 2);
        std::fs::write(dir.join("a.txt"), "ONE-changed").unwrap(); // change
        std::fs::remove_file(dir.join("b.txt")).unwrap();          // remove
        std::fs::write(dir.join("c.txt"), "three").unwrap();       // add
        let mut now = BTreeMap::new();
        walk_hash(&dir, &mut now).unwrap();
        let added: Vec<_> = now.keys().filter(|k| !base.contains_key(*k)).collect();
        let removed: Vec<_> = base.keys().filter(|k| !now.contains_key(*k)).collect();
        let changed: Vec<_> = now.iter().filter(|(k, v)| base.get(*k).map(|h| h != *v).unwrap_or(false)).collect();
        assert_eq!(added, vec!["c.txt"]);
        assert_eq!(removed, vec!["b.txt"]);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].0, "a.txt");
    }
}

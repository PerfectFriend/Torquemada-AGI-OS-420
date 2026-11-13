//! Фаза 11: управление патчами (patch_mgmt.rs).
//!
//! Локальный хост: `apt list --upgradable` (не требует root), security-пакеты по суффиксу `-security`.
//! Удалённые хосты из hosts.db — через ssh (BatchMode, таймаут 5с).
//! Деплой: `sudo -n apt-get install -y ...` — если в sudoers нет apt-get, вернёт needs_root + готовую команду.
//! Rollback: парсинг /var/log/apt/history.log → план downgrade (только план, без выполнения).
//! AI-оценка риска: patch_ai_assess гоняет security-обновления через KeyRotation (NVIDIA).
//! БД: ~/.w420/patch.db (таблицы scans, deploys).

use rusqlite::Connection;
use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

pub struct PatchManager {
    pub db: Mutex<PathBuf>,
}

fn home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"))
}

#[derive(Serialize, Clone)]
pub struct PkgUpdate {
    pub package: String,
    pub current: String,
    pub candidate: String,
    pub origin: String,
    pub is_security: bool,
}

impl PatchManager {
    pub fn new() -> Self {
        let db = home().join(".w420").join("patch.db");
        let m = Self { db: Mutex::new(db.clone()) };
        m.init(&db);
        m
    }

    fn init(&self, db: &PathBuf) {
        if let Ok(c) = Connection::open(db) {
            let _ = c.execute_batch(
                "CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL, host TEXT NOT NULL, package TEXT, current TEXT, candidate TEXT, origin TEXT, is_security INTEGER
                );
                CREATE TABLE IF NOT EXISTS deploys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL, host TEXT NOT NULL, mode TEXT, packages TEXT, ok INTEGER, detail TEXT
                );",
            );
        }
    }

    pub fn conn(&self) -> Result<Connection, String> {
        let p = self.db.lock().unwrap().clone();
        Connection::open(p).map_err(|e| e.to_string())
    }

    fn store_scan(&self, host: &str, pkgs: &[PkgUpdate]) {
        if let Ok(c) = self.conn() {
            let ts = chrono::Utc::now().to_rfc3339();
            for p in pkgs {
                let _ = c.execute(
                    "INSERT INTO scans (ts, host, package, current, candidate, origin, is_security) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    rusqlite::params![ts, host, &p.package, &p.current, &p.candidate, &p.origin, p.is_security as i64],
                );
            }
        }
    }

    /// Скан локального хоста. Возвращает (всего, security).
    pub fn scan_local(&self) -> Result<(usize, usize), String> {
        let out = Command::new("apt")
            .arg("list").arg("--upgradable")
            .output()
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr).into_owned();
        let pkgs = parse_apt_upgradable(&text);
        let sec = pkgs.iter().filter(|p| p.is_security).count();
        self.store_scan("localhost", &pkgs);
        Ok((pkgs.len(), sec))
    }

    /// Скан всех хостов из hosts.db по ssh + локальный. Возвращает карту host -> (всего, security).
    pub fn scan_all(&self) -> Result<Vec<(String, usize, usize)>, String> {
        let mut res = Vec::new();
        let (t, s) = self.scan_local()?;
        res.push(("localhost".into(), t, s));
        // удалённые хосты
        if let Ok(c) = Connection::open(home().join(".w420").join("hosts.db")) {
            let mut st = c.prepare("SELECT name, ip, port, username FROM hosts").map_err(|e| e.to_string())?;
            let rows = st
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, u16>(2)?, r.get::<_, String>(3)?)))
                .map_err(|e| e.to_string())?;
            for row in rows.flatten() {
                let (name, ip, port, user) = row;
                let target = format!("{user}@{ip}");
                let out = Command::new("ssh")
                    .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-p", &port.to_string(), &target,
                           "apt list --upgradable 2>/dev/null"])
                    .output();
                match out {
                    Ok(o) if o.status.success() => {
                        let pkgs = parse_apt_upgradable(&String::from_utf8_lossy(&o.stdout));
                        let sec = pkgs.iter().filter(|p| p.is_security).count();
                        self.store_scan(&name, &pkgs);
                        res.push((name, pkgs.len(), sec));
                    }
                    _ => res.push((name, 0, 0)), // недоступен
                }
            }
        }
        Ok(res)
    }

    pub fn list_updates(&self, security_only: bool) -> Result<Vec<serde_json::Value>, String> {
        let c = self.conn()?;
        let sql = if security_only {
            "SELECT host, package, current, candidate, origin, MAX(ts) FROM scans WHERE is_security=1 GROUP BY host, package ORDER BY host, package"
        } else {
            "SELECT host, package, current, candidate, origin, MAX(ts) FROM scans GROUP BY host, package ORDER BY host, package"
        };
        let mut st = c.prepare(sql).map_err(|e| e.to_string())?;
        let rows = st
            .query_map([], |r| {
                Ok(serde_json::json!({
                    "host": r.get::<_, String>(0)?, "package": r.get::<_, String>(1)?,
                    "current": r.get::<_, String>(2)?, "candidate": r.get::<_, String>(3)?,
                    "origin": r.get::<_, String>(4)?, "last_scan": r.get::<_, String>(5)?,
                }))
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }

    /// Деплой обновлений. Локально: sudo -n apt-get install -y. needs_root если apt-get нет в sudoers.
    pub fn deploy(&self, security_only: bool) -> Result<serde_json::Value, String> {
        let pkgs = self.list_updates(security_only)?;
        if pkgs.is_empty() {
            return Ok(serde_json::json!({"ok": true, "deployed": 0, "detail": "нечего ставить"}));
        }
        let names: Vec<String> = pkgs.iter().filter_map(|p| p["package"].as_str().map(String::from)).collect();
        // Деплой — ТОЛЬКО через root-хелпер w420-apt-install (валидирует имена пакетов); см. scripts/root_setup.sh
        let cmd_str = format!("sudo -n /usr/local/sbin/w420-apt-install {}", names.join(" "));
        let out = Command::new("sudo")
            .args(["-n", "/usr/local/sbin/w420-apt-install"])
            .args(&names)
            .output();
        let (ok, detail, needs_root) = match out {
            Ok(o) if o.status.success() => (true, String::from_utf8_lossy(&o.stdout).into_owned(), false),
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr).into_owned();
                let nr = err.contains("a password is required") || err.contains("not allowed");
                (false, err, nr)
            }
            Err(e) => (false, e.to_string(), false),
        };
        if let Ok(c) = self.conn() {
            let _ = c.execute(
                "INSERT INTO deploys (ts, host, mode, packages, ok, detail) VALUES (?1,'localhost',?2,?3,?4,?5)",
                rusqlite::params![
                    chrono::Utc::now().to_rfc3339(),
                    if security_only { "security" } else { "all" },
                    names.join(","),
                    ok as i64,
                    detail.chars().take(2000).collect::<String>()
                ],
            );
        }
        Ok(serde_json::json!({
            "ok": ok, "needs_root": needs_root, "count": names.len(),
            "command": cmd_str, "detail": detail.chars().take(500).collect::<String>()
        }))
    }

    /// Rollback-план по /var/log/apt/history.log: последние транзакции → команды downgrade (только план!).
    pub fn rollback_plan(&self, transactions: u32) -> Result<Vec<String>, String> {
        let path = "/var/log/apt/history.log";
        let text = std::fs::read_to_string(path)
            .or_else(|_| {
                let o = Command::new("sudo").args(["-n", "cat", path]).output().map_err(|e| e.to_string())?;
                Ok::<String, String>(String::from_utf8_lossy(&o.stdout).into_owned())
            })
            .map_err(|e| format!("нет доступа к {path}: {e} (нужен sudo cat — добавь в root_setup)"))?;
        Ok(parse_apt_history(&text, transactions.max(1) as usize))
    }

    pub fn status(&self) -> Result<serde_json::Value, String> {
        let c = self.conn()?;
        let total: i64 = c.query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0)).unwrap_or(0);
        let sec: i64 = c.query_row("SELECT COUNT(*) FROM scans WHERE is_security=1", [], |r| r.get(0)).unwrap_or(0);
        let hosts: i64 = c.query_row("SELECT COUNT(DISTINCT host) FROM scans", [], |r| r.get(0)).unwrap_or(0);
        let last_deploy: String = c
            .query_row("SELECT ts || ' ' || mode || ' ok=' || ok FROM deploys ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .unwrap_or_default();
        Ok(serde_json::json!({
            "scanned_rows": total, "security_rows": sec, "hosts": hosts, "last_deploy": last_deploy
        }))
    }

    /// AI-оценка риска security-обновлений через KeyRotation (NVIDIA, ключи в бэкенде).
    pub async fn ai_assess(&self) -> Result<String, String> {
        use w420_ai::db::AIProviderDB;
        use w420_ai::rotation::KeyRotation;
        use w420_ai::{ChatMessage, ChatRequest};

        let pkgs = self.list_updates(true)?;
        let payload = serde_json::to_string_pretty(&pkgs).unwrap_or_default();
        let (providers_vec, keys_vec) = {
            let db = AIProviderDB::open().map_err(|e| e.to_string())?;
            (db.list_providers().map_err(|e| e.to_string())?, db.list_all_keys().map_err(|e| e.to_string())?)
        };
        let rotation = KeyRotation::new();
        for p in &providers_vec { rotation.add_provider(p.clone()).await; }
        for k in &keys_vec { rotation.add_key(k.clone()).await; }
        let request = ChatRequest {
            model: "mistralai/mistral-large-4-1t-a52b".into(),
            messages: vec![
                ChatMessage { role: "system".into(), content: "Ты patch-менеджер SOC. По списку security-обновлений дай на русском: что ставить немедленно, что можно отложить, риски. До 8 пунктов.".into() },
                ChatMessage { role: "user".into(), content: payload },
            ],
            temperature: 0.3,
            max_tokens: Some(800),
            stream: false,
        };
        let resp = rotation.chat_completion_with_rotation(request, None).await.map_err(|e| e.to_string())?;
        Ok(resp.response.content)
    }
}

/// Парсинг `apt list --upgradable` (чистая функция).
/// Формат: pkg/origin candidate arch [upgradable from: current]
pub fn parse_apt_upgradable(text: &str) -> Vec<PkgUpdate> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Listing") {
            continue;
        }
        let Some((pkg, rest)) = line.split_once('/') else { continue };
        let mut parts = rest.split_whitespace();
        let origin = parts.next().unwrap_or("").to_string();
        let candidate = parts.next().unwrap_or("").to_string();
        let _arch = parts.next().unwrap_or("");
        let current = if let Some(bracket) = line.find("[upgradable from: ") {
            line[bracket + "[upgradable from: ".len()..].trim_end_matches(']').trim().to_string()
        } else {
            String::new()
        };
        out.push(PkgUpdate {
            package: pkg.to_string(),
            current,
            candidate,
            is_security: origin.contains("-security"),
            origin,
        });
    }
    out
}

/// Парсинг /var/log/apt/history.log → команды downgrade для последних N транзакций (только план).
pub fn parse_apt_history(text: &str, transactions: usize) -> Vec<String> {
    // блоки вида: Start-Date / Commandline / Upgrade: pkg:amd64 (old, new) / End-Date
    let mut blocks: Vec<String> = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        if line.starts_with("Start-Date:") && !cur.is_empty() {
            blocks.push(std::mem::take(&mut cur));
        }
        cur.push_str(line);
        cur.push('\n');
    }
    if !cur.is_empty() {
        blocks.push(cur);
    }
    let mut plans = Vec::new();
    for block in blocks.iter().rev().take(transactions) {
        let mut pkgs: Vec<(String, String)> = Vec::new(); // (pkg, old_version)
        for line in block.lines() {
            if line.starts_with("Upgrade:") || line.starts_with("Downgrade:") {
                // Upgrade: curl:amd64 (8.0, 8.1), openssl:amd64 (3.0, 3.1)
                if let Some(colon) = line.find(':') {
                    let list = &line[colon + 1..];
                    // chunk'и вида "pkg:arch (old, new)" разделены "), "
                    for chunk in list.split("), ") {
                        let chunk = chunk.trim().trim_end_matches(')');
                        if let Some((name, vers)) = chunk.split_once(" (") {
                            let mut it = vers.split(", ");
                            if let (Some(old), Some(_new)) = (it.next(), it.next()) {
                                pkgs.push((name.trim().to_string(), old.trim().to_string()));
                            }
                        }
                    }
                }
            }
        }
        if !pkgs.is_empty() {
            let cmd = format!(
                "sudo apt-get install -y {}",
                pkgs.iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>().join(" ")
            );
            plans.push(cmd);
        }
    }
    plans
}

#[tauri::command]
pub fn patch_scan_local(mgr: tauri::State<'_, PatchManager>) -> Result<(usize, usize), String> {
    mgr.scan_local()
}

#[tauri::command]
pub fn patch_scan_all(mgr: tauri::State<'_, PatchManager>) -> Result<Vec<(String, usize, usize)>, String> {
    mgr.scan_all()
}

#[tauri::command]
pub fn patch_list_updates(mgr: tauri::State<'_, PatchManager>, security_only: Option<bool>) -> Result<Vec<serde_json::Value>, String> {
    mgr.list_updates(security_only.unwrap_or(false))
}

#[tauri::command]
pub fn patch_deploy(mgr: tauri::State<'_, PatchManager>, security_only: Option<bool>) -> Result<serde_json::Value, String> {
    mgr.deploy(security_only.unwrap_or(true))
}

#[tauri::command]
pub fn patch_rollback_plan(mgr: tauri::State<'_, PatchManager>, transactions: Option<u32>) -> Result<Vec<String>, String> {
    mgr.rollback_plan(transactions.unwrap_or(1))
}

#[tauri::command]
pub fn patch_status(mgr: tauri::State<'_, PatchManager>) -> Result<serde_json::Value, String> {
    mgr.status()
}

#[tauri::command]
pub async fn patch_ai_assess(mgr: tauri::State<'_, PatchManager>) -> Result<String, String> {
    mgr.inner().ai_assess().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_apt_upgradable() {
        let sample = "Listing...\napt/resolute-security 3.2.1ubuntu0.1 amd64 [upgradable from: 3.2.0]\nbase-files/resolute-updates 14ubuntu6.3 amd64 [upgradable from: 14ubuntu6.2]\ncode/stable 1.145.0 amd64 [upgradable from: 1.144.1]\n";
        let pkgs = parse_apt_upgradable(sample);
        assert_eq!(pkgs.len(), 3);
        assert!(pkgs[0].is_security);
        assert_eq!(pkgs[0].package, "apt");
        assert_eq!(pkgs[0].candidate, "3.2.1ubuntu0.1");
        assert_eq!(pkgs[0].current, "3.2.0");
        assert!(!pkgs[1].is_security);
        assert!(!pkgs[2].is_security);
    }

    #[test]
    fn test_parse_apt_history() {
        let sample = "Start-Date:  2026-11-01  10:00:00\nCommandline: /usr/bin/apt-get install -y curl\nUpgrade: curl:amd64 (8.0, 8.1), openssl:amd64 (3.0, 3.1)\nEnd-Date:  2026-11-01  10:01:00\n\nStart-Date:  2026-11-02  11:00:00\nCommandline: /usr/bin/apt-get upgrade\nUpgrade: vim:amd64 (9.0, 9.1)\nEnd-Date:  2026-11-02  11:01:00\n";
        let plans = parse_apt_history(sample, 1);
        assert_eq!(plans.len(), 1);
        assert!(plans[0].contains("vim:amd64=9.0"));
        let plans2 = parse_apt_history(sample, 2);
        assert_eq!(plans2.len(), 2);
        assert!(plans2[1].contains("curl:amd64=8.0"));
    }

    /// Живой скан: на этой машине apt list --upgradable должен вернуть ≥0 пакетов без ошибок.
    #[test]
    fn live_scan_local() {
        let dir = std::env::temp_dir().join(format!("w420_patch_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("patch.db");
        let _ = std::fs::remove_file(&db);
        let m = PatchManager { db: Mutex::new(db.clone()) };
        m.init(&db);
        let (total, sec) = m.scan_local().expect("apt list должен работать");
        println!("LIVE patch scan: всего={total} security={sec}");
        assert!(total >= 0);
    }
}

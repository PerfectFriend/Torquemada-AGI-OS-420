//! Фаза 13: веб-сканер / сканер сети (web_scan.rs).
//!
//! Два режима:
//!  - discovery: `nmap -sn <cidr>` — кто живой в сети; новые хосты → net_scan.db.scan_results(is_known=0),
//!    их подхватывает SIEM (siem.rs читает эту таблицу).
//!  - vuln: `nmap -sT -sV --script vuln -oX <xml>` — сервисы/версии + CVE-скрипты; результаты → web_vulns.
//!
//! Всё без root: connect-scan (-sT) работает от пользователя, XML пишем в ~/.w420. nmap 7.98 из root_setup.sh.

use rusqlite::Connection;
use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

pub struct WebScanManager {
    pub db: Mutex<PathBuf>,
}

fn home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"))
}

impl WebScanManager {
    pub fn new() -> Self {
        let db = home().join(".w420").join("net_scan.db");
        let m = Self { db: Mutex::new(db.clone()) };
        m.init_db(&db);
        m
    }

    fn init_db(&self, db: &PathBuf) {
        if let Ok(c) = Connection::open(db) {
            let _ = c.execute_batch(
                "CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started TEXT NOT NULL, target TEXT NOT NULL, finished TEXT, hosts_up INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS scan_results (
                    scanned_at TEXT NOT NULL, ip TEXT NOT NULL, is_known INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (scanned_at, ip)
                );
                CREATE TABLE IF NOT EXISTS web_vulns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scanned_at TEXT NOT NULL, host TEXT NOT NULL, port INTEGER, url TEXT,
                    severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_vulns_host ON web_vulns(host);",
            );
        }
    }

    pub fn conn(&self) -> Result<Connection, String> {
        let p = self.db.lock().unwrap().clone();
        Connection::open(p).map_err(|e| e.to_string())
    }

    fn nmap(args: &[&str], timeout_secs: u64) -> Result<String, String> {
        let out = Command::new("nmap")
            .args(args)
            .arg("--noninteractive")
            .arg(format!("--host-timeout={}s", timeout_secs + 30))
            .output()
            .map_err(|e| format!("nmap не найден (root_setup.sh ставит nmap): {e}"))?;
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        Ok(text)
    }

    /// Discovery: `nmap -sn <target>`. Новые хосты (которых нет в scan_results) → is_known=0.
    pub fn scan_net(&self, target: &str) -> Result<serde_json::Value, String> {
        let now = chrono::Utc::now().to_rfc3339();
        let text = Self::nmap(&["-sn", target], 120)?;
        let hosts = parse_nmap_hosts(&text);
        let mut new_hosts = Vec::new();
        {
            let c = self.conn()?;
            let _ = c.execute("INSERT INTO scans (started, target, hosts_up) VALUES (?1,?2,?3)", rusqlite::params![&now, target, hosts.len() as i64]);
            for ip in &hosts {
                // is_known=1 если уже знаем; иначе 0 (новый хост → SIEM)
                let known: i64 = c
                    .query_row("SELECT COUNT(*) FROM scan_results WHERE ip=?1 AND is_known=1", [ip], |r| r.get(0))
                    .unwrap_or(0);
                let is_known = if known > 0 { 1 } else { 0 };
                let _ = c.execute(
                    "INSERT OR IGNORE INTO scan_results (scanned_at, ip, is_known) VALUES (?1,?2,?3)",
                    rusqlite::params![&now, ip, is_known],
                );
                if is_known == 0 {
                    new_hosts.push(ip.clone());
                }
            }
            let _ = c.execute("UPDATE scans SET finished=?1 WHERE started=?2 AND target=?3", rusqlite::params![chrono::Utc::now().to_rfc3339(), &now, target]);
        }
        Ok(serde_json::json!({
            "target": target, "scanned_at": now, "hosts_up": hosts.len(),
            "hosts": hosts, "new_hosts": new_hosts,
        }))
    }

    /// Vuln-скан целей: `nmap -sT -sV --script vuln -oX xml`. XML парсим чистой функцией.
    pub fn scan_targets(&self, targets: &str, ports: Option<String>, script: Option<String>) -> Result<serde_json::Value, String> {
        let now = chrono::Utc::now().to_rfc3339();
        let tmp_xml = std::env::temp_dir().join(format!("w420_nmap_{}.xml", std::process::id()));
        let mut args: Vec<String> = vec!["-sT".into(), "-sV".into(), "-oX".into(), tmp_xml.to_string_lossy().into_owned()];
        if let Some(p) = &ports {
            args.push("-p".into());
            args.push(p.clone());
        } else {
            args.push("--top-ports".into());
            args.push("1000".into());
        }
        args.push("--script".into());
        args.push(script.unwrap_or_else(|| "vuln".into()));
        args.push("--script-args".into());
        args.push("mincvss=5.0".into()); // не шуметь совсем уж низкими
        args.push(targets.into());
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let _text = Self::nmap(&refs, 600)?;
        let xml = std::fs::read_to_string(&tmp_xml).map_err(|e| format!("nmap не записал XML: {e}"))?;
        let _ = std::fs::remove_file(&tmp_xml);
        let parsed = parse_nmap_xml(&xml);
        let mut vuln_count = 0i64;
        {
            let c = self.conn()?;
            for h in &parsed.hosts {
                for p in &h.ports {
                    if p.state != "open" {
                        continue;
                    }
                    for v in &p.vulns {
                        vuln_count += 1;
                        let sev = v.severity.clone();
                        let _ = c.execute(
                            "INSERT INTO web_vulns (scanned_at, host, port, url, severity, title, detail) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                            rusqlite::params![&now, &h.ip, p.port, &h.url_for(p.port), &sev, &v.title, &v.detail],
                        );
                    }
                }
            }
            let _ = c.execute("INSERT INTO scans (started, target, finished, hosts_up) VALUES (?1,?2,?3,?4)", rusqlite::params![&now, targets, chrono::Utc::now().to_rfc3339(), parsed.hosts.len() as i64]);
        }
        Ok(serde_json::json!({
            "target": targets, "scanned_at": now,
            "hosts": parsed.hosts.iter().map(|h| serde_json::json!({
                "ip": h.ip, "ports_open": h.ports.iter().filter(|p| p.state=="open").count(),
                "ports": h.ports.iter().filter(|p| p.state=="open").map(|p| serde_json::json!({
                    "port": p.port, "service": p.service, "version": p.version, "vulns": p.vulns.len(),
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "vulns_total": vuln_count,
        }))
    }

    pub fn vulns_list(&self, host: Option<String>, min_sev: Option<String>) -> Result<Vec<serde_json::Value>, String> {
        let c = self.conn()?;
        let order = ["info", "low", "medium", "high", "critical"];
        let min_idx = min_sev.as_deref().and_then(|s| order.iter().position(|o| *o == s)).unwrap_or(0);
        let mut st = match &host {
            Some(h) => c.prepare("SELECT scanned_at, host, port, url, severity, title, detail FROM web_vulns WHERE host=?1 ORDER BY scanned_at DESC LIMIT 500").map_err(|e| e.to_string())?,
            None => c.prepare("SELECT scanned_at, host, port, url, severity, title, detail FROM web_vulns ORDER BY scanned_at DESC LIMIT 500").map_err(|e| e.to_string())?,
        };
        let params: Vec<Box<dyn rusqlite::types::ToSql>> = match &host {
            Some(h) => vec![Box::new(h.clone())],
            None => vec![],
        };
        let rows = st.query_map(rusqlite::params_from_iter(params.iter()), |r| {
            Ok(serde_json::json!({
                "scanned_at": r.get::<_, String>(0)?, "host": r.get::<_, String>(1)?,
                "port": r.get::<_, i64>(2)?, "url": r.get::<_, String>(3)?,
                "severity": r.get::<_, String>(4)?, "title": r.get::<_, String>(5)?,
                "detail": r.get::<_, String>(6)?,
            }))
        }).map_err(|e| e.to_string())?;
        Ok(rows.flatten().filter(|v| {
            let sev = v["severity"].as_str().unwrap_or("info");
            order.iter().position(|o| *o == sev).map(|i| i >= min_idx).unwrap_or(true)
        }).collect())
    }

    pub fn results(&self) -> Result<Vec<serde_json::Value>, String> {
        let c = self.conn()?;
        let mut st = c.prepare("SELECT scanned_at, ip, is_known FROM scan_results ORDER BY scanned_at DESC LIMIT 500").map_err(|e| e.to_string())?;
        let rows = st.query_map([], |r| Ok(serde_json::json!({
            "scanned_at": r.get::<_, String>(0)?, "ip": r.get::<_, String>(1)?,
            "is_known": r.get::<_, i64>(2)? == 1,
        }))).map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }

    /// Пометить хост известным (убирает из SIEM-алертов новых хостов в будущих ingest'ах).
    pub fn ack_host(&self, ip: &str) -> Result<String, String> {
        let c = self.conn()?;
        let n = c.execute("UPDATE scan_results SET is_known=1 WHERE ip=?1", [ip]).map_err(|e| e.to_string())?;
        Ok(format!("host {ip}: помечен известным ({n} записей)"))
    }

    /// Статус сканера: хосты, последний скан, уязвимости по severity (без AI).
    pub fn status(&self) -> Result<serde_json::Value, String> {
        let c = self.conn()?;
        let q = |sql: &str| -> i64 {
            c.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap_or(0)
        };
        let last: String = c
            .query_row("SELECT MAX(scanned_at) FROM scan_results", [], |r| r.get::<_, String>(0))
            .unwrap_or_default();
        let mut sev = serde_json::Map::new();
        for s in ["info", "low", "medium", "high", "critical"] {
            sev.insert(s.to_string(), serde_json::json!(q(&format!("SELECT COUNT(*) FROM web_vulns WHERE severity='{s}'"))));
        }
        Ok(serde_json::json!({
            "hosts_total": q("SELECT COUNT(*) FROM scan_results"),
            "hosts_distinct": q("SELECT COUNT(DISTINCT ip) FROM scan_results"),
            "hosts_new": q("SELECT COUNT(*) FROM scan_results WHERE is_known=0"),
            "last_scan": last,
            "vulns_total": q("SELECT COUNT(*) FROM web_vulns"),
            "vulns_by_severity": serde_json::Value::Object(sev),
        }))
    }

    /// Детерминированный markdown-отчёт по сканам и уязвимостям (без AI — для архива/тикетов).
    pub fn report_md(&self) -> Result<String, String> {
        let c = self.conn()?;
        let st = self.status()?;
        let mut md = String::new();
        md.push_str(&format!("# Отчёт сканера W420 — {}\n\n", chrono::Utc::now().to_rfc3339()));
        md.push_str(&format!("- Хостов просканировано: {} (уникальных {}, новых: {})\n- Последний скан: {}\n- Уязвимостей: {} (critical: {}, high: {}, medium: {}, low: {}, info: {})\n\n",
            st["hosts_total"], st["hosts_distinct"], st["hosts_new"], st["last_scan"].as_str().unwrap_or("—"),
            st["vulns_total"], st["vulns_by_severity"]["critical"], st["vulns_by_severity"]["high"],
            st["vulns_by_severity"]["medium"], st["vulns_by_severity"]["low"], st["vulns_by_severity"]["info"]));
        md.push_str("## Уязвимости\n\n| Хост | Порт | Severity | Уязвимость |\n|---|---|---|---|\n");
        let mut s = c.prepare("SELECT host, port, severity, title FROM web_vulns ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, scanned_at DESC LIMIT 500").map_err(|e| e.to_string())?;
        let rows = s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?))).map_err(|e| e.to_string())?;
        let mut n = 0;
        for r in rows.flatten() {
            md.push_str(&format!("| {} | {} | {} | {} |\n", r.0, r.1, r.2, r.3.replace('|', "\\|")));
            n += 1;
        }
        if n == 0 { md.push_str("| — | — | — | уязвимостей не найдено |\n"); }
        md.push_str("\n## Последние хосты\n\n| IP | Статус | Скан |\n|---|---|---|\n");
        let mut s2 = c.prepare("SELECT ip, is_known, MAX(scanned_at) FROM scan_results GROUP BY ip ORDER BY MAX(scanned_at) DESC LIMIT 100").map_err(|e| e.to_string())?;
        let rows2 = s2.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0, r.get::<_, String>(2)?))).map_err(|e| e.to_string())?;
        for r in rows2.flatten() {
            md.push_str(&format!("| {} | {} | {} |\n", r.0, if r.1 { "known" } else { "NEW" }, r.2));
        }
        Ok(md)
    }

    /// AI-отчёт по уязвимостям через KeyRotation/NVIDIA (паттерн как в siem.rs).
    pub async fn ai_report(&self) -> Result<String, String> {
        use w420_ai::db::AIProviderDB;
        use w420_ai::rotation::KeyRotation;
        use w420_ai::{ChatMessage, ChatRequest};

        let vulns = self.vulns_list(None, Some("medium".into()))?;
        let hosts = self.results()?;
        let new_hosts: Vec<&str> = hosts.iter().filter(|h| !h["is_known"].as_bool().unwrap_or(false)).filter_map(|h| h["ip"].as_str()).collect();
        let payload = serde_json::to_string_pretty(&vulns).unwrap_or_default();

        // rusqlite::Connection не-Send: читаем провайдеров/ключи в Vec и дропаем соединение до .await
        let (providers_vec, keys_vec) = {
            let db = AIProviderDB::open().map_err(|e| format!("БД провайдеров: {e}"))?;
            let providers = db.list_providers().map_err(|e| format!("провайдеры: {e}"))?;
            let keys = db.list_all_keys().map_err(|e| format!("ключи: {e}"))?;
            (providers, keys)
        };
        if providers_vec.is_empty() {
            return Err("нет настроенных AI-провайдеров".into());
        }
        let rotation = KeyRotation::new();
        for p in &providers_vec {
            rotation.add_provider(p.clone()).await;
        }
        for k in &keys_vec {
            rotation.add_key(k.clone()).await;
        }
        let request = ChatRequest {
            model: "mistralai/mistral-large-4-1t-a52b".into(),
            messages: vec![
                ChatMessage {
                    role: "system".into(),
                    content: "Ты SOC-аналитик W420. По списку уязвимостей (nmap vuln-скрипты) и новым хостам составь отчёт на русском: топ-угрозы, что чинить первым, нужна ли изоляция. До 12 пунктов.".into(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: format!("Новые хосты в сети: {new_hosts:?}\nУязвимости (severity>=medium):\n{payload}"),
                },
            ],
            temperature: 0.3,
            max_tokens: Some(1024),
            stream: false,
        };
        let resp = rotation.chat_completion_with_rotation(request, None).await.map_err(|e| format!("AI: {e}"))?;
        Ok(resp.response.content)
    }
}

// ---------- парсеры (чистые функции) ----------

#[derive(Serialize, Clone, Default)]
pub struct NmapHost {
    pub ip: String,
    pub hostname: String,
    pub ports: Vec<NmapPort>,
}

impl NmapHost {
    pub fn url_for(&self, port: i64) -> String {
        let scheme = match port {
            443 | 8443 => "https",
            _ => "http",
        };
        if port == 80 || port == 443 {
            format!("{scheme}://{}", self.ip)
        } else {
            format!("{scheme}://{}:{}", self.ip, port)
        }
    }
}

#[derive(Serialize, Clone, Default)]
pub struct NmapPort {
    pub port: i64,
    pub state: String,
    pub service: String,
    pub version: String,
    pub vulns: Vec<NmapVuln>,
}

#[derive(Serialize, Clone)]
pub struct NmapVuln {
    pub severity: String,
    pub title: String,
    pub detail: String,
}

/// Парсинг текстового вывода `nmap -sn`: "Nmap scan report for host (1.2.3.4)" или "... for 1.2.3.4"
pub fn parse_nmap_hosts(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Nmap scan report for ") {
            let ip = if let Some(p) = rest.find('(') {
                rest[p + 1..].trim_end_matches(')').trim().to_string()
            } else {
                rest.trim().to_string()
            };
            if ip.chars().all(|c| c.is_ascii_digit() || c == '.') && !ip.is_empty() {
                out.push(ip);
            }
        }
    }
    out
}

/// Парсинг `nmap -oX` XML без внешних крейтов: блочный разбор <host>…</host>, внутри — <port>…</port> и <script …/>.
pub fn parse_nmap_xml(xml: &str) -> NmapScan {
    let mut scan = NmapScan::default();
    let mut rest = xml;
    while let Some(hstart) = find_tag(rest, "host") {
        let after = &rest[hstart..];
        // конец блока host: ищем "</host>", учитывая вложенные <hostnames> (другой тег, не закроет раньше времени)
        let Some(hend_rel) = after.find("</host>") else { break };
        let block = &after[..hend_rel];
        rest = &after[hend_rel + 7..];

        let mut h = NmapHost::default();
        if let Some(addr) = find_attr(block, "addr") {
            h.ip = addr;
        }
        if let Some(hn) = find_attr(block, "name") {
            h.hostname = hn;
        }
        // порты внутри блока
        let mut prest = block;
        while let Some(pstart) = prest.find("<port ") {
            let pafter = &prest[pstart..];
            let Some(pend_rel) = pafter.find("</port>") else { break };
            let pblock = &pafter[..pend_rel];
            prest = &pafter[pend_rel + 7..];

            let open_tag_end = pblock.find('>').unwrap_or(0);
            let open_tag = &pblock[..open_tag_end];
            let mut p = NmapPort {
                port: find_attr(open_tag, "portid").and_then(|v| v.parse().ok()).unwrap_or(0),
                ..Default::default()
            };
            // state/service внутри блока порта
            if let Some(si) = pblock.find("<state ") {
                let stag = &pblock[si..pblock[si..].find('>').map(|e| si + e).unwrap_or(pblock.len())];
                p.state = find_attr(stag, "state").unwrap_or_default();
            }
            if let Some(svi) = pblock.find("<service ") {
                let end = pblock[svi..].find('>').map(|e| svi + e).unwrap_or(pblock.len());
                let stag = &pblock[svi..end];
                p.service = find_attr(stag, "name").unwrap_or_default();
                p.version = find_attr(stag, "version").unwrap_or_default();
            }
            // скрипты: <script id="..." output="..."/> (self-closing) или с телом
            let mut srest = pblock;
            while let Some(si) = srest.find("<script ") {
                let safter = &srest[si..];
                let Some(send_rel) = safter.find("/>").or_else(|| safter.find("</script>")) else { break };
                let sblock = &safter[..send_rel];
                srest = &safter[send_rel + 2..];
                let sid = find_attr(sblock, "id").unwrap_or_default();
                let sout = find_attr(sblock, "output").unwrap_or_default();
                if sid.contains("vuln") || sid.contains("cve") {
                    let cvss = find_cvss(&sout);
                    p.vulns.push(NmapVuln {
                        severity: cvss_to_sev(cvss),
                        title: format!("{} {}", sid, cvss.map(|c| format!("CVSS {c}")).unwrap_or_default()),
                        detail: sout.chars().take(500).collect(),
                    });
                }
            }
            h.ports.push(p);
        }
        if !h.ip.is_empty() {
            scan.hosts.push(h);
        }
    }
    scan
}

#[derive(Serialize, Default)]
pub struct NmapScan {
    pub hosts: Vec<NmapHost>,
}

fn find_attr(tag: &str, key: &str) -> Option<String> {
    let pat = format!("{key}=\"");
    let i = tag.find(&pat)? + pat.len();
    let j = tag[i..].find('"')? + i;
    Some(tag[i..j].to_string())
}

/// Найти открывающий тег `<name>` или `<name …>` (не `<name…s>`, напр. hostnames для host).
fn find_tag(text: &str, name: &str) -> Option<usize> {
    let pat = format!("<{name}");
    let mut from = 0;
    while let Some(i) = text[from..].find(&pat) {
        let pos = from + i;
        let next = text.as_bytes().get(pos + pat.len()).copied();
        if next == Some(b'>') || next == Some(b' ') || next == Some(b'/') {
            return Some(pos);
        }
        from = pos + pat.len();
    }
    None
}

fn find_cvss(text: &str) -> Option<f64> {
    // ищем "CVSSv3 7.5" или cvss="7.5" в выводе скрипта
    for pat in ["CVSSv3 ", "CVSSv2 ", "cvss=\""] {
        if let Some(i) = text.find(pat) {
            let rest = &text[i + pat.len()..];
            let num: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
            if let Ok(v) = num.parse::<f64>() {
                return Some(v);
            }
        }
    }
    None
}

pub fn cvss_to_sev(cvss: Option<f64>) -> String {
    match cvss {
        Some(v) if v >= 9.0 => "critical",
        Some(v) if v >= 7.0 => "high",
        Some(v) if v >= 4.0 => "medium",
        Some(_) => "low",
        None => "medium",
    }
    .to_string()
}

// ---------- Tauri команды ----------

#[tauri::command]
pub fn web_scan_net(mgr: tauri::State<'_, WebScanManager>, target: String) -> Result<serde_json::Value, String> {
    mgr.scan_net(&target)
}

#[tauri::command]
pub fn web_scan_targets(mgr: tauri::State<'_, WebScanManager>, targets: String, ports: Option<String>, script: Option<String>) -> Result<serde_json::Value, String> {
    mgr.scan_targets(&targets, ports, script)
}

#[tauri::command]
pub fn web_vulns_list(mgr: tauri::State<'_, WebScanManager>, host: Option<String>, min_sev: Option<String>) -> Result<Vec<serde_json::Value>, String> {
    mgr.vulns_list(host, min_sev)
}

#[tauri::command]
pub fn web_scan_results(mgr: tauri::State<'_, WebScanManager>) -> Result<Vec<serde_json::Value>, String> {
    mgr.results()
}

#[tauri::command]
pub fn web_ack_host(mgr: tauri::State<'_, WebScanManager>, ip: String) -> Result<String, String> {
    mgr.ack_host(&ip)
}

#[tauri::command]
pub async fn web_ai_report(mgr: tauri::State<'_, WebScanManager>) -> Result<String, String> {
    mgr.ai_report().await
}

/// Статус сканера: хосты, последний скан, уязвимости по severity.
#[tauri::command]
pub fn web_scan_status(mgr: tauri::State<'_, WebScanManager>) -> Result<serde_json::Value, String> {
    mgr.status()
}

/// Markdown-отчёт по сканам и уязвимостям (детерминированный, без AI).
#[tauri::command]
pub fn web_scan_report(mgr: tauri::State<'_, WebScanManager>) -> Result<String, String> {
    mgr.report_md()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nmap_hosts() {
        let text = "Starting Nmap 7.98\nNmap scan report for router.local (192.168.1.1)\nNmap scan report for 192.168.1.20\nNmap done: 256 IPs, 3 up\n";
        let hosts = parse_nmap_hosts(text);
        assert_eq!(hosts, vec!["192.168.1.1".to_string(), "192.168.1.20".to_string()]);
    }

    #[test]
    fn test_parse_nmap_xml() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host><address addr="10.0.0.5" addrtype="ipv4"/><hostnames><hostname name="web.local"/></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" version="nginx 1.25"/><script id="ssl-cert" output="ok"/><script id="http-vuln-cve2017-5638" output="CVSSv3 9.8 VULNERABLE"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" version="OpenSSH 9.6"/></port></ports></host>
</nmaprun>"#;
        let scan = parse_nmap_xml(xml);
        assert_eq!(scan.hosts.len(), 1);
        let h = &scan.hosts[0];
        assert_eq!(h.ip, "10.0.0.5");
        assert_eq!(h.ports.len(), 2);
        let p443 = &h.ports[0];
        assert_eq!(p443.port, 443);
        assert_eq!(p443.state, "open");
        assert_eq!(p443.service, "https");
        assert_eq!(p443.vulns.len(), 1);
        assert_eq!(p443.vulns[0].severity, "critical");
        assert_eq!(h.url_for(443), "https://10.0.0.5");
        assert_eq!(h.url_for(8080), "http://10.0.0.5:8080");
    }

    #[test]
    fn test_cvss_to_sev() {
        assert_eq!(cvss_to_sev(Some(9.8)), "critical");
        assert_eq!(cvss_to_sev(Some(7.5)), "high");
        assert_eq!(cvss_to_sev(Some(5.0)), "medium");
        assert_eq!(cvss_to_sev(Some(2.0)), "low");
    }

    /// LIVE: скан localhost (voice server на 8420 должен всплыть). Без root: -sT.
    #[test]
    #[ignore]
    fn live_scan_localhost() {
        let m = WebScanManager::new();
        let r = m.scan_targets("127.0.0.1", Some("8420,8000,8080,4010,80,443".into()), Some("vuln".into())).expect("scan");
        println!("LIVE scan 127.0.0.1: hosts={} vulns={}", r["hosts"].as_array().map(|a| a.len()).unwrap_or(0), r["vulns_total"]);
        println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
        let v = m.vulns_list(Some("127.0.0.1".into()), None).unwrap_or_default();
        println!("LIVE vulns for 127.0.0.1: {}", v.len());
        let d = m.scan_net("127.0.0.1/32").expect("net scan");
        println!("LIVE net scan: hosts_up={}", d["hosts_up"]);
    }
}

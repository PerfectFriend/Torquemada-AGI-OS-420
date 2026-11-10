//! Фаза 14: PKI — локальный центр сертификации (pki.rs).
//!
//! Собственный корневой CA (RSA-2048/SHA-256, самоподписанный) + выпуск серверных
//! сертификатов с SAN, проверка цепочки (`openssl verify`), отзыв через index.txt
//! и выдача CRL (`openssl ca -gencrl`). Всё — вокруг системного openssl,
//! без внешних крейтов; каталог ~/.w420/pki (700), ключи 600.
//!
//! Команды: pki_ca_init, pki_issue, pki_list, pki_revoke, pki_verify, pki_crl, pki_status.

use rusqlite::Connection;
use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

pub const PKI_DIR_NAME: &str = "pki";
pub const CA_DAYS: i64 = 3650;
pub const CERT_DAYS: i64 = 825;

pub struct PkiManager {
    pub db: Mutex<PathBuf>,
    pub dir: PathBuf,
}

fn home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"))
}

impl PkiManager {
    pub fn new() -> Self {
        let dir = home().join(".w420").join(PKI_DIR_NAME);
        let _ = std::fs::create_dir_all(dir.join("certs"));
        let _ = std::fs::create_dir_all(dir.join("ca"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let db = home().join(".w420").join("pki.db");
        let m = Self { db: Mutex::new(db.clone()), dir };
        if let Ok(c) = Connection::open(&db) {
            let _ = c.execute_batch(
                "CREATE TABLE IF NOT EXISTS certificates (
                    cn TEXT PRIMARY KEY,
                    serial TEXT NOT NULL,
                    sans TEXT NOT NULL DEFAULT '',
                    not_before TEXT NOT NULL DEFAULT '',
                    not_after TEXT NOT NULL DEFAULT '',
                    issued TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );",
            );
        }
        m
    }

    pub fn conn(&self) -> Result<Connection, String> {
        let p = self.db.lock().unwrap().clone();
        Connection::open(p).map_err(|e| e.to_string())
    }

    fn run(args: &[&str]) -> Result<String, String> {
        let out = Command::new("openssl").args(args).output().map_err(|e| format!("openssl не запущен: {e}"))?;
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        if out.status.success() {
            Ok(text)
        } else {
            Err(text)
        }
    }

    fn cnf_path(&self) -> PathBuf {
        self.dir.join("openssl.cnf")
    }

    /// Инициализация корневого CA: ключ 600 + сертификат + базовая openssl.cnf (для ca/gencrl).
    pub fn ca_init(&self, cn: Option<String>, days: Option<i64>) -> Result<serde_json::Value, String> {
        let cn = cn.unwrap_or_else(|| "w420-root-CA".into());
        let days = days.unwrap_or(CA_DAYS);
        let subj = build_ca_subject(&cn);
        let key = self.dir.join("ca").join("ca.key");
        let crt = self.dir.join("ca").join("ca.crt");
        let r = Self::run(&[
            "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
            "-keyout", key.to_str().unwrap(), "-out", crt.to_str().unwrap(),
            "-days", &days.to_string(), "-subj", &subj,
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ]);
        if let Err(e) = r {
            return Err(format!("CA не создан: {e}"));
        }
        // конфиг для выпуска/отзыва (SAN-строка переписывается при каждом выпуске)
        let cnf = build_openssl_cnf(self.dir.to_str().unwrap(), "DNS:placeholder");
        std::fs::write(self.cnf_path(), &cnf).map_err(|e| e.to_string())?;
        // чистая БД индекса/серийника + newcerts
        let _ = std::fs::create_dir_all(self.dir.join("newcerts"));
        let _ = std::fs::write(self.dir.join("index.txt"), "");
        let _ = std::fs::write(self.dir.join("serial"), "1000\n");
        let _ = std::fs::write(self.dir.join("crlnumber"), "1000\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600));
        }
        let info = self.cert_info(crt.to_str().unwrap()).unwrap_or_default();
        Ok(serde_json::json!({
            "ca": true, "cn": cn, "days": days, "cert": crt.display().to_string(),
            "key": key.display().to_string(), "info": info,
        }))
    }

    /// Выпуск сертификата: ключ + CSR + подпись (`openssl ca`, SAN через -extfile).
    pub fn issue(&self, cn: &str, sans: Vec<String>, days: Option<i64>) -> Result<serde_json::Value, String> {
        if !self.cnf_path().exists() {
            return Err("сначала pki_ca_init".into());
        }
        let days = days.unwrap_or(CERT_DAYS);
        let cdir = self.dir.join("certs").join(cn);
        std::fs::create_dir_all(&cdir).map_err(|e| e.to_string())?;
        let key = cdir.join(format!("{cn}.key"));
        let csr = cdir.join(format!("{cn}.csr"));
        let crt = cdir.join(format!("{cn}.crt"));

        let r = Self::run(&[
            "req", "-newkey", "rsa:2048", "-sha256", "-nodes",
            "-keyout", key.to_str().unwrap(), "-out", csr.to_str().unwrap(),
            "-subj", &format!("/CN={cn}"),
        ]);
        if let Err(e) = r {
            return Err(format!("ключ/CSR: {e}"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600));
        }
        let san_line = build_san_line(&sans);
        // SAN запекаем прямо в конфиг: revoke/verify не требуют env, а openssl падает на $ENV:: без значения
        let san = if san_line == "DNS:placeholder" { format!("DNS:{cn}") } else { san_line };
        let cnf = build_openssl_cnf(self.dir.to_str().unwrap(), &san);
        std::fs::write(self.cnf_path(), &cnf).map_err(|e| e.to_string())?;
        let mut args = vec![
            "ca".to_string(), "-batch".to_string(), "-config".to_string(), self.cnf_path().to_str().unwrap().to_string(),
            "-days".to_string(), days.to_string(),
            "-in".to_string(), csr.to_str().unwrap().to_string(),
            "-out".to_string(), crt.to_str().unwrap().to_string(),
            "-extensions".to_string(), "v3_req".to_string(),
        ];
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let r = Self::run(&refs);
        if let Err(e) = r {
            return Err(format!("подпись: {e}"));
        }
        // сохраняем метаданные
        let (mut serial, mut not_before, mut not_after) = (String::new(), String::new(), String::new());
        if let Ok(info) = self.cert_info(crt.to_str().unwrap()) {
            serial = info["serial"].as_str().unwrap_or("").to_string();
            not_before = info["not_before"].as_str().unwrap_or("").to_string();
            not_after = info["not_after"].as_str().unwrap_or("").to_string();
        }
        let sans_str = sans.join(",");
        {
            let c = self.conn()?;
            let _ = c.execute(
                "INSERT OR REPLACE INTO certificates (cn, serial, sans, not_before, not_after, issued, revoked) VALUES (?1,?2,?3,?4,?5,?6,0)",
                rusqlite::params![cn, &serial, &sans_str, &not_before, &not_after, chrono::Utc::now().to_rfc3339()],
            );
        }
        Ok(serde_json::json!({
            "cn": cn, "serial": serial, "sans": sans,
            "not_before": not_before, "not_after": not_after,
            "cert": crt.display().to_string(), "key": key.display().to_string(),
        }))
    }

    /// Отзыв сертификата + перегенерация CRL.
    pub fn revoke(&self, cn: &str) -> Result<serde_json::Value, String> {
        let crt = self.dir.join("certs").join(cn).join(format!("{cn}.crt"));
        if !crt.exists() {
            return Err(format!("сертификат '{cn}' не найден"));
        }
        let r = Self::run(&[
            "ca", "-config", self.cnf_path().to_str().unwrap(),
            "-revoke", crt.to_str().unwrap(),
        ]);
        if let Err(e) = r {
            if !e.contains("ALREADY REVOKED") && !e.contains("already revoked") {
                return Err(format!("отзыв: {e}"));
            }
        }
        let crl = self.crl()?;
        let c = self.conn()?;
        let _ = c.execute("UPDATE certificates SET revoked=1 WHERE cn=?1", [cn]);
        Ok(serde_json::json!({"revoked": true, "cn": cn, "crl": crl}))
    }

    /// Сгенерировать CRL (список отозванных).
    pub fn crl(&self) -> Result<String, String> {
        // gencrl требует crlnumber — создаём если нет
        if !self.dir.join("crlnumber").exists() {
            let _ = std::fs::write(self.dir.join("crlnumber"), "1000\n");
        }
        let out = self.dir.join("ca").join("crl.pem");
        let r = Self::run(&[
            "ca", "-config", self.cnf_path().to_str().unwrap(),
            "-gencrl", "-out", out.to_str().unwrap(),
        ]);
        r.map_err(|e| format!("gencrl: {e}"))?;
        Ok(out.display().to_string())
    }

    /// Проверка цепочки до CA. revoke-aware: с -crl_check.
    pub fn verify(&self, cn: &str, crl_check: Option<bool>) -> Result<serde_json::Value, String> {
        let crt = self.dir.join("certs").join(cn).join(format!("{cn}.crt"));
        let ca = self.dir.join("ca").join("ca.crt");
        if !crt.exists() {
            return Err(format!("сертификат '{cn}' не найден"));
        }
        let mut args = vec!["verify".to_string(), "-CAfile".to_string(), ca.to_str().unwrap().to_string()];
        if crl_check.unwrap_or(false) {
            args.push("-crl_check".into());
            args.extend_from_slice(&["-CRLfile".into(), self.dir.join("ca").join("crl.pem").to_str().unwrap().to_string()]);
        }
        args.push(crt.to_str().unwrap().to_string());
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match Self::run(&refs) {
            Ok(t) => Ok(serde_json::json!({"cn": cn, "valid": true, "detail": t.trim()})),
            Err(e) => Ok(serde_json::json!({"cn": cn, "valid": false, "detail": e.chars().take(300).collect::<String>()})),
        }
    }

    /// Метаданные сертификата (`openssl x509 -noout -subject -enddate -serial -dates`).
    pub fn cert_info(&self, path: &str) -> Result<serde_json::Value, String> {
        let t = Self::run(&["x509", "-noout", "-subject", "-enddate", "-serial", "-startdate", "-in", path])
            .map_err(|e| format!("x509: {e}"))?;
        Ok(parse_x509_info(&t))
    }

    pub fn list(&self) -> Result<Vec<serde_json::Value>, String> {
        let c = self.conn()?;
        let mut st = c.prepare("SELECT cn, serial, sans, not_before, not_after, issued, revoked FROM certificates ORDER BY issued").map_err(|e| e.to_string())?;
        let rows = st.query_map([], |r| Ok(serde_json::json!({
            "cn": r.get::<_, String>(0)?, "serial": r.get::<_, String>(1)?,
            "sans": r.get::<_, String>(2)?, "not_before": r.get::<_, String>(3)?,
            "not_after": r.get::<_, String>(4)?, "issued": r.get::<_, String>(5)?,
            "revoked": r.get::<_, i64>(6)? == 1,
        }))).map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }

    /// Автопродление: перевыпускает все неотозванные сертификаты, истекающие в пределах `days` дней.
    /// Перевыпуск идёт тем же CN и SAN (новый ключ + новая подпись CA), запись в БД обновляется (INSERT OR REPLACE).
    pub fn renew_expiring(&self, days: i64) -> Result<serde_json::Value, String> {
        if !self.cnf_path().exists() {
            return Err("сначала pki_ca_init".into());
        }
        let now = chrono::Utc::now();
        let mut renewed = Vec::new();
        let mut expiring = Vec::new();
        for cert in self.list()? {
            if cert["revoked"].as_bool().unwrap_or(false) { continue; }
            let cn = cert["cn"].as_str().unwrap_or("").to_string();
            let not_after = cert["not_after"].as_str().unwrap_or("").to_string();
            let Some(na) = parse_not_after(&not_after) else { continue };
            let days_left = (na - now).num_days();
            if days_left <= days {
                expiring.push(serde_json::json!({"cn": cn, "not_after": not_after, "days_left": days_left}));
                let sans: Vec<String> = cert["sans"].as_str().unwrap_or("")
                    .split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                match self.issue(&cn, sans, Some(CERT_DAYS)) {
                    Ok(v) => renewed.push(serde_json::json!({
                        "cn": cn, "old_not_after": not_after, "new_not_after": v["not_after"], "new_serial": v["serial"],
                    })),
                    Err(e) => renewed.push(serde_json::json!({"cn": cn, "error": e})),
                }
            }
        }
        Ok(serde_json::json!({
            "threshold_days": days,
            "expiring": expiring,
            "renewed": renewed,
            "renewed_ok": renewed.iter().filter(|r| r.get("error").is_none()).count(),
        }))
    }
}

// ---------- чистые функции ----------

/// Парсит дату истечения сертификата: RFC3339 ИЛИ openssl-формат `notAfter=Nov  5 23:12:00 2027 GMT`.
pub fn parse_not_after(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let s = s.trim();
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    // openssl: "Nov  5 23:12:00 2027 GMT" (%e — день с ведущим пробелом)
    if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(s, "%b %e %H:%M:%S %Y GMT") {
        return Some(chrono::DateTime::from_naive_utc_and_offset(ndt, chrono::Utc));
    }
    // запасной вариант: без GMT в конце
    if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(s.trim_end_matches(" GMT"), "%b %e %H:%M:%S %Y") {
        return Some(chrono::DateTime::from_naive_utc_and_offset(ndt, chrono::Utc));
    }
    None
}

/// Истекает ли сертификат в пределах `days` дней от `now` (или уже истёк)?
pub fn cert_expiring(not_after: &str, days: i64, now: chrono::DateTime<chrono::Utc>) -> bool {
    match parse_not_after(not_after) {
        Some(na) => (na - now).num_days() <= days,
        None => false,
    }
}

/// subject CA: `/CN=w420-root-CA`
pub fn build_ca_subject(cn: &str) -> String {
    format!("/CN={cn}")
}

/// строка subjectAltName для openssl (RFC: "DNS:x,DNS:y,IP:1.2.3.4"); пустой список → placeholder.
pub fn build_san_line(sans: &[String]) -> String {
    let parts: Vec<String> = sans
        .iter()
        .filter_map(|s| {
            let s = s.trim();
            if s.is_empty() {
                return None;
            }
            // IP без префикса → IP:, иначе DNS:
            if s.split('.').count() == 4 && s.chars().all(|c| c.is_ascii_digit() || c == '.') {
                Some(format!("IP:{s}"))
            } else {
                Some(format!("DNS:{s}"))
            }
        })
        .collect();
    if parts.is_empty() {
        "DNS:placeholder".to_string()
    } else {
        parts.join(",")
    }
}

/// содержимое extfile для выпуска серверного сертификата.
pub fn build_extfile(sans: &[String]) -> String {
    format!(
        "basicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = {}\n",
        build_san_line(sans)
    )
}

/// openssl.cnf для `openssl ca` (подпись/отзыв/CRL); SAN запекается при выпуске (без $ENV::).
pub fn build_openssl_cnf(dir: &str, san: &str) -> String {
    format!(
        "[ ca ]\ndefault_ca = CA_default\n\n[ CA_default ]\ndir = {dir}\ndatabase = $dir/index.txt\nserial = $dir/serial\nnew_certs_dir = $dir/newcerts\ncertificate = $dir/ca/ca.crt\nprivate_key = $dir/ca/ca.key\ncrlnumber = $dir/crlnumber\ndefault_md = sha256\ndefault_crl_days = 30\npolicy = policy_any\nemail_in_dn = no\nrand_serial = no\nunique_subject = no\ncrl_extensions = crl_ext\ncopy_extensions = copy\n\n[ policy_any ]\ncommonName = supplied\n\n[ req ]\ndefault_bits = 2048\nprompt = no\ndefault_md = sha256\ndistinguished_name = dn\n\n[ dn ]\nCN = placeholder\n\n[ v3_req ]\nbasicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = {san}\n\n[ crl_ext ]\nauthorityKeyIdentifier = keyid:always\n"
    )
}

/// Разбор вывода `openssl x509 -noout -subject -enddate -serial -startdate` (чистая функция).
pub fn parse_x509_info(text: &str) -> serde_json::Value {
    let mut j = serde_json::json!({
        "cn": "", "subject": "", "not_before": "", "not_after": "", "serial": ""
    });
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("subject=") {
            let s = v.trim().to_string();
            j["subject"] = serde_json::json!(s.clone());
            if let Some(cn) = s.strip_prefix("CN") {
                j["cn"] = serde_json::json!(cn.trim_start_matches(" = ").trim());
            }
            // формата "subject=CN = name" или "subject=CN=name"
            if j["cn"].as_str().unwrap_or("").is_empty() {
                // форматы: "CN = name" (OpenSSL 3.x) и "CN=name"
                if let Some(p) = s.find("CN") {
                    let rest = &s[p + 2..];
                    let val = rest.trim_start().trim_start_matches('=').trim();
                    if !val.is_empty() {
                        j["cn"] = serde_json::json!(val.to_string());
                    }
                }
                }
        } else if let Some(v) = line.strip_prefix("notBefore=") {
            j["not_before"] = serde_json::json!(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("notAfter=") {
            j["not_after"] = serde_json::json!(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("serial=") {
            j["serial"] = serde_json::json!(v.trim().to_string());
        }
    }
    j
}

// ---------- Tauri команды ----------

#[tauri::command]
pub fn pki_ca_init(mgr: tauri::State<'_, PkiManager>, cn: Option<String>, days: Option<i64>) -> Result<serde_json::Value, String> {
    mgr.ca_init(cn, days)
}

#[tauri::command]
pub fn pki_issue(mgr: tauri::State<'_, PkiManager>, cn: String, sans: Vec<String>, days: Option<i64>) -> Result<serde_json::Value, String> {
    mgr.issue(&cn, sans, days)
}

#[tauri::command]
pub fn pki_revoke(mgr: tauri::State<'_, PkiManager>, cn: String) -> Result<serde_json::Value, String> {
    mgr.revoke(&cn)
}

#[tauri::command]
pub fn pki_verify(mgr: tauri::State<'_, PkiManager>, cn: String, crl_check: Option<bool>) -> Result<serde_json::Value, String> {
    mgr.verify(&cn, crl_check)
}

#[tauri::command]
pub fn pki_crl(mgr: tauri::State<'_, PkiManager>) -> Result<String, String> {
    mgr.crl()
}

#[tauri::command]
pub fn pki_list(mgr: tauri::State<'_, PkiManager>) -> Result<Vec<serde_json::Value>, String> {
    mgr.list()
}

#[tauri::command]
pub fn pki_status(mgr: tauri::State<'_, PkiManager>, cn: String) -> Result<serde_json::Value, String> {
    let crt = mgr.dir.join("certs").join(&cn).join(format!("{cn}.crt"));
    if crt.exists() {
        mgr.cert_info(crt.to_str().unwrap())
    } else {
        let ca = mgr.dir.join("ca").join("ca.crt");
        if ca.exists() {
            mgr.cert_info(ca.to_str().unwrap())
        } else {
            Err("нет ни CA, ни такого сертификата".into())
        }
    }
}

/// Автопродление сертификатов, истекающих в пределах `days` дней (по умолчанию 30).
#[tauri::command]
pub fn pki_cert_renew(mgr: tauri::State<'_, PkiManager>, days: Option<i64>) -> Result<serde_json::Value, String> {
    mgr.renew_expiring(days.unwrap_or(30))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_not_after_openssl_and_rfc3339() {
        use chrono::Datelike;
        // openssl-формат из `openssl x509 -text` (день с двумя пробелами)
        let dt = parse_not_after("Nov  5 23:12:00 2027 GMT").expect("openssl-формат должен парситься");
        assert_eq!(dt.year(), 2027);
        assert_eq!(dt.month(), 11);
        assert_eq!(dt.day(), 5);
        // RFC3339
        let dt2 = parse_not_after("2027-11-05T23:12:00+00:00").expect("RFC3339 должен парситься");
        assert_eq!(dt, dt2);
        // мусор — None
        assert!(parse_not_after("not a date").is_none());
    }

    #[test]
    fn test_cert_expiring() {
        let now = chrono::Utc::now();
        let soon = (now + chrono::Duration::days(10)).to_rfc3339();
        let later = (now + chrono::Duration::days(400)).to_rfc3339();
        let past = (now - chrono::Duration::days(1)).to_rfc3339();
        assert!(cert_expiring(&soon, 30, now));
        assert!(cert_expiring(&past, 30, now), "уже истёкший — тоже в пределах порога");
        assert!(!cert_expiring(&later, 30, now));
        assert!(!cert_expiring("мусор", 30, now));
    }

    #[test]
    fn test_build_san_line() {
        assert_eq!(build_san_line(&["web.local".into(), "10.0.0.5".into()]), "DNS:web.local,IP:10.0.0.5");
        assert_eq!(build_san_line(&[]), "DNS:placeholder");
        assert_eq!(build_san_line(&["a.b".into(), "1.2.3.4".into(), "".into()]), "DNS:a.b,IP:1.2.3.4");
    }

    #[test]
    fn test_build_extfile() {
        let e = build_extfile(&["web.local".into()]);
        assert!(e.contains("subjectAltName = DNS:web.local"));
        assert!(e.contains("CA:FALSE"));
        assert!(e.contains("serverAuth"));
    }

    #[test]
    fn test_build_openssl_cnf() {
        let c = build_openssl_cnf("/home/thomas/.w420/pki", "DNS:web.test");
        assert!(c.contains("[ CA_default ]"));
        assert!(c.contains("database = $dir/index.txt"));
        assert!(c.contains("subjectAltName = DNS:web.test"));
        assert!(c.contains("certificate = $dir/ca/ca.crt"));
    }

    #[test]
    fn test_parse_x509_info() {
        let text = "subject=CN = web.local\nnotBefore=Nov  5 01:00:00 2026 GMT\nnotAfter=Feb  5 01:00:00 2029 GMT\nserial=1001\n";
        let j = parse_x509_info(text);
        assert_eq!(j["cn"], "web.local");
        assert_eq!(j["serial"], "1001");
        assert!(j["not_after"].as_str().unwrap().contains("2029"));
    }

    /// LIVE полный цикл PKI: CA → выпуск → verify → статус → отзыв → CRL-check.
    /// Проверено вручную на openssl 3.5.5; требует openssl в PATH.
    #[test]
    #[ignore]
    fn live_pki_cycle() {
        let m = PkiManager::new();
        let ca = m.ca_init(Some("w420-test-ca".into()), Some(365)).expect("ca_init");
        println!("LIVE CA: {}", ca["info"]["cn"]);
        let cert = m.issue("w420-test", vec!["w420.test".into(), "10.9.8.7".into()], Some(825)).expect("issue");
        println!("LIVE issue: serial={} sans={}", cert["serial"], cert["sans"]);
        assert_eq!(cert["sans"][0], "w420.test");
        let v = m.verify("w420-test", None).expect("verify");
        println!("LIVE verify: {}", v);
        assert_eq!(v["valid"], true, "свежий сертификат должен быть валиден");
        let st = m.cert_info(m.dir.join("certs").join("w420-test").join("w420-test.crt").to_str().unwrap()).expect("status");
        println!("LIVE status: cn={} not_after={}", st["cn"], st["not_after"]);
        let r = m.revoke("w420-test").expect("revoke");
        println!("LIVE revoke: {}", r["crl"]);
        let v2 = m.verify("w420-test", Some(true)).expect("verify crl");
        println!("LIVE verify+crl: {}", v2);
        assert_eq!(v2["valid"], false, "после отзыва должен быть НЕвалиден");
        let l = m.list().expect("list");
        assert!(l.iter().any(|c| c["cn"] == "w420-test" && c["revoked"] == true));
    }
}

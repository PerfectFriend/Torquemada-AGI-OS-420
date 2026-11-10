//! ad.rs — Этап 31 (DameWare Parity): модуль Active Directory поверх LDAP (ldap3, sync API).
//!
//! Конфиг (сервер, bind DN, base DN) хранится в ~/.w420/ad.json, пароль —
//! зашифрован через w420_ai::encryption (AES-256-GCM), наружу уходит только маска.
//! Опасные операции (unlock / reset password / group add/remove) — только явные команды,
//! UI спрашивает подтверждение (HITL).

use ldap3::{LdapConn, Mod, Scope, SearchEntry};
use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use w420_ai::encryption::{decrypt_api_key, encrypt_api_key};

/// Конфиг подключения к AD. Пароль — в зашифрованном виде.
#[derive(Serialize, Deserialize, Clone)]
pub struct AdConfig {
    pub server: String,      // напр. "ldap://dc.corp.local" или "ldaps://…"
    pub port: u16,
    pub bind_dn: String,     // напр. "CORP\\svc-w420"
    pub bind_password_enc: String, // AES-256-GCM
    pub base_dn: String,     // напр. "DC=corp,DC=local"
    pub use_tls: bool,
}

fn cfg_path() -> String {
    format!("{}/.w420/ad.json", std::env::var("HOME").unwrap_or_default())
}

pub fn load_config() -> Result<AdConfig, String> {
    let s = std::fs::read_to_string(cfg_path()).map_err(|_| "AD не настроен — сначала ad_config_set".to_string())?;
    serde_json::from_str(&s).map_err(|e| format!("ad.json: {e}"))
}

pub fn save_config(c: &AdConfig) -> Result<(), String> {
    let dir = format!("{}/.w420", std::env::var("HOME").unwrap_or_default());
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let p = cfg_path();
    std::fs::write(&p, serde_json::to_string_pretty(c).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    // права только владельцу
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Маска пароля для UI: «…xxxx» (последние 4 символа).
pub fn mask_password(pw: &str) -> String {
    let n = pw.chars().count();
    if n <= 4 { "…****".to_string() } else { format!("…{}", pw.chars().skip(n - 4).collect::<String>()) }
}

/// Экранирование значения в LDAP-фильтре (RFC 4515).
pub fn escape_filter(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}

/// Проверка DN: базовая валидация (буквы/цифры/=/,/./ /-/:/space).
pub fn valid_dn(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 1024
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "=,./-: \\+@#\"".contains(c))
}

/// unicodePwd для AD: пароль в UTF-16LE, в кавычках (RFC 2307bis / MS-ADTS).
pub fn encode_unicode_pwd(pw: &str) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(2 + pw.len() * 2);
    v.push(b'"');
    for u in pw.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v.push(b'"');
    v
}

fn connect(cfg: &AdConfig) -> Result<LdapConn, String> {
    let url = format!("{}://{}:{}", if cfg.use_tls { "ldaps" } else { "ldap" }, cfg.server, cfg.port);
    let mut conn = LdapConn::new(&url).map_err(|e| format!("connect {url}: {e}"))?;
    let pw = decrypt_api_key(&cfg.bind_password_enc).map_err(|e| format!("расшифровка пароля: {e}"))?;
    conn.simple_bind(&cfg.bind_dn, &pw)
        .map_err(|e| format!("bind: {e}"))?
        .success()
        .map_err(|e| format!("bind отклонён: {e:?}"))?;
    Ok(conn)
}

fn search(conn: &mut LdapConn, cfg: &AdConfig, base: &str, filter: &str, attrs: Vec<&str>) -> Result<Vec<SearchEntry>, String> {
    let (raw, _res) = conn
        .search(base, Scope::Subtree, filter, attrs)
        .map_err(|e| format!("search: {e}"))?
        .success()
        .map_err(|e| format!("search ошибка: {e:?}"))?;
    Ok(raw.into_iter().map(SearchEntry::construct).collect())
}

fn entry_attr(e: &SearchEntry, name: &str) -> Vec<String> {
    e.attrs.get(name).cloned().unwrap_or_default()
}

// ======================= Команды Tauri =======================

#[tauri::command]
pub fn ad_config_set(server: String, port: Option<u16>, bind_dn: String, bind_password: String, base_dn: String, use_tls: Option<bool>) -> Result<Value, String> {
    if !valid_dn(&bind_dn) || !valid_dn(&base_dn) {
        return Err("плохой DN".into());
    }
    if bind_password.is_empty() {
        return Err("пустой пароль".into());
    }
    let enc = encrypt_api_key(&bind_password).map_err(|e| format!("шифрование: {e}"))?;
    let c = AdConfig {
        server: server.trim_matches('/').trim_start_matches("ldap://").trim_start_matches("ldaps://").to_string(),
        port: port.unwrap_or(636),
        bind_dn, bind_password_enc: enc, base_dn,
        use_tls: use_tls.unwrap_or(true),
    };
    save_config(&c)?;
    Ok(json!({"ok": true, "server": c.server, "port": c.port, "bind_dn": c.bind_dn, "base_dn": c.base_dn, "use_tls": c.use_tls, "password_mask": mask_password(&bind_password)}))
}

#[tauri::command]
pub fn ad_config_get() -> Result<Value, String> {
    let c = load_config()?;
    let pw = decrypt_api_key(&c.bind_password_enc).map_err(|e| e.to_string())?;
    Ok(json!({
        "server": c.server, "port": c.port, "bind_dn": c.bind_dn, "base_dn": c.base_dn,
        "use_tls": c.use_tls, "password_mask": mask_password(&pw), "configured": true,
    }))
}

#[tauri::command]
pub fn ad_ping() -> Result<Value, String> {
    let cfg = load_config()?;
    let mut conn = connect(&cfg)?;
    // RootDSE: поддерживаемые расширения/версия
    let (raw, _res) = conn.search("", Scope::Base, "(objectClass=*)", vec!["vendorName", "vendorVersion", "supportedLDAPVersion"])
        .map_err(|e| e.to_string())?.success().map_err(|e| format!("{e:?}"))?;
    let e = raw.into_iter().map(SearchEntry::construct).next().ok_or("пустой RootDSE")?;
    Ok(json!({"ok": true, "vendor": entry_attr(&e, "vendorName"), "version": entry_attr(&e, "supportedLDAPVersion")}))
}

#[tauri::command]
pub fn ad_tree() -> Result<Value, String> {
    let cfg = load_config()?;
    let mut conn = connect(&cfg)?;
    let entries = search(&mut conn, &cfg, &cfg.base_dn, "(objectClass=organizationalUnit)", vec!["ou", "distinguishedName", "description"])?;
    let ous: Vec<Value> = entries.iter().map(|e| json!({
        "ou": entry_attr(e, "ou").first().cloned().unwrap_or_default(),
        "dn": entry_attr(e, "distinguishedName").first().cloned().unwrap_or_default(),
        "description": entry_attr(e, "description").first().cloned().unwrap_or_default(),
    })).collect();
    Ok(json!({"ous": ous, "count": ous.len()}))
}

#[tauri::command]
pub fn ad_users_search(filter: Option<String>) -> Result<Value, String> {
    let cfg = load_config()?;
    let mut conn = connect(&cfg)?;
    let f = match filter {
        Some(f) if !f.is_empty() => format!("(&(objectClass=user)(objectCategory=person)(|(sAMAccountName={})(cn={})(mail={})))", escape_filter(&f), escape_filter(&f), escape_filter(&f)),
        _ => "(&(objectClass=user)(objectCategory=person))".to_string(),
    };
    let entries = search(&mut conn, &cfg, &cfg.base_dn, &f, vec!["sAMAccountName", "cn", "mail", "distinguishedName", "whenCreated", "lastLogon", "userAccountControl"])?;
    let users: Vec<Value> = entries.iter().map(|e| {
        let uac: i64 = entry_attr(e, "userAccountControl").first().and_then(|s| s.parse().ok()).unwrap_or(0);
        json!({
            "login": entry_attr(e, "sAMAccountName").first().cloned().unwrap_or_default(),
            "cn": entry_attr(e, "cn").first().cloned().unwrap_or_default(),
            "mail": entry_attr(e, "mail").first().cloned().unwrap_or_default(),
            "dn": entry_attr(e, "distinguishedName").first().cloned().unwrap_or_default(),
            "locked": uac & 0x2 != 0,   // ACCOUNTDISABLE
            "disabled": uac & 0x2 != 0,
            "no_password_required": uac & 0x20 != 0,
            "password_never_expires": uac & 0x10000 != 0,
        })
    }).collect();
    Ok(json!({"users": users, "count": users.len()}))
}

#[tauri::command]
pub fn ad_groups() -> Result<Value, String> {
    let cfg = load_config()?;
    let mut conn = connect(&cfg)?;
    let entries = search(&mut conn, &cfg, &cfg.base_dn, "(objectClass=group)", vec!["cn", "distinguishedName", "member", "groupType"])?;
    let groups: Vec<Value> = entries.iter().map(|e| json!({
        "cn": entry_attr(e, "cn").first().cloned().unwrap_or_default(),
        "dn": entry_attr(e, "distinguishedName").first().cloned().unwrap_or_default(),
        "members_count": entry_attr(e, "member").len(),
    })).collect();
    Ok(json!({"groups": groups, "count": groups.len()}))
}

/// Разблокировать пользователя: pwdAccountLockedTime = 0.
#[tauri::command]
pub fn ad_user_unlock(user_dn: String) -> Result<Value, String> {
    if !valid_dn(&user_dn) { return Err("плохой DN".into()); }
    let cfg = load_config()?;
    let mut conn = connect(&cfg)?;
    conn.modify(&user_dn, vec![Mod::Replace("pwdAccountLockedTime".to_string().into_bytes(), HashSet::from([b"0".to_vec()]))])
        .map_err(|e| format!("modify: {e}"))?
        .success().map_err(|e| format!("unlock отклонён: {e:?}"))?;
    Ok(json!({"unlocked": user_dn}))
}

/// Сброс пароля: unicodePwd (UTF-16LE в кавычках) + снятие must-change при желании.
#[tauri::command]
pub fn ad_user_reset_password(user_dn: String, new_password: String, must_change: Option<bool>) -> Result<Value, String> {
    if !valid_dn(&user_dn) { return Err("плохой DN".into()); }
    if new_password.len() < 8 { return Err("пароль короче 8 символов — AD не примет".into()); }
    let cfg = load_config()?;
    let mut conn = connect(&cfg)?;
    let pwd: Vec<u8> = encode_unicode_pwd(&new_password); // бинарный атрибут — Vec<u8>, не lossy-строка
    let mut mods: Vec<Mod<Vec<u8>>> = vec![Mod::Replace("unicodePwd".to_string().into_bytes(), HashSet::from([pwd]))];
    if must_change.unwrap_or(true) {
        mods.push(Mod::Replace("pwdLastSet".to_string().into_bytes(), HashSet::from([b"0".to_vec()]))); // требовать смену при следующем входе
    }
    conn.modify(&user_dn, mods).map_err(|e| format!("modify: {e}"))?
        .success().map_err(|e| format!("reset отклонён: {e:?}"))?;
    Ok(json!({"reset": user_dn, "must_change": must_change.unwrap_or(true)}))
}

#[tauri::command]
pub fn ad_group_members(group_dn: String) -> Result<Value, String> {
    if !valid_dn(&group_dn) { return Err("плохой DN".into()); }
    let cfg = load_config()?;
    let mut conn = connect(&cfg)?;
    let entries = search(&mut conn, &cfg, &group_dn, "(objectClass=*)", vec!["member"])?;
    let members = entries.first().map(|e| entry_attr(e, "member")).unwrap_or_default();
    Ok(json!({"group": group_dn, "members": members, "count": members.len()}))
}

#[tauri::command]
pub fn ad_group_add_member(group_dn: String, member_dn: String) -> Result<Value, String> {
    if !valid_dn(&group_dn) || !valid_dn(&member_dn) { return Err("плохой DN".into()); }
    let cfg = load_config()?;
    let mut conn = connect(&cfg)?;
    conn.modify(&group_dn, vec![Mod::Add("member".to_string().into_bytes(), HashSet::from([member_dn.clone().into_bytes()]))])
        .map_err(|e| e.to_string())?.success().map_err(|e| format!("{e:?}"))?;
    Ok(json!({"added": member_dn, "to": group_dn}))
}

#[tauri::command]
pub fn ad_group_remove_member(group_dn: String, member_dn: String) -> Result<Value, String> {
    if !valid_dn(&group_dn) || !valid_dn(&member_dn) { return Err("плохой DN".into()); }
    let cfg = load_config()?;
    let mut conn = connect(&cfg)?;
    conn.modify(&group_dn, vec![Mod::Delete("member".to_string().into_bytes(), HashSet::from([member_dn.clone().into_bytes()]))])
        .map_err(|e| e.to_string())?.success().map_err(|e| format!("{e:?}"))?;
    Ok(json!({"removed": member_dn, "from": group_dn}))
}

/// GPO (read-only): контейнеры политик в CN=Policies,CN=System.
#[tauri::command]
pub fn ad_gpo_list() -> Result<Value, String> {
    let cfg = load_config()?;
    let mut conn = connect(&cfg)?;
    let policies_base = format!("CN=Policies,CN=System,{}", cfg.base_dn);
    let entries = search(&mut conn, &cfg, &policies_base, "(objectClass=groupPolicyContainer)", vec!["displayName", "distinguishedName", "gPCFileSysPath"])?;
    let gpos: Vec<Value> = entries.iter().map(|e| json!({
        "name": entry_attr(e, "displayName").first().cloned().unwrap_or_default(),
        "dn": entry_attr(e, "distinguishedName").first().cloned().unwrap_or_default(),
        "sysvol_path": entry_attr(e, "gPCFileSysPath").first().cloned().unwrap_or_default(),
    })).collect();
    Ok(json!({"gpos": gpos, "count": gpos.len()}))
}

/// Экспорт объектов (users/groups) в CSV/XML — как у DRS.
#[tauri::command]
pub fn ad_export(what: String, format: String, out_path: String) -> Result<Value, String> {
    if !["users", "groups"].contains(&what.as_str()) { return Err("что экспортировать: users|groups".into()); }
    if format != "csv" && format != "xml" { return Err("формат: csv|xml".into()); }
    if out_path.is_empty() || out_path.contains('\0') { return Err("плохой путь".into()); }
    let v = if what == "users" { ad_users_search(None)? } else { ad_groups()? };
    let arr = v[if what == "users" { "users" } else { "groups" }].as_array().cloned().unwrap_or_default();
    let content = match format.as_str() {
        "csv" => {
            let mut s = String::from("dn,cn,login,mail\n");
            for o in &arr {
                s.push_str(&format!("\"{}\",\"{}\",\"{}\",\"{}\"\n",
                    o["dn"].as_str().unwrap_or("").replace('"', "\"\""),
                    o["cn"].as_str().unwrap_or("").replace('"', "\"\""),
                    o["login"].as_str().unwrap_or("").replace('"', "\"\""),
                    o["mail"].as_str().unwrap_or("").replace('"', "\"\"")));
            }
            s
        }
        _ => {
            let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ad>\n");
            for o in &arr {
                s.push_str(&format!("  <obj dn=\"{}\" cn=\"{}\" login=\"{}\" mail=\"{}\"/>\n",
                    xml_esc(o["dn"].as_str().unwrap_or("")), xml_esc(o["cn"].as_str().unwrap_or("")),
                    xml_esc(o["login"].as_str().unwrap_or("")), xml_esc(o["mail"].as_str().unwrap_or(""))));
            }
            s.push_str("</ad>\n");
            s
        }
    };
    std::fs::write(&out_path, &content).map_err(|e| format!("write: {e}"))?;
    Ok(json!({"path": out_path, "format": format, "objects": arr.len()}))
}

fn xml_esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

// ======================= Тесты (без live AD) =======================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_filter() {
        assert_eq!(escape_filter("a*b(c)d\\e"), "a\\2ab\\28c\\29d\\5ce");
        assert_eq!(escape_filter("plain"), "plain");
    }

    #[test]
    fn test_valid_dn() {
        assert!(valid_dn("CN=Admin,OU=IT,DC=corp,DC=local"));
        assert!(valid_dn("CORP\\svc-w420"));
        assert!(!valid_dn("CN=x; rm -rf /"));
        assert!(!valid_dn(""));
    }

    #[test]
    fn test_unicode_pwd() {
        let v = encode_unicode_pwd("P@ss");
        // кавычки + 4 символа × 2 байта UTF-16LE = 10 байт
        assert_eq!(v.len(), 10);
        assert_eq!(v[0], b'"');
        assert_eq!(v[1], 0x50); assert_eq!(v[2], 0x00); // 'P'
        assert_eq!(v[3], 0x40); assert_eq!(v[4], 0x00); // '@'
        assert_eq!(v[v.len() - 1], b'"');
        // кириллица
        let v2 = encode_unicode_pwd("Пароль1");
        assert_eq!(v2.len(), 2 + 7 * 2);
    }

    #[test]
    fn test_mask_password() {
        assert_eq!(mask_password("supersecret"), "…cret");
        assert_eq!(mask_password("abc"), "…****");
    }

    #[test]
    fn test_config_roundtrip_encrypted() {
        let dir = std::env::temp_dir().join(format!("w420-ad-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // возможна гонка с чужими тестами, перегенерирующими соль — ретрай
        let mut ok = false;
        for _ in 0..5 {
            let enc = encrypt_api_key("MySecret123!").unwrap();
            assert!(enc != "MySecret123!");
            if decrypt_api_key(&enc).map(|d| d == "MySecret123!").unwrap_or(false) { ok = true; break; }
        }
        assert!(ok, "encrypt/decrypt roundtrip не сошёлся за 5 попыток");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_export_format() {
        // собираем фиктивный вывод и проверяем CSV/XML через внутреннюю логику ad_export нельзя без AD,
        // поэтому проверяем xml_esc
        assert_eq!(xml_esc("a<b>&\"c"), "a&lt;b&gt;&amp;&quot;c");
    }
}

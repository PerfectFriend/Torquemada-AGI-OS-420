//! smartcard.rs — Этап 33 (DameWare Parity): Smart-Card / PKCS#11 (OpenSC).
//!
//! Тонкая обёртка над `pkcs11-tool` (пакет opensc): читатели, слоты, токены,
//! сертификаты, подпись данных закрытым ключом. PIN передаётся аргументом и
//! НИГДЕ не логируется/не уходит во фронтенд обратно. Если opensc не
//! установлен — команды возвращают понятную ошибку, UI это показывает.

use serde_json::{json, Value};
use std::process::Command;

fn module_path() -> String {
    // типичные пути модуля OpenSC
    for p in ["/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
              "/usr/lib/opensc-pkcs11.so",
              "/usr/lib64/opensc-pkcs11.so",
              "/usr/lib/onepin-opensc-pkcs11.so"] {
        if std::path::Path::new(p).is_file() { return p.to_string(); }
    }
    "opensc-pkcs11.so".to_string()
}

fn have_tool() -> bool {
    std::env::var("PATH").ok().map(|p| p.split(':').any(|d| std::path::Path::new(&format!("{d}/pkcs11-tool")).is_file())).unwrap_or(false)
}

fn run_tool(args: &[&str]) -> Result<String, String> {
    if !have_tool() {
        return Err("не установлен pkcs11-tool (пакет opensc)".into());
    }
    let out = Command::new("pkcs11-tool")
        .arg("--module").arg(module_path())
        .args(args)
        .output().map_err(|e| format!("spawn: {e}"))?;
    let s = String::from_utf8_lossy(&out.stdout).to_string()
        + &String::from_utf8_lossy(&out.stderr);
    if !out.status.success() && !s.trim().is_empty() {
        // некоторые команды (например --list-slots без карты) частично успешны
        return Ok(s);
    }
    Ok(s)
}

// ======================= Чистые парсеры (тестируются) =======================

/// Парсинг вывода `pkcs11-tool --list-slots`.
pub fn parse_slots(stdout: &str) -> Vec<Value> {
    let mut slots = Vec::new();
    let mut cur = json!({});
    let mut in_slot = false;
    for line in stdout.lines() {
        let t = line.trim();
        if t.starts_with("Slot ") {
            if in_slot { slots.push(cur.clone()); }
            // "Slot 0 (0x0): ACS ACR122 ..." -> id между "Slot " и первой ':'
            let id = t.trim_start_matches("Slot ").split(':').next().unwrap_or("").trim().to_string();
            cur = json!({"slot": id});
            in_slot = true;
        } else if in_slot {
            if let Some((k, v)) = t.split_once(':') {
                cur[k.trim().to_lowercase().replace(' ', "_")] = Value::String(v.trim().to_string());
            }
        }
    }
    if in_slot { slots.push(cur); }
    slots
}

/// Парсинг `--list-token-slots` → метки токенов.
pub fn parse_token_labels(stdout: &str) -> Vec<Value> {
    parse_slots(stdout).into_iter()
        .filter(|s| s.get("token_present").and_then(|v| v.as_str()) == Some("true")
                 || s.get("token_label").map(|v| !v.as_str().unwrap_or("").is_empty()).unwrap_or(false))
        .map(|mut s| {
            let label = s.get("token_label").cloned().unwrap_or(Value::String("?".into()));
            s.as_object_mut().unwrap().insert("label".into(), label);
            s
        })
        .collect()
}

/// Парсинг `--list-objects` (сертификаты/ключи): блоки "Certificate Object"/"Private Key Object".
pub fn parse_objects(stdout: &str) -> Vec<Value> {
    let mut objs = Vec::new();
    let mut cur = json!({});
    let mut kind: Option<String> = None;
    for line in stdout.lines() {
        let t = line.trim();
        if t.starts_with("Certificate Object") { if !cur.is_null() && kind.is_some() { objs.push(cur.clone()); } kind = Some("certificate".into()); cur = json!({"type": "certificate"}); }
        else if t.starts_with("Private Key Object") { if !cur.is_null() && kind.is_some() { objs.push(cur.clone()); } kind = Some("private_key".into()); cur = json!({"type": "private_key"}); }
        else if t.starts_with("Public Key Object") { if !cur.is_null() && kind.is_some() { objs.push(cur.clone()); } kind = Some("public_key".into()); cur = json!({"type": "public_key"}); }
        else if line.starts_with("  ") {
            if let Some((kk, vv)) = t.split_once(':') {
                cur[kk.trim().to_lowercase().replace(' ', "_")] = Value::String(vv.trim().to_string());
            }
        }
    }
    if kind.is_some() && !cur.is_null() { objs.push(cur); }
    objs
}

/// Валидация PIN: только цифры, длина 4..16 (не логируем значение!).
pub fn valid_pin(pin: &str) -> bool {
    (4..=16).contains(&pin.len()) && pin.chars().all(|c| c.is_ascii_digit())
}

// ======================= Команды Tauri =======================

#[tauri::command]
pub fn sc_status() -> Result<Value, String> {
    Ok(json!({
        "tool": have_tool(),
        "module": module_path(),
        "module_exists": std::path::Path::new(&module_path()).is_file(),
    }))
}

#[tauri::command]
pub fn sc_slots() -> Result<Value, String> {
    let s = run_tool(&["--list-slots"])?;
    Ok(json!({"slots": parse_slots(&s), "raw": s}))
}

#[tauri::command]
pub fn sc_tokens() -> Result<Value, String> {
    let s = run_tool(&["--list-token-slots"])?;
    Ok(json!({"tokens": parse_token_labels(&s)}))
}

#[tauri::command]
pub fn sc_objects() -> Result<Value, String> {
    let s = run_tool(&["--list-objects"])?;
    Ok(json!({"objects": parse_objects(&s)}))
}

/// Сертификаты (только публичные данные, без приватных ключей).
#[tauri::command]
pub fn sc_certs() -> Result<Value, String> {
    let objs = sc_objects()?;
    let certs: Vec<Value> = objs["objects"].as_array().cloned().unwrap_or_default()
        .into_iter().filter(|o| o["type"] == "certificate").collect();
    Ok(json!({"certs": certs, "count": certs.len()}))
}

/// Подпись данных (hex или текст) закрытым ключом с данным ID. PIN не логируется.
#[tauri::command]
pub fn sc_sign(key_id: String, data_hex: String, pin: String) -> Result<Value, String> {
    if !valid_pin(&pin) { return Err("PIN: 4..16 цифр".into()); }
    if !data_hex.chars().all(|c| c.is_ascii_hexdigit()) || data_hex.len() % 2 != 0 {
        return Err("data_hex: hex чётной длины".into());
    }
    let tmp_in = format!("{}/.w420/.sc-sign-in.bin", std::env::var("HOME").unwrap_or_default());
    let tmp_out = format!("{}/.w420/.sc-sign-out.bin", std::env::var("HOME").unwrap_or_default());
    std::fs::create_dir_all(format!("{}/.w420", std::env::var("HOME").unwrap_or_default())).map_err(|e| e.to_string())?;
    std::fs::write(&tmp_in, hex::decode(&data_hex).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let out = Command::new("pkcs11-tool")
        .arg("--module").arg(module_path())
        .args(["--sign", "--id", &key_id, "--input-file", &tmp_in, "--output-file", &tmp_out,
               "--pin", &pin, "--mechanism", "RSA-PKCS"])
        .output().map_err(|e| format!("spawn: {e}"))?;
    let _ = std::fs::remove_file(&tmp_in);
    let _ = std::fs::remove_file(&tmp_out);
    if !out.status.success() {
        return Err(format!("sign: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let sig = std::fs::read(&tmp_out).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&tmp_out);
    Ok(json!({"key_id": key_id, "signature_hex": hex::encode(&sig), "sig_len": sig.len()}))
}

// ======================= Тесты =======================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_slots() {
        let s = "Slot 0 (0x0): ACS ACR122 00 00\n  token state:   present\n  token label:   W420 Card\n  serial number: AB12CD\nSlot 1 (0x1): empty\n  token state:   absent\n";
        let slots = parse_slots(s);
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0]["slot"], "0 (0x0)");
        assert_eq!(slots[0]["token_label"], "W420 Card");
        let toks = parse_token_labels(s);
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0]["label"], "W420 Card");
    }

    #[test]
    fn test_parse_objects() {
        let s = "Certificate Object; type: X.509 certificate\n  label:      SignCert\n  ID:         01\nPrivate Key Object; RSA\n  label:      SignKey\n  ID:         01\n  Usage:      sign\n";
        let objs = parse_objects(s);
        assert_eq!(objs.len(), 2);
        assert_eq!(objs[0]["type"], "certificate");
        assert_eq!(objs[0]["label"], "SignCert");
        assert_eq!(objs[1]["type"], "private_key");
        assert_eq!(objs[1]["usage"], "sign");
    }

    #[test]
    fn test_valid_pin() {
        assert!(valid_pin("1234"));
        assert!(valid_pin("123456789012"));
        assert!(!valid_pin("123"));
        assert!(!valid_pin("12345a"));
        assert!(!valid_pin(""));
        assert!(!valid_pin(&"1".repeat(17)));
    }
}

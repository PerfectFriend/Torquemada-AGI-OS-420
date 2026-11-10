//! did.rs — Этап 22: персистентный DIGITAL ID.
//!
//! Пара ECDSA P-256 генерируется в Rust (k256). Приватный ключ (PKCS#8 DER)
//! шифруется AES-256-GCM (PBKDF2-HMAC-SHA256, 600k итераций) и хранится в
//! keyring ~/.w420/did/keyring.json (0600). DID = "did:w420:" + HEX(SHA-256(pubkey))[..20].
//! Подпись — ECDSA по SHA-256(challenge) (prehash). Во фронтенд уходят
//! только did, публичный ключ и подписи — приватный ключ не покидает Rust.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use signature::hazmat::{PrehashSigner, PrehashVerifier};
use std::fs;
use std::path::PathBuf;

/// Число итераций PBKDF2 (как в wallet.rs — единая политика KDF).
const KDF_ITER: u32 = 600_000;
/// Длина отпечатка DID: 20 байт → 40 hex-символов.
const FP_LEN: usize = 20;

fn keyring_path() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "нет HOME".to_string())?;
    Ok(PathBuf::from(home).join(".w420/did/keyring.json"))
}

/// Запись keyring: did + зашифрованный приватный ключ.
#[derive(Serialize, Deserialize, Clone)]
struct DidEntry {
    did: String,
    label: String,
    pubkey_hex: String, // SEC1 uncompressed (65 байт, префикс 04)
    salt: String,       // hex
    nonce: String,      // hex (12 байт)
    ct: String,         // hex: AES-256-GCM над PKCS#8 DER приватного ключа
    created: String,    // RFC3339
}

#[derive(Serialize, Deserialize, Default)]
struct DidKeyring {
    entries: Vec<DidEntry>,
}

fn load_keyring() -> Result<DidKeyring, String> {
    let p = keyring_path()?;
    match fs::read_to_string(&p) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| format!("keyring повреждён: {e}")),
        Err(_) => Ok(DidKeyring::default()),
    }
}

fn save_keyring(k: &DidKeyring) -> Result<(), String> {
    let p = keyring_path()?;
    fs::create_dir_all(p.parent().unwrap()).map_err(|e| format!("mkdir: {e}"))?;
    let s = serde_json::to_string_pretty(k).map_err(|e| format!("json: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(&p, s).map_err(|e| format!("write: {e}"))?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).map_err(|e| format!("chmod: {e}"))?;
    }
    #[cfg(not(unix))]
    fs::write(&p, s).map_err(|e| format!("write: {e}"))?;
    Ok(())
}

/// KDF + шифрование.
fn seal(priv_der: &[u8], password: &str) -> Result<(String, String, String), String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, KDF_ITER, &mut key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), priv_der)
        .map_err(|_| "AES-GCM encrypt failed".to_string())?;
    Ok((hex::encode(salt), hex::encode(nonce), hex::encode(ct)))
}

/// Расшифровка приватного ключа.
fn open_ct(ct_hex: &str, nonce_hex: &str, salt_hex: &str, password: &str) -> Result<Vec<u8>, String> {
    let salt = hex::decode(salt_hex).map_err(|e| format!("salt hex: {e}"))?;
    let nonce = hex::decode(nonce_hex).map_err(|e| format!("nonce hex: {e}"))?;
    let ct = hex::decode(ct_hex).map_err(|e| format!("ct hex: {e}"))?;
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, KDF_ITER, &mut key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    cipher
        .decrypt(Nonce::from_slice(&nonce), ct.as_slice())
        .map_err(|_| "неверный пароль или повреждённый keyring".to_string())
}

/// DID из публичного ключа: did:w420: + hex(sha256(SEC1))[..20].
fn did_from_pubkey(vk: &VerifyingKey) -> String {
    let sec1 = vk.to_encoded_point(false);
    let mut h = Sha256::new();
    h.update(sec1.as_bytes());
    let fp = hex::encode(&h.finalize()[..FP_LEN]);
    format!("did:w420:{fp}")
}

/// Сгенерировать identity, зашифровать приватный ключ в keyring.
#[tauri::command]
pub fn did_create(password: String, label: Option<String>) -> Result<Value, String> {
    if password.len() < 8 {
        return Err("пароль минимум 8 символов".into());
    }
    let sk = SigningKey::random(&mut rand::thread_rng());
    let vk = VerifyingKey::from(&sk);
    let der = sk.to_pkcs8_der().map_err(|e| format!("pkcs8: {e}"))?;
    let (salt, nonce, ct) = seal(der.as_bytes(), &password)?;
    let did = did_from_pubkey(&vk);
    let entry = DidEntry {
        did: did.clone(),
        label: label.unwrap_or_else(|| "w420".to_string()),
        pubkey_hex: hex::encode(vk.to_encoded_point(false).as_bytes()),
        salt,
        nonce,
        ct,
        created: chrono::Utc::now().to_rfc3339(),
    };
    let mut k = load_keyring()?;
    k.entries.retain(|e| e.did != did);
    k.entries.push(entry);
    save_keyring(&k)?;
    Ok(json!({
        "did": did,
        "pubkey_hex": hex::encode(vk.to_encoded_point(false).as_bytes()),
        "scheme": "ECDSA P-256 + SHA-256 (prehash) · AES-256-GCM at rest · PBKDF2 600k",
        "note": "приватный ключ хранится только в зашифрованном виде; наружу — did и подписи"
    }))
}

/// Список DID (без приватных данных).
#[tauri::command]
pub fn did_list() -> Result<Value, String> {
    let k = load_keyring()?;
    let list: Vec<Value> = k
        .entries
        .iter()
        .map(|e| json!({"did": e.did, "label": e.label, "created": e.created, "pubkey_hex": e.pubkey_hex}))
        .collect();
    Ok(json!({"count": list.len(), "dids": list}))
}

/// Статус DID-подсистемы.
#[tauri::command]
pub fn did_status() -> Result<Value, String> {
    let k = load_keyring()?;
    Ok(json!({"count": k.entries.len(), "path": keyring_path()?.to_string_lossy(), "scheme": "ECDSA P-256, AES-256-GCM at rest"}))
}

/// Подписать challenge (hex или текст) приватным ключом DID.
#[tauri::command]
pub fn did_sign_challenge(did: String, password: String, challenge: String) -> Result<Value, String> {
    let k = load_keyring()?;
    let e = k.entries.iter().find(|e| e.did == did).ok_or("DID не найден в keyring")?;
    let der = open_ct(&e.ct, &e.nonce, &e.salt, &password)?;
    let sk = SigningKey::from_pkcs8_der(&der).map_err(|_| "невалидный приватный ключ".to_string())?;
    // challenge интерпретируем как hex, если валидный, иначе как текст
    let msg: Vec<u8> = if challenge.len() % 2 == 0 && hex::decode(&challenge).is_ok() {
        hex::decode(&challenge).unwrap()
    } else {
        challenge.clone().into_bytes()
    };
    // ECDSA по SHA-256(challenge) — prehash, семантически идентично WebCrypto {ECDSA, SHA-256}
    let digest = Sha256::digest(&msg);
    let sig: Signature = sk.sign_prehash(&digest).map_err(|e| format!("sign: {e}"))?;
    Ok(json!({
        "did": did,
        "challenge": challenge,
        "sig_hex": hex::encode(sig.to_der().as_bytes()),
        "pubkey_hex": e.pubkey_hex,
    }))
}

/// Проверить подпись challenge для DID (публичным ключом из keyring).
#[tauri::command]
pub fn did_verify(did: String, challenge: String, sig_hex: String) -> Result<Value, String> {
    let k = load_keyring()?;
    let e = k.entries.iter().find(|e| e.did == did).ok_or("DID не найден в keyring")?;
    let pk = hex::decode(&e.pubkey_hex).map_err(|x| format!("pubkey hex: {x}"))?;
    let vk = VerifyingKey::from_sec1_bytes(&pk).map_err(|_| "невалидный публичный ключ".to_string())?;
    let sig_bytes = hex::decode(sig_hex.trim()).map_err(|x| format!("sig hex: {x}"))?;
    let sig = Signature::from_der(&sig_bytes).map_err(|_| "невалидная DER-подпись".to_string())?;
    let msg: Vec<u8> = if challenge.len() % 2 == 0 && hex::decode(&challenge).is_ok() {
        hex::decode(&challenge).unwrap()
    } else {
        challenge.into_bytes()
    };
    let digest = Sha256::digest(&msg);
    let ok = vk.verify_prehash(&digest, &sig).is_ok();
    Ok(json!({"did": did, "valid": ok}))
}

/// Удалить DID из keyring.
#[tauri::command]
pub fn did_remove(did: String) -> Result<Value, String> {
    let mut k = load_keyring()?;
    let before = k.entries.len();
    k.entries.retain(|e| e.did != did);
    save_keyring(&k)?;
    Ok(json!({"removed": before - k.entries.len()}))
}

// ============================================================================
// Тесты
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// HOME — процессный env, поэтому DID-тесты сериализуем мьютексом.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn tmp_home(tag: &str) {
        // Изолируем keyring в уникальный HOME для тестов
        let dir = std::env::temp_dir().join(format!("w420-did-test-{tag}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::env::set_var("HOME", &dir);
    }

    #[test]
    fn test_create_list_sign_verify_roundtrip() {
        let _g = TEST_LOCK.lock().unwrap();
        tmp_home("rt");
        let r = did_create("test-password-1".to_string(), None).unwrap();
        let did = r["did"].as_str().unwrap().to_string();
        assert!(did.starts_with("did:w420:") && did.len() == "did:w420:".len() + 40);

        let list = did_list().unwrap();
        assert_eq!(list["count"].as_u64().unwrap(), 1);

        let ch = hex::encode(b"challenge-123");
        let s = did_sign_challenge(did.clone(), "test-password-1".into(), ch.clone()).unwrap();
        let v = did_verify(did.clone(), ch.clone(), s["sig_hex"].as_str().unwrap().to_string()).unwrap();
        assert_eq!(v["valid"], true);

        // другой challenge → невалидно
        let v2 = did_verify(did, hex::encode(b"other"), s["sig_hex"].as_str().unwrap().to_string()).unwrap();
        assert_eq!(v2["valid"], false);
    }

    #[test]
    fn test_wrong_password_fails() {
        let _g = TEST_LOCK.lock().unwrap();
        tmp_home("wp");
        let r = did_create("correct-pass".to_string(), None).unwrap();
        let did = r["did"].as_str().unwrap().to_string();
        let res = did_sign_challenge(did, "wrong-pass".into(), hex::encode(b"x"));
        assert!(res.is_err());
    }

    #[test]
    fn test_unknown_did_fails() {
        let _g = TEST_LOCK.lock().unwrap();
        tmp_home("ud");
        assert!(did_sign_challenge("did:w420:00".into(), "password123".into(), "ab".into()).is_err());
        assert!(did_verify("did:w420:00".into(), "ab".into(), "00".into()).is_err());
    }

    #[test]
    fn test_short_password_rejected() {
        let _g = TEST_LOCK.lock().unwrap();
        tmp_home("sp");
        assert!(did_create("short".to_string(), None).is_err());
    }

    #[test]
    fn test_remove() {
        let _g = TEST_LOCK.lock().unwrap();
        tmp_home("rm");
        let r = did_create("password-123".to_string(), Some("l1".into())).unwrap();
        let did = r["did"].as_str().unwrap().to_string();
        let rm = did_remove(did.clone()).unwrap();
        assert_eq!(rm["removed"].as_u64().unwrap(), 1);
        assert_eq!(did_list().unwrap()["count"].as_u64().unwrap(), 0);
    }

    #[test]
    fn test_deterministic_did_from_same_key() {
        // did зависит только от pubkey: один и тот же ключ → один и тот же did
        let sk = SigningKey::random(&mut rand::thread_rng());
        let vk = VerifyingKey::from(&sk);
        assert_eq!(did_from_pubkey(&vk), did_from_pubkey(&vk));
        let sk2 = SigningKey::random(&mut rand::thread_rng());
        assert_ne!(did_from_pubkey(&vk), did_from_pubkey(&VerifyingKey::from(&sk2)));
    }
}

//! pqc.rs — Этап 21: постквантовое шифрование vault (гибридная схема).
//!
//! Обёртывание данных: ML-KEM-768 (FIPS 203) даёт общий секрет через
//! инкапсуляцию к публичному ключу → HKDF-SHA256 → ключ AES-256-GCM.
//! Конверт: (kem_ct, nonce, ct). Классический слой AES-256-GCM остаётся,
//! PQC добавляет стойкость транспорта ключа к квантовым атакам.
//! Всё считается в Rust; во фронтенд уходят только байты конверта.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;

/// Расшифровочный ключ ML-KEM-768.
pub type PqcSk = DecapsulationKey<MlKem768Params>;
/// Публичный ключ инкапсуляции ML-KEM-768.
pub type PqcPk = EncapsulationKey<MlKem768Params>;
/// Описание схемы (для UI и отчётов).
pub const PQC_SCHEME: &str = "ML-KEM-768 + HKDF-SHA256 + AES-256-GCM";

/// HKDF-SHA256: общий секрет → ключ AES-256 (домен разделения w420-vault-pqc-v1).
fn derive_aes_key(ss: &[u8]) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha256>::new(None, ss);
    let mut key = [0u8; 32];
    hk.expand(b"w420-vault-pqc-v1", &mut key).map_err(|_| "HKDF expand failed".to_string())?;
    Ok(key)
}

/// hex → Array фиксированной длины (тип задаёт нужный размер).
fn array_from_hex<T: EncodedSizeUser>(hex_str: &str) -> Result<Encoded<T>, String> {
    let s = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
    let bytes = hex::decode(s).map_err(|e| format!("невалидный hex: {e}"))?;
    Array::try_from(bytes.as_slice()).map_err(|_| "неверная длина байтов для ключа/конверта".to_string())
}

/// Сгенерировать пару ключей. `sk_hex` показывается ОДИН раз (хранит владелец).
#[tauri::command]
pub fn vault_pqc_keygen() -> Result<Value, String> {
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng);
    Ok(json!({
        "pk_hex": hex::encode(ek.as_bytes().as_slice()),
        "sk_hex": hex::encode(dk.as_bytes().as_slice()),
        "scheme": PQC_SCHEME,
        "note": "приватный ключ показан один раз — сохраните; без него расшифровка невозможна"
    }))
}

/// Конверт с постквантовым ключом.
#[derive(Serialize, Deserialize, Clone)]
pub struct PqcEnvelope {
    pub kem_ct: String, // hex: шифротекст ML-KEM (общий секрет извлекается при декапсуляции)
    pub nonce: String,  // hex: nonce AES-256-GCM
    pub ct: String,     // hex: шифротекст AES-256-GCM
    pub scheme: String,
}

/// Зашифровать текст в PQC-конверт для владельца `pk_hex`.
#[tauri::command]
pub fn vault_pqc_seal(pk_hex: String, text: String) -> Result<PqcEnvelope, String> {
    let ek_bytes = array_from_hex::<PqcPk>(&pk_hex)?;
    let ek = PqcPk::from_bytes(&ek_bytes);
    let mut rng = rand::thread_rng();
    let (ct_kem, ss) = ek.encapsulate(&mut rng).map_err(|_| "ML-KEM encapsulate failed".to_string())?;
    let key = derive_aes_key(ss.as_slice())?;
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rng, &mut nonce);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), text.as_bytes())
        .map_err(|_| "AES-GCM encrypt failed".to_string())?;
    Ok(PqcEnvelope {
        kem_ct: hex::encode(ct_kem.as_slice()),
        nonce: hex::encode(nonce),
        ct: hex::encode(ct),
        scheme: PQC_SCHEME.to_string(),
    })
}

/// Расшифровать PQC-конверт приватным ключом `sk_hex`.
#[tauri::command]
pub fn vault_pqc_open(
    sk_hex: String,
    kem_ct: String,
    nonce: String,
    ct: String,
) -> Result<Value, String> {
    let dk_bytes = array_from_hex::<PqcSk>(&sk_hex)?;
    let dk = PqcSk::from_bytes(&dk_bytes);
    let ct_bytes = hex::decode(kem_ct.trim().strip_prefix("0x").unwrap_or(kem_ct.trim()))
        .map_err(|e| format!("kem_ct hex: {e}"))?;
    let ct_kem_bytes: ml_kem::Ciphertext<MlKem768> =
        Array::try_from(ct_bytes.as_slice()).map_err(|_| "неверная длина kem_ct".to_string())?;
    let ss = dk
        .decapsulate(&ct_kem_bytes)
        .map_err(|_| "ML-KEM decapsulate failed".to_string())?;
    let key = derive_aes_key(ss.as_slice())?;
    let nonce_bytes = hex::decode(nonce.trim()).map_err(|e| format!("nonce hex: {e}"))?;
    let ct_bytes = hex::decode(ct.trim()).map_err(|e| format!("ct hex: {e}"))?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let pt = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ct_bytes.as_slice())
        .map_err(|_| "неверный ключ или повреждённый конверт".to_string())?;
    let text = String::from_utf8(pt).map_err(|e| format!("utf8: {e}"))?;
    Ok(json!({"text": text, "scheme": PQC_SCHEME}))
}

/// Статус PQC-слоя (бейдж LIVE/SIM).
#[tauri::command]
pub fn vault_pqc_status() -> Result<Value, String> {
    Ok(json!({"scheme": PQC_SCHEME, "level": "NIST Level 3 (ML-KEM-768)", "live": true}))
}

// ============================================================================
// Тесты
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_sizes_and_distinctness() {
        let a = vault_pqc_keygen().unwrap();
        let b = vault_pqc_keygen().unwrap();
        assert_ne!(a["pk_hex"], b["pk_hex"]);
        assert_ne!(a["sk_hex"], b["sk_hex"]);
        assert_eq!(a["pk_hex"].as_str().unwrap().len(), 1184 * 2); // ek ML-KEM-768
        assert_eq!(a["sk_hex"].as_str().unwrap().len(), 2400 * 2); // dk ML-KEM-768
    }

    #[test]
    fn test_seal_open_roundtrip() {
        let kg = vault_pqc_keygen().unwrap();
        let pk = kg["pk_hex"].as_str().unwrap().to_string();
        let sk = kg["sk_hex"].as_str().unwrap().to_string();
        let text = "секрет PQC · заметка vault · ΩBTC-адрес 0xf39F…2266";
        let env = vault_pqc_seal(pk, text.to_string()).unwrap();
        assert_eq!(env.kem_ct.len(), 1088 * 2); // ciphertext ML-KEM-768
        assert_eq!(env.nonce.len(), 24); // 12 байт
        let opened = vault_pqc_open(sk, env.kem_ct, env.nonce, env.ct).unwrap();
        assert_eq!(opened["text"], text);
        assert_eq!(opened["scheme"], PQC_SCHEME);
    }

    #[test]
    fn test_open_wrong_key_fails() {
        let kg1 = vault_pqc_keygen().unwrap();
        let kg2 = vault_pqc_keygen().unwrap();
        let env = vault_pqc_seal(kg1["pk_hex"].as_str().unwrap().to_string(), "данные".to_string()).unwrap();
        let wrong = vault_pqc_open(
            kg2["sk_hex"].as_str().unwrap().to_string(),
            env.kem_ct.clone(), env.nonce.clone(), env.ct.clone(),
        );
        assert!(wrong.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let kg = vault_pqc_keygen().unwrap();
        let env = vault_pqc_seal(kg["pk_hex"].as_str().unwrap().to_string(), "данные".to_string()).unwrap();
        let mut bytes = hex::decode(&env.ct).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF; // порча тега AES-GCM
        let res = vault_pqc_open(
            kg["sk_hex"].as_str().unwrap().to_string(),
            env.kem_ct, env.nonce, hex::encode(bytes),
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_bad_keys_rejected() {
        assert!(vault_pqc_seal("не hex".to_string(), "x".to_string()).is_err());
        assert!(vault_pqc_seal("00".to_string(), "x".to_string()).is_err()); // короткий pk
        let kg = vault_pqc_keygen().unwrap();
        let env = vault_pqc_seal(kg["pk_hex"].as_str().unwrap().to_string(), "x".to_string()).unwrap();
        // sk неверной длины
        assert!(vault_pqc_open("00".to_string(), env.kem_ct, env.nonce, env.ct).is_err());
    }
}

//! Модуль шифрования: защита API-ключей на диске.
//!
//! Используется симметричное шифрование AES-256-GCM.
//! Ключ шифрования выводится из machine-id системы через PBKDF2 с солью,
//! хранящейся в ~/.w420/ai_encryption_salt.
//!
//! Это гарантирует, что API-ключи не хранятся в открытом виде даже если база данных
//! будет скопирована злоумышленником.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use getrandom::getrandom;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};
use crate::AIError;

/// Порядок итераций PBKDF2 для вывода ключа шифрования.
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Длина соли в байтах.
const SALT_LEN: usize = 16;

/// Длина ключа AES-256 в байтах.
const KEY_LEN: usize = 32;

/// Имя файла с солью для шифрования.
const SALT_FILE: &str = "ai_encryption_salt";

/// Зашифрованный ключ вместе с nonce.
///
/// Структура для хранения в базе данных:
///   <base64(nonce)>.<base64(ciphertext)>
#[derive(Debug, Clone)]
pub struct EncryptedKey {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl EncryptedKey {
    /// Сериализует в строку для хранения в БД: base64(nonce).base64(ciphertext)
    pub fn serialize(&self) -> String {
        use aes_gcm::aead::generic_array::GenericArray;
        use base64::engine::{general_purpose::STANDARD, Engine as _};
        format!(
            "{}.{}",
            STANDARD.encode(&self.nonce),
            STANDARD.encode(&self.ciphertext)
        )
    }

    /// Десериализует из строки БД.
    pub fn deserialize(s: &str) -> Result<Self, AIError> {
        use base64::engine::{general_purpose::STANDARD, Engine as _};
        let parts: Vec<&str> = s.splitn(2, '.').collect();
        if parts.len() != 2 {
            return Err(AIError::Encryption(
                "неверный формат зашифрованного ключа (ожидается nonce.ciphertext)".into(),
            ));
        }
        let nonce = STANDARD.decode(parts[0]).map_err(|e| AIError::Encryption(e.to_string()))?;
        let ciphertext = STANDARD.decode(parts[1]).map_err(|e| AIError::Encryption(e.to_string()))?;
        Ok(Self { nonce, ciphertext })
    }
}

/// Шифрование plaintext ключа с помощью AES-256-GCM.
pub fn encrypt_key(plaintext: &str, master_key: &[u8; KEY_LEN]) -> Result<EncryptedKey, AIError> {
    let cipher = Aes256Gcm::new_from_slice(master_key)
        .map_err(|e| AIError::Encryption(format!("ошибка инициализации шифра: {e}")))?;

    let mut nonce = [0u8; 12];
    getrandom(&mut nonce).map_err(|e| AIError::Encryption(format!("ошибка генерации nonce: {e}")))?;
    let ciphertext = cipher
        .encrypt(nonce.as_slice().into(), plaintext.as_bytes())
        .map_err(|e| AIError::Encryption(format!("ошибка шифрования: {e}")))?;

    Ok(EncryptedKey { nonce: nonce.to_vec(), ciphertext })
}

/// Расшифрование зашифрованного ключа.
pub fn decrypt_key(encrypted: &str, master_key: &[u8; KEY_LEN]) -> Result<String, AIError> {
    let enc = EncryptedKey::deserialize(encrypted)?;
    let cipher = Aes256Gcm::new_from_slice(master_key)
        .map_err(|e| AIError::Encryption(format!("ошибка инициализации шифра: {e}")))?;

    let plaintext = cipher
        .decrypt(enc.nonce.as_slice().into(), enc.ciphertext.as_slice())
        .map_err(|e| AIError::Encryption(format!("ошибка расшифрования: {e}")))?;

    String::from_utf8(plaintext).map_err(|e| AIError::Encryption(e.to_string()))
}

/// Выводит master-ключ из machine-id системы и соли через PBKDF2.
pub fn derive_master_key(salt: &[u8]) -> Result<[u8; KEY_LEN], AIError> {
    let machine_id = get_machine_id()?;
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(
        machine_id.as_bytes(),
        salt,
        PBKDF2_ITERATIONS,
        &mut key,
    );
    Ok(key)
}

/// Возвращает directory для хранения файлов шифрования (~/.w420/).
pub fn encryption_dir() -> Result<PathBuf, AIError> {
    let home = std::env::var("HOME")
        .map_err(|e| AIError::Encryption(format!("HOME не задан: {e}")))?;
    let dir = Path::new(&home).join(".w420");
    fs::create_dir_all(&dir).map_err(|e| AIError::Encryption(format!("не удалось создать {dir:?}: {e}")))?;
    Ok(dir)
}

/// Возвращает путь к файлу соли.
pub fn salt_path() -> Result<PathBuf, AIError> {
    Ok(encryption_dir()?.join(SALT_FILE))
}

/// Генерирует новую соль и сохраняет её на диск. Возвращает соль.
pub fn generate_and_save_salt() -> Result<Vec<u8>, AIError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom(&mut salt).map_err(|e| AIError::Encryption(format!("ошибка генерации соли: {e}")))?;
    let path = salt_path()?;
    fs::write(&path, &salt).map_err(|e| AIError::Encryption(format!("не удалось сохранить соль: {e}")))?;
    Ok(salt.to_vec())
}

/// Загружает соль с диска или генерирует новую, если файла нет.
pub fn load_or_create_salt() -> Result<Vec<u8>, AIError> {
    let path = salt_path()?;
    if path.exists() {
        fs::read(&path).map_err(|e| AIError::Encryption(format!("не удалось прочитать соль: {e}")))
    } else {
        generate_and_save_salt()
    }
}

/// Возвращает master-ключ для шифрования (создаёт соль при необходимости).
pub fn get_master_key() -> Result<[u8; KEY_LEN], AIError> {
    let salt = load_or_create_salt()?;
    let mut salt_array = [0u8; SALT_LEN];
    let len = salt.len().min(SALT_LEN);
    salt_array[..len].copy_from_slice(&salt[..len]);
    derive_master_key(&salt_array)
}

/// Получает machine-id системы (используется как основа для PBKDF2).
fn get_machine_id() -> Result<String, AIError> {
    if let Ok(content) = fs::read_to_string("/etc/machine-id") {
        let id = content.trim().to_string();
        if !id.is_empty() {
            return Ok(id);
        }
    }

    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
    Ok(format!("w420-{hostname}-{}", std::process::id()))
}

/// Шифрует API-ключ с использованием системного master-ключа.
pub fn encrypt_api_key(plaintext: &str) -> Result<String, AIError> {
    let master_key = get_master_key()?;
    let enc = encrypt_key(plaintext, &master_key)?;
    Ok(enc.serialize())
}

/// Расшифровывает API-ключ с использованием системного master-ключа.
pub fn decrypt_api_key(encrypted: &str) -> Result<String, AIError> {
    let master_key = get_master_key()?;
    decrypt_key(encrypted, &master_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let master_key = [0x42u8; KEY_LEN];
        let plaintext = "sk-test-1234567890abcdef";

        let enc = encrypt_key(plaintext, &master_key).expect("шифрование должно работать");
        let serialized = enc.serialize();

        let dec = decrypt_key(&serialized, &master_key).expect("расшифрование должно работать");
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let master_key1 = [0x01u8; KEY_LEN];
        let master_key2 = [0x02u8; KEY_LEN];
        let plaintext = "sk-secret-key";

        let enc = encrypt_key(plaintext, &master_key1).expect("шифрование");
        let serialized = enc.serialize();

        let result = decrypt_key(&serialized, &master_key2);
        assert!(result.is_err(), "расшифрование неверным ключом должно失败");
    }

    #[test]
    fn test_serialized_format() {
        let master_key = [0x42u8; KEY_LEN];
        let plaintext = "test-key";
        let enc = encrypt_key(plaintext, &master_key).expect("шифрование");
        let serialized = enc.serialize();

        let parts: Vec<&str> = serialized.split('.').collect();
        assert_eq!(parts.len(), 2, "формат должен быть nonce.ciphertext");
        assert!(!parts[0].is_empty(), "nonce не должен быть пустым");
        assert!(!parts[1].is_empty(), "ciphertext не должен быть пустым");
    }
}

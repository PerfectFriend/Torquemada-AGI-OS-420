//! wallet.rs — Этап 20: REAL-кошелёк в Rust (secp256k1 / BIP-39 / BIP-32).
//!
//! Keyring хранится в `~/.w420/wallet/keyring.json` (права 0600): каждая запись —
//! адрес + label + соль/nonce + зашифрованная мнемоника (AES-256-GCM, ключ из
//! PBKDF2-HMAC-SHA256, 600 000 итераций). Приватные ключи и мнемоники НАРУЖУ
//! (во фронтенд) не отдаются никогда — только адрес и подписи.
//!
//! Сеть: legacy-транзакции (EIP-155), JSON-RPC. По умолчанию Sepolia testnet —
//! реальные деньги только после явного указания другого RPC и chain_id.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hmac::Mac;
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use k256::elliptic_curve::PrimeField;
use k256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use bip39::{Language, Mnemonic, MnemonicType, Seed};

/// Путь derivation для Ethereum: m/44'/60'/0'/0/0.
const ETH_PATH: [u32; 5] = [44 | 0x8000_0000, 60 | 0x8000_0000, 0 | 0x8000_0000, 0, 0];
/// Итераций PBKDF2 для ключа шифрования keyring.
const KDF_ITER: u32 = 600_000;
/// RPC по умолчанию: Sepolia testnet (тестовые средства, не mainnet).
pub const DEFAULT_RPC: &str = "https://rpc.sepolia.org";
/// Chain ID Sepolia.
pub const DEFAULT_CHAIN_ID: u64 = 11155111;

/// Блокировка файла keyring на время чтения-модификации-записи.
static FILE_LOCK: Mutex<()> = Mutex::new(());

// ============================================================================
// Крипто: BIP-32 / адреса / подпись
// ============================================================================

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = <hmac::Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC принимает ключ любой длины");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut r = [0u8; 64];
    r.copy_from_slice(&out);
    r
}

/// Мастер-ключ из seed (HMAC-SHA512 с ключом "Bitcoin seed").
fn master_from_seed(seed: &[u8]) -> (SecretKey, [u8; 32]) {
    let i = hmac_sha512(b"Bitcoin seed", seed);
    let key = SecretKey::from_slice(&i[..32]).expect("32 байта — валидный ключ");
    let mut cc = [0u8; 32];
    cc.copy_from_slice(&i[32..]);
    (key, cc)
}

/// Один шаг BIP-32 (hardened если index >= 0x80000000).
fn derive_child(parent: &SecretKey, parent_cc: &[u8; 32], index: u32) -> Result<(SecretKey, [u8; 32]), String> {
    let mut data = Vec::with_capacity(37);
    if index & 0x8000_0000 != 0 {
        data.push(0u8);
        data.extend_from_slice(&parent.to_bytes());
    } else {
        let sk = SigningKey::from(parent);
        let vk = sk.verifying_key();
        data.extend_from_slice(vk.to_encoded_point(true).as_bytes());
    }
    data.extend_from_slice(&index.to_be_bytes());
    let i = hmac_sha512(parent_cc, &data);
    // child = (IL + kpar) mod n; IL >= n бывает с вероятностью ~2^-128 — тогда шаг невалиден
    let il_opt: Option<k256::Scalar> =
        Option::from(k256::Scalar::from_repr(*k256::FieldBytes::from_slice(&i[..32])));
    let il = il_opt.ok_or("BIP-32: IL >= n (нужен следующий индекс)")?;
    let parent_scalar = parent.to_nonzero_scalar();
    let sum: k256::Scalar = il + *parent_scalar;
    let key = SecretKey::from_slice(&sum.to_bytes()).map_err(|e| format!("BIP-32 derive: {e}"))?;
    let mut cc = [0u8; 32];
    cc.copy_from_slice(&i[32..]);
    Ok((key, cc))
}

/// Адрес Ethereum из приватного ключа: keccak256(uncompressed pubkey без 0x04)[12..].
pub fn address_of(key: &SecretKey) -> String {
    let sk = SigningKey::from(key);
    let vk = sk.verifying_key();
    let pub64 = vk.to_encoded_point(false); // 65 байт, 0x04 || X || Y
    let hash = Keccak256::digest(&pub64.as_bytes()[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

/// Пара (ключ, адрес) из BIP-39 мнемоники по пути m/44'/60'/0'/0/0.
pub fn key_from_phrase(phrase: &str) -> Result<(SecretKey, String), String> {
    let m = Mnemonic::from_phrase(phrase.trim(), Language::English)
        .map_err(|e| format!("невалидная мнемоника: {e:?}"))?;
    let seed = Seed::new(&m, ""); // пустая passphrase (стандарт как в MetaMask)
    let (mut key, mut cc) = master_from_seed(seed.as_bytes());
    for idx in ETH_PATH {
        let (nk, ncc) = derive_child(&key, &cc, idx)?;
        key = nk;
        cc = ncc;
    }
    let addr = address_of(&key);
    Ok((key, addr))
}

/// Минимальное big-endian представление (RLP-целое).
fn be_bytes(v: u128) -> Vec<u8> {
    let mut b = v.to_be_bytes().to_vec();
    while b.len() > 1 && b[0] == 0 {
        b.remove(0);
    }
    if b.len() == 1 && b[0] == 0 {
        b.clear(); // ноль = пустая строка в RLP
    }
    b
}

/// "1.5" ETH → wei (u128). Дробная часть длиннее 18 знаков — ошибка.
pub fn eth_to_wei(s: &str) -> Result<u128, String> {
    let s = s.trim();
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit() || c == '.') || s.matches('.').count() > 1 {
        return Err(format!("невалидная сумма: {s}"));
    }
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if frac.len() > 18 {
        return Err("больше 18 знаков после запятой".to_string());
    }
    let whole: u128 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| "переполнение целой части")? };
    let frac: u128 = if frac.is_empty() {
        0
    } else {
        let frac_padded = format!("{frac:0<18}"); // добиваем НУЛЯМИ справа, не пробелами
        frac_padded[..18].parse().map_err(|_| "невалидная дробная часть")?
    };
    whole
        .checked_mul(10u128.pow(18))
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(|| "переполнение wei".to_string())
}

/// gwei → wei (1 gwei = 1e9 wei).
pub fn gwei_to_wei(s: &str) -> Result<u128, String> {
    let s = s.trim();
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit() || c == '.') || s.matches('.').count() > 1 {
        return Err(format!("невалидный gas price: {s}"));
    }
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if frac.len() > 9 {
        return Err("больше 9 знаков gwei".to_string());
    }
    let whole: u128 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| "невалидная целая часть gwei")? };
    let frac: u128 = if frac.is_empty() {
        0
    } else {
        let frac_padded = format!("{frac:0<9}");
        frac_padded[..9].parse().map_err(|_| "невалидная дробная часть gwei")?
    };
    whole
        .checked_mul(1_000_000_000u128)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(|| "переполнение wei".to_string())
}

/// Подписать legacy-транзакцию (EIP-155). Возвращает (raw_hex, tx_hash).
pub fn sign_legacy_tx(
    key: &SecretKey,
    to: &str,
    value_wei: u128,
    nonce: u64,
    gas_limit: u64,
    gas_price_wei: u128,
    chain_id: u64,
) -> Result<(String, String), String> {
    let to_bytes: Vec<u8> = if to.trim().is_empty() {
        Vec::new()
    } else {
        let t = to.trim().strip_prefix("0x").unwrap_or(to.trim());
        hex::decode(t).map_err(|e| format!("невалидный адрес to: {e}"))?
    };
    if !to_bytes.is_empty() && to_bytes.len() != 20 {
        return Err("адрес to должен быть 20 байт".to_string());
    }
    // append байтового среза: Encodable реализован для &[u8]
    fn app_bytes(s: &mut rlp::RlpStream, b: &[u8]) {
        s.append(&b);
    }
    // payload для подписи: [nonce, gasPrice, gas, to, value, data, chainId, 0, 0]
    let mut s = rlp::RlpStream::new_list(9);
    s.append(&nonce);
    app_bytes(&mut s, &be_bytes(gas_price_wei));
    s.append(&gas_limit);
    app_bytes(&mut s, &to_bytes);
    app_bytes(&mut s, &be_bytes(value_wei));
    app_bytes(&mut s, &[]); // data = пусто
    s.append(&chain_id);
    s.append(&0u8);
    s.append(&0u8);
    let payload = s.as_raw();
    let hash = Keccak256::digest(payload);
    let signing = SigningKey::from(key);
    let (sig, recid): (Signature, RecoveryId) = signing
        .sign_prehash_recoverable(&hash)
        .map_err(|e| format!("ошибка подписи: {e}"))?;
    let sig_bytes = sig.to_bytes();
    let (r, s_) = sig_bytes.split_at(32);
    let v = chain_id * 2 + 35 + recid.to_byte() as u64;
    // финальная транзакция: [nonce, gasPrice, gas, to, value, data, v, r, s]
    let mut t = rlp::RlpStream::new_list(9);
    t.append(&nonce);
    app_bytes(&mut t, &be_bytes(gas_price_wei));
    t.append(&gas_limit);
    app_bytes(&mut t, &to_bytes);
    app_bytes(&mut t, &be_bytes(value_wei));
    app_bytes(&mut t, &[]);
    t.append(&v);
    app_bytes(&mut t, r);
    app_bytes(&mut t, s_);
    let raw = format!("0x{}", hex::encode(t.as_raw()));
    let tx_hash = format!("0x{}", hex::encode(Keccak256::digest(t.as_raw())));
    Ok((raw, tx_hash))
}

// ============================================================================
// Keyring: шифрование и файл
// ============================================================================

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyEntry {
    pub address: String,
    pub label: String,
    pub created: String,
    pub kdf: String,
    pub salt: String,  // hex
    pub nonce: String, // hex
    pub ct: String,    // hex (AES-256-GCM: tag в конце)
}

#[derive(Serialize, Deserialize)]
struct Keyring {
    version: u32,
    entries: Vec<KeyEntry>,
}

/// Путь keyring по умолчанию: ~/.w420/wallet/keyring.json
pub fn keyring_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".w420").join("wallet").join("keyring.json")
}

/// Зашифровать полезную нагрузку паролем: PBKDF2-HMAC-SHA256(600k) → AES-256-GCM.
pub fn seal(payload: &str, password: &str) -> (String, String, String) {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    let mut rng = rand::thread_rng();
    use rand::RngCore;
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, KDF_ITER, &mut key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), payload.as_bytes())
        .expect("AES-GCM encrypt не падает");
    (hex::encode(salt), hex::encode(nonce), hex::encode(ct))
}

/// Расшифровать запись keyring паролем.
pub fn open_entry(e: &KeyEntry, password: &str) -> Result<String, String> {
    let salt = hex::decode(&e.salt).map_err(|x| format!("salt: {x}"))?;
    let nonce = hex::decode(&e.nonce).map_err(|x| format!("nonce: {x}"))?;
    let ct = hex::decode(&e.ct).map_err(|x| format!("ct: {x}"))?;
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, KDF_ITER, &mut key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let pt = cipher
        .decrypt(Nonce::from_slice(&nonce), ct.as_slice())
        .map_err(|_| "неверный пароль или повреждённая запись".to_string())?;
    String::from_utf8(pt).map_err(|e| format!("utf8: {e}"))
}

fn read_keyring(path: &PathBuf) -> Keyring {
    match fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or(Keyring { version: 1, entries: vec![] }),
        Err(_) => Keyring { version: 1, entries: vec![] },
    }
}

fn write_keyring(path: &PathBuf, kr: &Keyring) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("mkdir: {e}"))?;
    }
    let s = serde_json::to_string_pretty(kr).map_err(|e| e.to_string())?;
    fs::write(path, s).map_err(|e| format!("write keyring: {e}"))?;
    // права 0600 — приватный материал
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// ============================================================================
// JSON-RPC (testnet first)
// ============================================================================

async fn rpc_call(rpc: &str, method: &str, params: Value) -> Result<Value, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
    let resp = client.post(rpc).json(&body).send().await.map_err(|e| format!("RPC {method}: {e}"))?;
    let v: Value = resp.json().await.map_err(|e| format!("RPC {method} ответ не JSON: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("RPC {method} error: {err}"));
    }
    Ok(v.get("result").cloned().unwrap_or(Value::Null))
}

fn hex_to_u128(h: &str) -> Result<u128, String> {
    let h = h.strip_prefix("0x").unwrap_or(h);
    u128::from_str_radix(h, 16).map_err(|e| format!("невалидный hex {h}: {e}"))
}

// ============================================================================
// Tauri-команды
// ============================================================================

/// Создать новый кошелёк: генерирует мнемонику (24 слова), кладёт в зашифрованный
/// keyring. Мнемоника возвращается ОДИН раз (для записи пользователем).
#[tauri::command]
pub fn wallet_create(password: String, label: Option<String>) -> Result<Value, String> {
    if password.len() < 8 {
        return Err("пароль минимум 8 символов".to_string());
    }
    let _g = FILE_LOCK.lock().unwrap();
    let path = keyring_path();
    let m = Mnemonic::new(MnemonicType::Words24, Language::English);
    let phrase = m.phrase().to_string();
    let (_key, address) = key_from_phrase(&phrase)?;
    let mut kr = read_keyring(&path);
    if kr.entries.iter().any(|e| e.address == address) {
        return Err("такой кошелёк уже есть в keyring".to_string());
    }
    let (salt, nonce, ct) = seal(&phrase, &password);
    kr.entries.push(KeyEntry {
        address: address.clone(),
        label: label.unwrap_or_else(|| "wallet".to_string()),
        created: chrono::Utc::now().to_rfc3339(),
        kdf: format!("pbkdf2-hmac-sha256-{KDF_ITER}+aes-256-gcm"),
        salt,
        nonce,
        ct,
    });
    write_keyring(&path, &kr)?;
    Ok(json!({"address": address, "phrase": phrase, "note": "мнемоника показана один раз — запишите; в keyring она хранится зашифрованно"}))
}

/// Импортировать существующую мнемонику в keyring.
#[tauri::command]
pub fn wallet_import(phrase: String, password: String, label: Option<String>) -> Result<Value, String> {
    if password.len() < 8 {
        return Err("пароль минимум 8 символов".to_string());
    }
    let _g = FILE_LOCK.lock().unwrap();
    let path = keyring_path();
    let (_key, address) = key_from_phrase(&phrase)?; // валидирует фразу и даёт адрес
    let mut kr = read_keyring(&path);
    if kr.entries.iter().any(|e| e.address == address) {
        return Err("такой кошелёк уже есть в keyring".to_string());
    }
    let (salt, nonce, ct) = seal(phrase.trim(), &password);
    kr.entries.push(KeyEntry {
        address: address.clone(),
        label: label.unwrap_or_else(|| "imported".to_string()),
        created: chrono::Utc::now().to_rfc3339(),
        kdf: format!("pbkdf2-hmac-sha256-{KDF_ITER}+aes-256-gcm"),
        salt, nonce, ct,
    });
    write_keyring(&path, &kr)?;
    Ok(json!({"address": address}))
}

/// Список кошельков keyring (адреса и метки, без ключей).
#[tauri::command]
pub fn wallet_list() -> Result<Vec<Value>, String> {
    let _g = FILE_LOCK.lock().unwrap();
    let kr = read_keyring(&keyring_path());
    Ok(kr.entries.iter().map(|e| json!({"address": e.address, "label": e.label, "created": e.created})).collect())
}

/// Показать мнемонику кошелька (нужен пароль keyring).
#[tauri::command]
pub fn wallet_reveal(address: String, password: String) -> Result<Value, String> {
    let _g = FILE_LOCK.lock().unwrap();
    let kr = read_keyring(&keyring_path());
    let e = kr.entries.iter().find(|e| e.address == address).ok_or("кошелёк не найден")?;
    let phrase = open_entry(e, &password)?;
    Ok(json!({"address": address, "phrase": phrase}))
}

/// Удалить кошелёк из keyring (нужен пароль).
#[tauri::command]
pub fn wallet_remove(address: String, password: String) -> Result<Value, String> {
    let _g = FILE_LOCK.lock().unwrap();
    let path = keyring_path();
    let mut kr = read_keyring(&path);
    let pos = kr.entries.iter().position(|e| e.address == address).ok_or("кошелёк не найден")?;
    // проверяем пароль перед удалением
    open_entry(&kr.entries[pos], &password)?;
    kr.entries.remove(pos);
    write_keyring(&path, &kr)?;
    Ok(json!({"removed": address}))
}

fn load_key(address: &str, password: &str) -> Result<(SecretKey, String), String> {
    let kr = read_keyring(&keyring_path());
    let e = kr.entries.iter().find(|e| e.address == address).ok_or("кошелёк не найден в keyring")?;
    let phrase = open_entry(e, password)?;
    let (key, addr) = key_from_phrase(&phrase)?;
    Ok((key, addr))
}

/// Офлайн-подпись legacy-транзакции. Ничего в сеть не уходит.
#[tauri::command]
pub fn wallet_sign_tx(
    address: String,
    password: String,
    to: String,
    value_eth: String,
    nonce: u64,
    gas_limit: Option<u64>,
    gas_price_gwei: Option<String>,
    chain_id: Option<u64>,
) -> Result<Value, String> {
    let _g = FILE_LOCK.lock().unwrap();
    let (key, from) = load_key(&address, &password)?;
    let value_wei = eth_to_wei(&value_eth)?;
    let gp = gwei_to_wei(&gas_price_gwei.unwrap_or_else(|| "20".to_string()))?;
    let (raw, hash) = sign_legacy_tx(&key, &to, value_wei, nonce, gas_limit.unwrap_or(21000), gp, chain_id.unwrap_or(DEFAULT_CHAIN_ID))?;
    Ok(json!({"from": from, "to": to, "value_wei": value_wei.to_string(), "raw": raw, "hash": hash, "chain_id": chain_id.unwrap_or(DEFAULT_CHAIN_ID), "offline": true}))
}

/// Баланс адреса через JSON-RPC (по умолчанию Sepolia).
#[tauri::command]
pub async fn wallet_balance(address: String, rpc: Option<String>) -> Result<Value, String> {
    let rpc = rpc.unwrap_or_else(|| DEFAULT_RPC.to_string());
    let r = rpc_call(&rpc, "eth_getBalance", json!([address, "latest"])).await?;
    let wei = hex_to_u128(r.as_str().ok_or("eth_getBalance вернул не строку")?)?;
    Ok(json!({"address": address, "wei": wei.to_string(), "eth": format_wei(wei), "rpc": rpc}))
}

/// Отправить транзакцию в сеть: nonce берётся через eth_getTransactionCount("pending"),
/// подписывается локально и уходит через eth_sendRawTransaction. TESTNET FIRST.
#[tauri::command]
pub async fn wallet_send(
    address: String,
    password: String,
    to: String,
    value_eth: String,
    rpc: Option<String>,
    gas_limit: Option<u64>,
    gas_price_gwei: Option<String>,
    chain_id: Option<u64>,
) -> Result<Value, String> {
    let rpc = rpc.unwrap_or_else(|| DEFAULT_RPC.to_string());
    let chain_id = chain_id.unwrap_or(DEFAULT_CHAIN_ID);
    let (key, from) = {
        let _g = FILE_LOCK.lock().unwrap();
        load_key(&address, &password)?
    };
    let nonce_hex = rpc_call(&rpc, "eth_getTransactionCount", json!([address, "pending"])).await?;
    let nonce = hex_to_u128(nonce_hex.as_str().ok_or("nonce не hex")?)? as u64;
    let value_wei = eth_to_wei(&value_eth)?;
    let gp = gwei_to_wei(&gas_price_gwei.unwrap_or_else(|| "20".to_string()))?;
    let (raw, hash) = sign_legacy_tx(&key, &to, value_wei, nonce, gas_limit.unwrap_or(21000), gp, chain_id)?;
    let tx_hash = rpc_call(&rpc, "eth_sendRawTransaction", json!([raw])).await?;
    Ok(json!({"from": from, "to": to, "value_wei": value_wei.to_string(), "nonce": nonce, "tx_hash": tx_hash, "raw_hash": hash, "rpc": rpc, "chain_id": chain_id}))
}

/// Статус: сколько кошельков в keyring + RPC по умолчанию.
#[tauri::command]
pub fn wallet_status() -> Result<Value, String> {
    let _g = FILE_LOCK.lock().unwrap();
    let kr = read_keyring(&keyring_path());
    Ok(json!({"count": kr.entries.len(), "default_rpc": DEFAULT_RPC, "default_chain_id": DEFAULT_CHAIN_ID, "keyring": keyring_path().display().to_string()}))
}

/// wei → строка ETH (18 знаков).
pub fn format_wei(wei: u128) -> String {
    let whole = wei / 10u128.pow(18);
    let frac = wei % 10u128.pow(18);
    format!("{whole}.{frac:018}")
}

// ============================================================================
// Тесты
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Hardhat/MetaMask тестовый вектор: "test … junk" → адрес 0xf39F…2266,
    /// приватный ключ 0xac09…ff80 по пути m/44'/60'/0'/0/0.
    const TEST_PHRASE: &str = "test test test test test test test test test test test junk";

    #[test]
    fn test_key_from_phrase_hardhat_vector() {
        let (key, addr) = key_from_phrase(TEST_PHRASE).unwrap();
        assert_eq!(addr.to_lowercase(), "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        assert_eq!(hex::encode(key.to_bytes()), "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    }

    #[test]
    fn test_bad_phrase_rejected() {
        assert!(key_from_phrase("hello world").is_err());
        assert!(key_from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").is_ok());
    }

    #[test]
    fn test_eth_to_wei() {
        assert_eq!(eth_to_wei("1").unwrap(), 1_000_000_000_000_000_000u128);
        assert_eq!(eth_to_wei("1.5").unwrap(), 1_500_000_000_000_000_000u128);
        assert_eq!(eth_to_wei("0.000000000000000001").unwrap(), 1u128);
        assert_eq!(eth_to_wei("0").unwrap(), 0u128);
        assert!(eth_to_wei("1.0000000000000000001").is_err()); // 19 знаков
        assert!(eth_to_wei("abc").is_err());
    }

    #[test]
    fn test_gwei_to_wei() {
        assert_eq!(gwei_to_wei("20").unwrap(), 20_000_000_000u128);
        assert_eq!(gwei_to_wei("1.5").unwrap(), 1_500_000_000u128);
    }

    #[test]
    fn test_sign_legacy_tx_deterministic() {
        let (key, from) = key_from_phrase(TEST_PHRASE).unwrap();
        let to = "0x000000000000000000000000000000000000dEaD".to_string();
        let (raw1, hash1) = sign_legacy_tx(&key, &to, eth_to_wei("0.01").unwrap(), 0, 21000, gwei_to_wei("20").unwrap(), DEFAULT_CHAIN_ID).unwrap();
        let (raw2, hash2) = sign_legacy_tx(&key, &to, eth_to_wei("0.01").unwrap(), 0, 21000, gwei_to_wei("20").unwrap(), DEFAULT_CHAIN_ID).unwrap();
        assert_eq!(raw1, raw2); // RFC-6979: детерминированная подпись
        assert_eq!(hash1, hash2);
        assert!(raw1.starts_with("0x") && raw1.len() > 100);
        assert!(hash1.starts_with("0x") && hash1.len() == 66);
        assert_eq!(from.to_lowercase(), "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        // v для Sepolia: 11155111*2+35 = 22310257 или +1
        assert!(raw1.contains(&format!("{:x}", 11155111u64 * 2 + 35)) || raw1.contains(&format!("{:x}", 11155111u64 * 2 + 36)));
    }

    #[test]
    fn test_sign_bad_to() {
        let (key, _) = key_from_phrase(TEST_PHRASE).unwrap();
        assert!(sign_legacy_tx(&key, "0x123", 0, 0, 21000, 0, 1).is_err());
        assert!(sign_legacy_tx(&key, "zz", 0, 0, 21000, 0, 1).is_err());
    }

    #[test]
    fn test_seal_open_roundtrip_and_wrong_password() {
        let (salt, nonce, ct) = seal("секретная фраза", "пароль123");
        let e = KeyEntry {
            address: "0x0".into(), label: "t".into(), created: "now".into(),
            kdf: "x".into(), salt, nonce, ct,
        };
        assert_eq!(open_entry(&e, "пароль123").unwrap(), "секретная фраза");
        assert!(open_entry(&e, "неверный").is_err());
    }

    #[test]
    fn test_keyring_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("w420-wallet-test-{}", uuid::Uuid::new_v4()));
        let path = dir.join("keyring.json");
        let _g = FILE_LOCK.lock().unwrap();
        let (salt, nonce, ct) = seal(TEST_PHRASE, "пароль123");
        let kr = Keyring { version: 1, entries: vec![KeyEntry {
            address: "0xf39f".into(), label: "test".into(), created: "now".into(),
            kdf: "x".into(), salt, nonce, ct,
        }]};
        write_keyring(&path, &kr).unwrap();
        let kr2 = read_keyring(&path);
        assert_eq!(kr2.entries.len(), 1);
        assert_eq!(open_entry(&kr2.entries[0], "пароль123").unwrap(), TEST_PHRASE);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_format_wei() {
        assert_eq!(format_wei(1_500_000_000_000_000_000), "1.500000000000000000");
        assert_eq!(format_wei(1), "0.000000000000000001");
    }
}

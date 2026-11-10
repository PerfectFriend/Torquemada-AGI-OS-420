# Phase 21 — Vault PQC: отчёт (2026-11-06)

## Что сделано
Новый модуль `app/src-tauri/src/pqc.rs` + 4 команды + UI-скрипт `app/dist/pqc.js`.

### Rust (`pqc.rs`) — гибридная PQC-схема, всё считается на бэкенде
- **ML-KEM-768 (FIPS 203, RustCrypto `ml-kem` 0.2)**: keygen → encapsulation key (1184 б) / decapsulation key (2400 б); инкапсуляция → общий секрет + ciphertext (1088 б).
- **Гибрид**: HKDF-SHA256(общий секрет, salt=None, info=`w420-vault-pqc-v1`) → ключ AES-256-GCM; конверт = `(kem_ct, nonce, ct)`. Классический слой vault (WebCrypto AES-GCM + PBKDF2 200k) не тронут — PQC надстройка.
- Команды: `vault_pqc_keygen` (sk показывается один раз), `vault_pqc_seal(pk_hex, text)`, `vault_pqc_open(sk_hex, kem_ct, nonce, ct)`, `vault_pqc_status`.

### UI (`pqc.js`, native-only)
- На вкладке QUANTUM FS · ENCRYPTED VAULT — панель: **PQC KEYGEN** (пары ключей с размерами), **PQC SEAL** (шифрует текст из `vt` под pubkey), **PQC OPEN** (расшифровывает последний конверт privkey). Вывод — в `#vmsg`.
- Плашка **«PQC TAG: SIM» → «PQC TAG: LIVE»** в нативной оболочке (схема реальна, тесты roundtrip зелёные); в браузере без Tauri — прежний SIM.

## Проверено
- `cargo test -p w420 --lib -- pqc::` — **5 passed / 0 failed**: размеры ключей (1184/2400/1088), roundtrip, неверный sk → отказ, порча ct → отказ (AES-GCM tag), битые ключи → отказ.
- `cargo test --workspace` — **140 passed / 0 failed / 7 ignored** (было 135; +5 pqc).
- `cargo build --release` — exit 0 (ml-kem, hkdf докачены).
- `node --check pqc.js` OK; wiring-аудит: **188 declared = 188 registered**, 140 inv-вызовов, 0 неразрешённых.

## Известные пределы
- Приватный ключ PQC (sk) хранится у владельца (в UI-поле/скопирован) — в файл не пишется; ключ шифрования данных доступен только владельцу конверта.
- Старые vault-записи (localStorage, WebCrypto) не мигрируются — PQC-слой отдельный инструмент поверх той же вкладки.

## Следующий этап
Этап 22 — DIGITAL ID: `did_create/sign_challenge/verify/list` в Rust, снять плашку «DID: WIP», персистентность ключа в зашифрованном keyring.

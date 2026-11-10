# Phase 20 — Кошелёк REAL: отчёт (2026-11-06)

## Что сделано
Новый модуль `app/src-tauri/src/wallet.rs` + 9 команд + UI-скрипт `app/dist/wallet.js`.

### Rust (`wallet.rs`) — всё крипто локально, ключи не покидают бэкенд
- **BIP-39/BIP-32/secp256k1 в Rust** (`bip39` + `k256`): мнемоника → seed → m/44'/60'/0'/0/0 → приватный ключ; адрес = keccak256(uncompressed pubkey)[12..]. **Вектор проверен тестом**: «test test … junk» → `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`, приватный ключ `0xac09…ff80` — совпадает с эталоном (MetaMask/Hardhat).
- **Keyring** `~/.w420/wallet/keyring.json` (права 0600): каждая запись — адрес, label, соль/nonce, зашифрованная мнемоника. KDF PBKDF2-HMAC-SHA256 **600 000 итераций** → ключ, шифр **AES-256-GCM**. Наружу отдаются только адреса/подписи.
- **Подпись legacy-транзакций (EIP-155)**: RLP([nonce, gasPrice, gas, to, value, data, chainId, 0, 0]) → keccak → детерминированная подпись (RFC-6979, k256) → v = chainId·2 + 35 + recid. Тест: двойная подпись идентична, v в диапазоне Sepolia (22310257/22310258).
- **JSON-RPC** (reqwest, timeout 20 с): `eth_getBalance`, `eth_getTransactionCount(pending)`, `eth_sendRawTransaction`. **По умолчанию Sepolia testnet** (chain 11155111, `https://rpc.sepolia.org`) — mainnet только при явном указании RPC и chain_id в командах.
- Команды: `wallet_create` (24 слова, мнемоника показывается один раз), `wallet_import`, `wallet_list`, `wallet_reveal` (нужен пароль), `wallet_remove`, `wallet_sign_tx` (офлайн), `wallet_balance`, `wallet_send` (testnet, real), `wallet_status`.

### UI (`wallet.js`, native-only)
- `kgen/kload/kshow/kvault/ksign` (вкладка WALLET · OFFLINE KEYS) → нативные команды; пароль берётся из `#kpw` (мин. 8 символов). Устаревшая заметка «отправка в сеть не подключены» динамически заменяется на реальную.
- `kvault` теперь показывает мнемонику через `wallet_reveal` и складывает её в QFS Vault прежним AES-GCM путём (двойное шифрование по желанию).
- На вкладке CRYPTO · WALLET добавлены кнопки **«БАЛАНС (RPC)»** и **«ОТПРАВИТЬ (testnet)»** (confirm перед отправкой) — реальные вызовы кошелька из keyring.

## Проверено
- `cargo test -p w420 --lib -- wallet::` — **9 passed / 0 failed** (вектор Hardhat, невалидные фразы, eth/gwei→wei, детерминированная подпись, seal/open roundtrip + неверный пароль, keyring-файл roundtrip, format_wei).
- `cargo test --workspace` — 135 passed / 0 failed / 7 ignored (было 126; +9 wallet).
- `cargo build --release` — exit 0 (новые крейты: k256, bip39, sha3, hmac, rlp, hex, rand; cargo fetch прошёл).
- `node --check wallet.js` OK; wiring-аудит: **184 declared = 184 registered**, 136 inv-вызовов, 0 неразрешённых.

## Известные пределы
- Живая отправка в Sepolia требует тестового ETH на адресе (faucet) — live-проверка вручную, `#[ignore]`-тест не добавлял;
- `waddr/wbal` в шапке вкладки CRYPTO · WALLET — теперь реальный адрес keyring (первый), баланс — по кнопке «БАЛАНС (RPC)»;
- `wsend/tmint` ([SIM]-подписи) : wsend заменён реальной отправкой; `tmint`/`mkt`/`led` (минт/биржа) остаются [SIM] по плану этапа — отдельная подсистема;
- Плашка «SEND [SIM]» на старой кнопке: onclick переназначен на реальную отправку с confirm — поведение перекрыто исполнением.

## Следующий этап
Этап 21 — Vault PQC: гибридная схема в Rust (ML-KEM-768 + AES-256-GCM), снять плашку «PQC TAG: SIM».

## Побочная правка (по просьбе пользователя)
- **Автозагрузка W420 удалена**: `~/.config/autostart/w420.desktop` и устаревший `~/.config/autostart/Windows420.desktop` удалены; systemd-юнит `app-w420@autostart.service` inactive, generator-юнит исчезнет при следующем входе (источник-delete). Тумблер в трее остался как ручной переключатель (по умолчанию выключено) — подключим обратно после завершения разработки.

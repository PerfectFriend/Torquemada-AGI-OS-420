# W420 — Фаза 14 (PKI: локальный CA) — 2026-11-05

## pki.rs — ГОТОВ, LIVE-цикл пройден
- **pki_ca_init** — корневой CA: RSA-2048/SHA-256, самоподписанный (3650 дней), `basicConstraints=CA:TRUE`, ключ 600, конфиг `openssl.cnf` для `openssl ca` (index/serial/crlnumber/newcerts заводим сами).
- **pki_issue(cn, sans, 825 дней)** — ключ + CSR + подпись через `openssl ca`; SAN (DNS/IP) запекается в конфиг (без `$ENV::` — иначе revoke падает на undeclared var); `copy_extensions=copy`.
- **pki_revoke** — `openssl ca -revoke` + метка в БД; **pki_crl** — `openssl ca -gencrl` (default_crl_days=30).
- **pki_verify(cn, crl_check)** — `openssl verify -CAfile ca.crt [+ -crl_check -CRLfile crl.pem]`.
- **pki_status / pki_list** — парсер `openssl x509 -noout` (CN/serial/даты), список из `~/.w420/pki.db`.
- Тесты: SAN-строка (DNS/IP/placeholder), extfile, cnf, парсер x509.

## LIVE-проверка (openssl 3.5.5)
- `live_pki_cycle ... ok`: CA (w420-test-ca) → выпуск w420-test с SAN `w420.test,10.9.8.7` → **verify: OK** → revoke → gencrl → **verify -crl_check: `certificate revoked`** (ровно то, что нужно). Варианты ошибок openssl закрыты по ходу: crlnumber, default_crl_days, CN-формат `CN=name` без пробелов.

## UI
- Карточка «PKI · ЛОКАЛЬНЫЙ CA» в `ops.js`: инициализация CA, выпуск по CN/SAN, список, отзыв, выдача CRL.
- `node --check` OK, HTML-баланс 0. Вся lib: 76 passed / 1 known fail (gitleaks) / 5 ignored. `cargo build --release` чисто.

## Фаза 15 (AI SOC) и 16 (упаковка) — далее.

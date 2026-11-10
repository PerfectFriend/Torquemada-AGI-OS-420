# W420 — Фаза 13 (сканер сети + уязвимостей) — 2026-11-05

##web_scan.rs — ГОТОВ, LIVE-проверен
- **Discovery** `web_scan_net(cidr)`: `nmap -sn` → парсер хостов → `net_scan.db.scan_results` (is_known=0 у новых) — SIEM подхватывает новые хосты в ingest'е (категория `new_host`). `web_ack_host` помечает известным.
- **Vuln-скан** `web_scan_targets(targets, ports?, script="vuln")`: `nmap -sT -sV --script vuln --script-args mincvss=5.0 -oX` (без root: connect-scan), XML парсится **блочным разбором без крейтов**: `<host>…</host>` → `<port>…</port>` → `<script …/>`, CVSS из вывода скрипта → severity critical/high/medium/low; результаты в `web_vulns`.
- `web_vulns_list` (фильтр по severity), `web_scan_results`, `web_ai_report` — AI-сводка по уязвимостям через KeyRotation/NVIDIA (async, ключи AES-256-GCM).
- Отличие от `net_scan.rs` (Фаза 6, pure-Rust сканер портов): там — инвентаризация портов без root, здесь — сервисные версии + CVE-скрипты + AI-оценка; обе пишут в `net_scan.db`, конфликтов имён команд нет (`net_*` vs `web_*`).

## LIVE-проверка (этот хост)
- `live_scan_localhost ... ok` (548 с): цель 127.0.0.1, порты 8420/8000/8080/4010/80/443 → **hosts_up=1, открыты 8080 и 8420 (http), уязвимостей ≥CVSS 5 — 0**. `-sn` по 127.0.0.1/32 → hosts_up=1. Парсер XML/CVERVERIFY — юнит-тесты (3) на реальном формате nmap.
- nmap 7.98 из root_setup.sh, vuln-скрипты работают без root.

## UI
- Карточка «СКАНЕР СЕТИ / УЯЗВИМОСТИ (nmap)» в `ops.js`: скан сети, vuln-скан по портам, список уязвимостей, хосты, AI-отчёт.
- `node --check` OK, HTML-баланс 0. `cargo build --release` чисто. Вся lib: тесты + live web_scan зелёные.

## Замечания
- VULN-скан долгий (nmap vuln-скрипты): для одного хоста ~9 мин; для сетей — планировать фоном (режим «долгих» задач как этот live-тест).

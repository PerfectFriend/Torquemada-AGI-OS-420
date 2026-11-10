# Отчёт: Фаза 6 — Сетевое сканирование (Network Discovery & Scanning)

Дата: 2026-11-04

## Что сделано

Создан модуль `app/src-tauri/src/net_scan.rs` (~530 строк) — **чисто-Rust сканер сети** на tokio, без внешних бинарников (nmap можно подключить позже как опциональный sidecar).

### Возможности
- **CIDR-парсинг IPv4** (`parse_cidr`): "192.168.1.0/24" → 256 адресов; защита от слишком больших подсетей (макс /16).
- **Асинхронное TCP connect-сканирование**: tokio + `Arc<Semaphore>` (лимит 500 одновременных соединений по умолчанию), таймаут на соединение.
- **Banner grabbing**: чтение до 256 байт с открытых портов; для HTTP-портов отправляется `HEAD / HTTP/1.0`.
- **Карта порт→сервис**: 25 стандартных портов (ssh, http, smb, rdp, mysql, redis, mongodb и др.).
- **Diff с инвентарём**: сравнение с `hosts.db` — алерт на «новое устройство в сети» (`new_hosts`).
- **SQLite-хранилище** `~/.w420/net_scan.db` (таблица `scan_results`, индексы по IP и времени).

### Tauri-команды (5)
`net_scan_subnet`, `net_scan_last`, `net_scan_history`, `net_parse_cidr`, `net_default_ports`

Зарегистрированы в `lib.rs` (модуль + state + invoke handler).

## Проверка

- **8/8 unit-тестов** модуля проходят (CIDR /24, /30, /32, защита от /8, карта портов).
- **Живой тест**: скан `127.0.0.1/32` нашёл открытые порты **8080 (http-alt, banner: "HTTP/1.0 200 OK..."), 6379 (redis), 3000** — реальный вывод в логе.
- `cargo build --release` — exit 0, бинарник 46.6 МБ.
- Workspace: 27/28 тестов (1 провал — известный старый `sysops::gitleaks`, не связан с изменениями).

## Что дальше (по плану EVOLUTION_PLAN.md)

Фаза 7 — IDS/IPS (Suricata/tcpdump sidecar), Фаза 8 — файрвол (nftables), далее SIEM, EDR и т.д.

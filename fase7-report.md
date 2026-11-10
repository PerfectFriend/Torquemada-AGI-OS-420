# Отчёт: Фаза 7 — Анализ трафика и IDS/IPS

Дата: 2026-11-04

## Что сделано

Создан модуль `app/src-tauri/src/traffic.rs` (~1340 строк) — анализ трафика и IDS/IPS.

### Возможности
- **IDS-перехват через tcpdump** (sidecar): запуск/останов на выбранном интерфейсе, BPF-фильтр, чтение потока пакетов построчно.
- **Pure-Rust детектор угроз** поверх потока:
  - *горизонтальное сканирование портов* — ≥15 разных портов с одного IP за 60 с → алерт high;
  - *флуд/DoS* — ≥500 пакетов от одного источника за 10 с → алерт medium;
  - *C2/бэкдор-порты* (23, 1234/12345, 31337, 4444, 5555, 6666/6667, 27374) → алерт high;
  - кулдаун алертов 30 с, чтобы не спамить.
- **SQLite-хранилище** `~/.w420/traffic.db`: таблицы `alerts` и `blocked_ips`.
- **Разовый захват в .pcap** (`traffic_capture`) — для последующего разбора в Wireshark/tshark.
- **Статистика из /proc/net/dev**: rx/tx байты по интерфейсам, скорость (бит/с) между вызовами, топ-10 говорящих по числу пакетов.
- **Режим IPS — блокировка IP через nftables**: таблица `inet w420_block`, набор `w420_blocked`, цепочка `w420_input` с правилом `ip saddr @w420_blocked counter drop`; блокировка/разблокировка/список. Валидация IPv4 перед вызовом nft (защита от инъекции в аргументы).
- **Авто-блокировка** при алерте high (режим `auto_block` IDS).
- **Импорт алертов Suricata (EVE JSON)** — forward-compatibility, если Suricata будет установлена.
- **AI-анализ алертов** через `w420-ai` (NVIDIA NIM / Mistral Large 4 по умолчанию): оценка угрозы, приоритизация, рекомендации по реагированию (по-русски).

### Tauri-команды (11)
`traffic_start_ids`, `traffic_stop`, `traffic_status`, `traffic_alerts`, `traffic_stats`,
`traffic_capture`, `traffic_block_ip`, `traffic_unblock_ip`, `traffic_blocked_list`,
`traffic_eve_sync`, `traffic_ai_analyze` — все зарегистрированы в `lib.rs` (+ `.manage`).

## Проверка

| Проверка | Результат |
|---|---|
| `cargo check -p w420` | exit 0 (чисто) |
| Тесты модуля `traffic` | **11/11 ok** |
| `cargo build --release` | exit 0, бинарник **46.97 МБ** |
| `cargo test --workspace` | 38 ok / 1 failed — единственный провал известный старый `sysops::gitleaks` (не связан) |

Сквозные тесты модуля (без root):
- `test_eve_sync_imports_alerts` — импорт EVE JSON с 3 строками (2 alert + 1 flow) → в БД ровно 2 алерта, severity high/medium, source=suricata;
- `test_alert_db_roundtrip` — запись/чтение алерта и подсчёт в БД;
- `test_detector_port_scan` / `_flood` / `_c2_port` — детектор срабатывает на сканирование, флуд и C2-порт;
- `test_parse_tcpdump_line_basic` — разбор реальной строки tcpdump.

## Блокер: нужен root

Живой перехват пакетов и блокировки nftables требуют привилегий — под uid 1000 их нет:

```
tcpdump -i lo ... → "You don't have permission to perform this capture" (CAP_NET_RAW may be required)
nft list tables  → "Operation not permitted (you must be root)"
getcap /usr/bin/tcpdump → пусто (нет file-капабилити)
passwordless sudo → отсутствует ("interactive authentication is required")
```

Поэтому **живой захват пакетов ещё не проверялся** — тесты покрывают парсер, детектор, БД и импорт, но не сам факт чтения трафика с интерфейса.

В модуле уже реализован фолбэк `sudo -n` (сначала прямой запуск, затем `sudo -n tcpdump` / `sudo -n nft`). Чтобы включить живую работу, нужен один из вариантов (владелец даёт root):
1. `sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump` и `sudo setcap cap_net_admin+eip /usr/sbin/nft`;
2. либо `/etc/sudoers.d/w420` с `NOPASSWD` для `/usr/bin/tcpdump` и `/usr/sbin/nft` (подходит под уже реализованный фолбэк `sudo -n`).

После выдачи прав — живой end-to-end тест: IDS на `lo` с фильтром `tcp port 8080`, генерация трафика, проверка `packets_seen > 0` и алертов.

## Что дальше

Фаза 8 — управление брандмауэром и сегментация сети (nftables-профили, зоны).

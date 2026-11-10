# Этап 29 (RAT) + панель «Диспетчер» (Argus) — DONE

## Из твитa @geekbb (Argus, github.com/Ray-lea/Argus) взято
Единое окно диспетчера: процессы с ресурсами, графики истории, сервисы, порты, file-occupation. У нас сервисы уже были (rat), добавлены недостающие части.

## Этап 29 — RAT поверх SSH (`rat.rs`, 9 команд)
- `rat_power` reboot/shutdown/lock/logoff; `rat_services_list`; `rat_service_control` start/stop/restart/status; `rat_log_view` (journalctl, unit/since/limit); `rat_log_clear` (rotate+vacuum); `rat_disk` (df); `rat_pkgs` (dpkg/rpm count); `rat_info_export` CSV/XML; `rat_wake` — WoL magic packet (6×FF + 16×MAC) чистым Rust на UDP broadcast 255.255.255.255:9, без sidecar.
- Безопасность: аргументы валидируются белым списком `[A-Za-z0-9@._:/-+ ]`, команды уходят в ssh как фиксированные строки — инъекций нет.
- UI `rat.js`: панель RAT в v-net (хост, power-кнопки с confirm, сервисы, логи, диски, пакеты, экспорт, WoL по MAC).

## Панель «ДИСПЕТЧЕР» (`argus.rs` + `argus.js`, раздел v-stat)
- **Процессы**: sysinfo 0.30, per-process CPU%/RAM/user/cmdline, сортировка cpu/mem/name/pid, фильтр, kill с confirm (`argus_kill`).
- **Графики**: `argus_metrics_start` — поток-семплер 1 раз/сек, ring buffer 7200 точек (2 ч) + дубль в `~/.w420/argus-metrics.jsonl`; canvas-кривые CPU и RAM в реальном времени.
- **Порты**: `argus_ports` — `ss -tunap`, парсинг в Rust (proto/local/remote/state/pid/process).
- **Файлы**: `argus_file_users(path)` — скан `/proc/<pid>/fd` + cwd/exe, возвращает pid+имя держателей.

## Проверено
- `cargo test --workspace`: **169 passed, 0 failed** (+8 новых: rat — валидация токенов, WoL пакет/loopback, escapes; argus — parse_ss, file_users находит свой открытый файл, ring cap 7200, scan_procs находит себя).
- `node --check` rat.js/argus.js OK; все `invoke('rat_*'/'argus_*')` совпадают с командами; `v-net`/`v-stat` на месте.
- `cargo build --release` → exit 0.

## Честные ограничения
- Live-SSH к удалённому хосту в dev-окружении не гонялся (нет цели); валидация и ошибки — в тестах.
- WoL уходит на broadcast — если хост в другой подсети, понадобится directed broadcast (доработаем при случае).
- История метрик — в памяти + jsonl; «откат на 7 дней как у Argus» пока не делаем,目前 2ч ring + файл.

## Следующий этап
30 — сетевые утилиты уровня DameWare: ping/traceroute/DNS/port-check.

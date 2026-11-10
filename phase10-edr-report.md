# W420 — Фаза 10 (EDR, локальное ядро) — 2026-11-05

## edr.rs — готово, протестировано вживую
- Скан процессов через sysinfo 0.30 (pid, имя, exe, cmd, CPU, RAM, parent) + снимки в `~/.w420/edr.db`.
- Соединения через `ss -tunp` (свой парсер, юнит-тест на реальном формате).
- Baseline процессов + diff: новый процесс → событие `new_process`; если у него есть **внешнее** соединение (вне RFC1918/loopback/link-local — `is_external`, покрыто тестами) → severity **high**.
- Фоновый watch (поток, интервал настраивается) — периодический scan+diff.
- Реагирование: `edr_kill_pid` (kill -9, защита pid≤1 и self; **live-тест: поднял `sleep 60`, убил, проверил исчезновение**), `edr_respond isolate_ip` → drop в обе стороны через `inet w420_fw` (работает от пользователя, cap_net_admin).
- Команды: `edr_scan_processes, edr_connections, edr_baseline_set, edr_diff, edr_events, edr_watch_start/stop/status, edr_kill_pid, edr_respond` (всего в приложении теперь ~100 команд).
- UI: карточка «EDR · ПРОЦЕССЫ · СОЕДИНЕНИЯ» во вкладке СЕТЬ (`edr.js`, `node --check` OK, HTML-баланс 0).

## Проверено
- `cargo test -p w420 --lib -- edr` — 5/5 ok (parse_ss, is_external, kill guards, реальный kill, baseline diff с high-severity).
- Вся lib: 60 passed / 1 известный fail (gitleaks, окружение) / 2 ignored (live-тесты).
- `cargo build --release` — чисто, бинарник 47.8 МБ.

## Что осталось по плану (Фазы 10–16)
- EDR remote-агент (легковесный бинарник на удалённые хосты, HTTPS-ингест событий) — unbuilt.
- Фаза 11 патч-менеджмент, 12 VPN (sing-box sidecar), 13 веб-сканер, 14 PKI, 15 AI SOC (частично есть: security_ai + siem_ai_summary), 16 упаковка в ОС — unbuilt.

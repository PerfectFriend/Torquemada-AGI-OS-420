# Phase Madre — Мать Торквемада за штурвалом арсенала (Torquemada 228 AGI)

Коммит: `d8d3ad3` · тесты: workspace all green (182+11+20 lib/bin/doctests, 0 failed) · `cargo build --release` exit 0.

## Философия (вшита в движок)
«Доверяем только своим пакетам — чужие все дропаем, для них нет хостов.»
Политика **default-deny**: запрещено всё, что не разрешено (egress allowlist only).

## Что добавлено — `app/src-tauri/src/madre.rs` (новый модуль, 13 команд)
- **Default-deny egress** — таблица `inet w420_madre`: input/output `policy drop`, allowlist своих подсетей/хостов (10/8, 172.16/12, 192.168/16 + ручной allowlist), honeypot-порты логируются. Применение атомарное через `nft -f` (как firewall.rs), без root — `needs_root` + персист в `~/.w420/madre.json`.
- **Honeypot** — TCP-ловушки на портах 22/2222/3389/8080/8443/9200, все подключения пишутся в `~/.w420/madre.db`.
- **Watchdog** — цикл (интервал из конфига), сканит `ss -tunap` на C2-порты (4444/5555/6666/31337/12345) вне своих сетей → событие `watchdog`.
- **Штурвал AGI** — `madre_helm` отдаёт AGI-оболочке (agi.rs) системный промпт Матери + сводку арсенала; мутации — только через human-in-the-loop approve.
- Команды: `madre_status, madre_mode_set, madre_allow_add/remove/list, madre_apply, madre_verdict, madre_honeypot_start/stop, madre_watchdog_start/stop, madre_events, madre_helm`.

## Чистая логика (тесты без root/сети)
`parse_allowlist` (фильтр мусора/дублей), `is_own`/`verdict` (foreign→drop), `build_madre_rules` (проверка policy drop + allowlist + honeypot-логов), промпт содержит философию. 5 тестов madre — все ok.

## Что осталось
- UI-панель «Арсенал Матери» в `app/dist` (тонкий клиент, native-only вызовы).
- Связка helm → agi.rs: AGI читает `madre_helm` как инструмент (добавить в whitelist agi::tools_list).

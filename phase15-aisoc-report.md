# Фаза 15: AI SOC — автономный центр операций безопасности (ai_soc.rs)

**Дата:** 2026-11-05 · **Статус: DONE**

## Что сделано

Новый модуль `app/src-tauri/src/ai_soc.rs` (~800 строк, SocManager, БД `~/.w420/soc.db`) — «мозг» W420 поверх siem/edr/traffic/firewall. Зарегистрирован в `lib.rs` (mod + `.manage()` + 8 invoke-команд).

### Автономный цикл (`soc_autonomous_cycle`)
1. **Сбор**: `siem.ingest()` + `siem.correlate()`, EDR `scan_processes` + diff к baseline (через свой `ss -tunp` + публичный `edr::parse_ss`), критические алерты из traffic.db.
2. **Решение**: открытые инциденты siem.db дедупятся по (src_ip, title) в `soc.incidents`, матчятся с playbooks по severity (ранг сравнивается в Rust — строковое сравнение в SQL ломается).
3. **Действие**: при `auto_response=1` и `sev_rank >= min_severity` playbook'а — `traffic::block_ip` / `edr::isolate_ip_free`. Guard: loopback/пустые IP не трогаем (`actionable_ip`).
4. **Отчёт**: цикл пишется в `soc_cycles` (events_seen, incidents_new, actions_taken, log).

### Playbooks (таблица в soc.db, засеяна при init)
`bruteforce_block` (block_ip, auto), `malware_isolate` (isolate, auto), `data_exfil_block` (block+alert, ручной), `new_host_alert`, `critical_contain` (isolate+block, auto). У каждого runs/success/fail — обучение через `soc_feedback`.

### AI на естественном языке (NVIDIA KeyRotation, модель `mistral-large-4-1t-a52b`)
- `soc_chat` — диалог с SOC на русском с контекстом статуса и открытых инцидентов
- `soc_forecast` — прогноз векторов атак по агрегированной статистике инцидентов
- `soc_ai_cycle_report` — executive summary смены, сохраняется в последний цикл

### UI
Карточка «AI SOC · АВТОНОМНЫЙ ЦИКЛ» в `app/dist/index.html` + обёртки в `ops.js`: СТАТУС / ЗАПУСТИТЬ ЦИКЛ / ИНЦИДЕНТЫ / AI-СВОДКА / ПРОГНОЗ / поле вопроса.

## Проверено
- Юнит-тесты `ai_soc`: 3/3 (actionable_ip, sev_rank/needs_auto_action, live dry-цикл)
- Полный `cargo test -p w420 --lib`: **79 passed, 1 failed** — единственный известный fail `sysops::gitleaks` (pre-existing)
- `cargo build --release`: Finished, exit 0
- **LIVE** `live_soc_ai` (NVIDIA): chat + forecast + ai_cycle_report — все вернули содержательные ответы, тест ok (211 с)
- `node --check ops.js` OK; баланс div/section = 0

## Известные нюансы
- Модель NVIDIA (reasoning) иногда начинает ответ с пересказа промпта — фолбэк `content → reasoning_content` уже в провайдере `w420-ai` (тот же паттерн, что в siem/web_scan).
- `kill_pid` в авто-цикле намеренно пропущен (требует pid) — только ручной `soc_playbook_run`.

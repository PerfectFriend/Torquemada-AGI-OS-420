# Этап 18 — доведение обещанного функционала W420 (2026-11-05)

Все пункты из EVOLUTION_PLAN.md, которые были объявлены, но не доведены до рабочего состояния, реализованы, собраны и протестированы.

## Что реализовано

### 1. SIEM rule-engine (`siem.rs`)
- Таблица `rules` с сидом дефолтных правил (`burst-src`: ≥10 событий с одного src за 10 мин; `critical-single`: одиночный critical)
- `correlate()` переписан на rule-engine на Rust: ранжирование severity в Rust (строковое сравнение в SQL ломалось), окно `window_minutes`, порог `min_events`, дедуп открытых инцидентов, шаблон заголовка
- Команды: `siem_rules_list`, `siem_rule_add`, `siem_rule_remove`, `siem_rule_toggle`, `siem_incidents_list`, `siem_incident_create`, `siem_incident_set_status`
- UI: карточка SIEM — список правил, добавление (имя/порог/окно/severity/шаблон), вкл/выкл, удаление, список инцидентов по статусу, перевод инцидента в resolved

### 2. Net scan diff (`net_scan.rs`)
- `net_scan_diff` — сравнение двух последних сканов: новые и исчезнувшие хосты
- Новые хосты автоматически пишутся в `siem.db` как события `source='net_scan'` → подхватываются AI SOC playbook `new_host_alert`
- UI: кнопка «DIFF СКАНОВ» в карточке сети

### 3. VPN traffic (`vpn.rs`)
- `vpn_traffic` — агрегация rx/tx по пирам из `wg show all`: per-peer, total_rx/total_tx, top_talker; пустой список без паники
- UI: кнопка «ТРАФИК» в карточке VPN

### 4. PKI продление (`pki.rs`)
- `pki_cert_renew {days}` — перевыпуск неотозванных сертификатов, истекающих в пределах N дней
- `parse_not_after` парсит и openssl-формат (`Nov  5 23:12:00 2027 GMT`), и RFC3339
- UI: кнопка «ПРОДЛИТЬ ≤30д» в карточке PKI

### 5. Веб-скан: status + md-отчёт (`web_scan.rs`)
- `web_scan_status` — хосты (всего/уникальных/новых), последний скан, уязвимости по severity
- `web_scan_report` — детерминированный markdown-отчёт (таблицы уязвимостей и последних хостов), без AI — для архива и тикетов
- UI: кнопки «СТАТУС» и «ОТЧЁТ MD» в карточке веб-сканера

## Верификация

- `cargo test -p w420 --lib` → **90 passed, 0 failed, 7 ignored** (+8 новых тестов: rules CRUD/toggle/correlate, diff_ip_sets, aggregate_traffic, parse_not_after, cert expiring)
- `cargo build --release` → exit 0 (бинарник ~49 МБ)
- `node --check` для `ops.js`, `fw.js`, `net.js` → OK
- Все 12 новых команд зарегистрированы в `lib.rs`

## Что осталось (не входит в «обещанный функционал")

- Полная проверочная загрузка собранного ISO на железе/VM
- Живой прогон UI в Tauri-окне (нет дисплея на этом хосте; отладка — через CLI/API)

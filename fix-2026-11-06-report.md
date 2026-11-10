# Fix-отчёт: пересборка артефактов + подключение THREAT MONITOR (2026-11-06)

По результатам аудита `audit-2026-11-05-report.md` закрыты находки HIGH (устаревшие артефакты) и MEDIUM (dead UI threats).

## 1. THREAT MONITOR подключён к фронтенду

- `app/dist/index.html`: в карточку THREAT MONITOR AGENT добавлены кнопки **СКАН СИСТЕМЫ / SYNC БАЗЫ CVE / УЯЗВИМОСТИ (+фильтр severity) / АЛЕРТЫ / ИСТОЧНИКИ / АЛЕРТ id→прочитан**, вывод `#th-out`, статус `#th-stat`. Старые `#feed`/`#brief` не тронуты — их использует inline-скрипт (audit-лента, AGI BRIEF).
- Новый `app/dist/threats.js` (подключён `<script src="threats.js">`): 7 команд `threats_scan / threats_sync / threats_list / threats_alerts / threats_acknowledge_alert / threats_sources / threats_last_scan` — все были в `generate_handler!`, теперь реально вызываются из UI (было 0 вызовов).
- Поля JS сверены с serde-структурами Rust (`cve_id`, `cvss_v3_score`, `alert_id`, `acknowledged`, …); аргумент acknowledge — camelCase `alertId` (Tauri конвертирует в `alert_id`).
- Проверка: `node --check threats.js` OK; баланс `<div>` 0; все 7 `threats_*` теперь встречаются в dist JS.

## 2. Артефакты пересобраны со свежим UI

- `scripts/build_deb.sh`: добавлена очистка staging (`rm -rf opt/w420/dist opt/w420/tts-server` перед копированием) — убирает старую вложенную `dist/dist` и гарантирует свежий фронтенд.
- `cargo build --release` → exit 0 (27 с, инкрементально).
- **.deb**: `packaging/w420_1.0.0_amd64.deb` (2026-11-06 03:41, 11.4 МБ) — `dpkg-deb -c` подтверждает: `opt/w420/dist/threats.js` и `ai-provider.js` на месте, 27 файлов dist, `dist/dist` — 0. `dpkg-deb -I` — control ок.
- **.rpm**: `packaging/rpmbuild/RPMS/*/w420-1.0.0-1.*.rpm` — `rpm -qip` ок, `rpm -qlp` показывает `/opt/w420/dist/threats.js` и `/opt/w420/w420`.
- **ISO**: `packaging/w420-os-20261106.iso` (2.8 ГБ, `file`: ISO 9660 'W420-OS' **bootable**), сборка exit=0, в корень ISO положены свежий `w420_1.0.0_amd64.deb` + `preseed.cfg` + `nocloud/user-data` (autoinstall, LUKS full-disk). Лог: `packaging/build_iso_20261106.log`. Внутренний .deb верифицирован отдельно через `dpkg-deb -c` (см. выше).

## 3. Что осталось

- Boot ISO на VM/железе — не проверялся (нет дисплея/VM на хосте).
- GUI-клик по новым кнопкам threats — headless-хост, проверено статически (wiring + node --check + serde-имена).
- Из аудита не закрыто: автостарт TTS при старте приложения (проверить в GUI), `edr_agents_list` (нет в плане реализации), mapping имён команд в EVOLUTION_PLAN.md.

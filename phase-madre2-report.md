# Phase Madre-2 — UI арсенала + AGI за штурвалом

Коммит: `19ffbb5` · тесты: 182+11+20 зелёные, 0 failed · release build exit 0 · `node --check madre.js` OK.

## Что добавлено
- **UI-панель «АРСЕНАЛ МАТЕРИ ТОРКВЕМАДЫ»** в секции СЕТЬ (`app/dist/index.html` + `app/dist/madre.js`, native-only): режим observe/enforce, применить/снять default-deny (w420_madre), honeypot on/off, watchdog on/off, allowlist (добавить своего), вердикт Матери для любого IP (accept/drop), «ШТУРВАЛ AGI» — промпт + сводка, автообновление каждые 15 с.
- **AGI whitelist расширен**: инструменты `madre_helm` и `madre_status` доступны модели AGI-Ω как read-only (`agi.rs`: tools_list 4→6, tool_exec/decide/agi_tool_exec/task_approve принимают `MadreManager`). Мутирующие команды (`madre_apply` и т.п.) в whitelist НЕ входят — только через PROPOSE + ручной approve.
- Рефакторинг madre.rs: `status_value`/`helm_value` — чистые функции, команды оборачивают их.

## Проверено
- `cargo test --lib -- agi:: madre::` → 10/10 ok (whitelist считает 6 инструментов, madre_apply не в whitelist).
- Полный workspace: 0 failed. Release-сборка собрана.

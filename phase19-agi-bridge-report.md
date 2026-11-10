# Phase 19 — AI-мост AGI-оболочки: отчёт (2026-11-06)

## Что сделано
Новый модуль `app/src-tauri/src/agi.rs` + 8 команд в `generate_handler!` + UI-скрипт `app/dist/agi.js`.

### Rust (`agi.rs`)
- `agi_chat(prompt, history)` — чат AGI-Ω поверх `ai_providers::chat_messages` (извлечён на старте этапа): системный промпт W420, история до 20 сообщений, KeyRotation ключей, наружу — только `key_mask` вида `…abcd`, модель/провайдер/латентность/tokens.
- `agi_status()` — LIVE/SIM бейдж: есть ли включённый провайдер с активными ключами.
- `agi_tools_list()` / `agi_tool_exec(name, args)` — whitelist **только чтение**: `system_status` (sysinfo), `siem_dashboard`, `soc_status`, `threats_last_scan`. Никаких мутаций из модели напрямую.
- `task_start(goal, interval_secs, max)` / `task_stop` / `task_status` / `task_approve(id, approve)` — автономная задача в tokio-цикле (интервал ≥5 с, max 10 итераций по умолчанию). Ответ модели разбирается (`parse_task_reply`): строки `PROPOSE: {"kind":"run_tool","params":{…}}` становятся pending-предложениями, остальное — заметки-отчёты. APPROVE выполняет только whitelisted чтение (`decide`), статус: pending→approved→executed/failed или rejected. Состояние — один `Arc<Agi>` через OnceLock (без рассинхрона State/глобал).

### UI (`agi.js`, подключается последним скриптом, native-only)
- Чат (`#ai/#aisend/#ask`, `brief`) → `agi_chat` с персистентной историей `w420.hist`; в чистом браузере — прежний SIM.
- Бейдж `#aib` и вкладка AGI ASSISTANT → LIVE/SIM по `agi_status`; `#aimsg` описывает реальный мост; чипы `⚙ <tool>` → `agi_tool_exec`.
- AUTONOMOUS TASK (`#tgoal/#tint/#tgo/#tstop/#tstat`) → нативные `task_*`: poll статуса каждые 3 с, заметки в терминал, pending PROPOSE — карточки с APPROVE/REJECT → `task_approve`. Трей-ивенты (`w420:stop-task`) и `task` для HUD-текста работают как раньше.

## Проверено
- `cargo test --workspace`: **126 passed, 0 failed, 7 ignored** (из них 5 новых agi: парсинг PROPOSE/заметок, промпт задачи, whitelist, постановка proposal).
- `cargo build --release`: exit 0.
- `node --check agi.js`: OK.
- Wiring-аудит: 177 `#[tauri::command]` = 177 в handler (6 корневых — артефакт парсера имён модулей), **128 inv-вызовов из dist, 0 неразрешённых**, все 8 `agi_*`/`task_*` на месте.

## Известные пределы
- Live-ответ модели (NVIDIA) — `#[ignore]`-тест, на этом хосте без дисплея не гоняем; чат в UI проверяется вручную.
- Инструменты модели — только чтение; запись/изменения — строго через PROPOSE + ручной APPROVE.
- `h-agi` (HUD «consciousness») — пока остаётся SIM, разбирается на этапе 25.

## Следующий этап
Этап 20 — кошелёк REAL: keyring в Rust (AES-256-GCM at rest), `wallet_balance` через JSON-RPC testnet, `wallet_send`/`wallet_sign`, UI v-key/v-wallet → inv.

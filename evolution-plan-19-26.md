# План эволюции: доведение SIM-элементов интерфейса до REAL (2026-11-06)

Основан на аудите `ui-audit-report.md`: из 221 id интерфейса 60 операционных кнопок уже REAL (→ 167 команд Rust), ~12 локальных REAL (vault AES-GCM, DID, кошелёк, карта, радио, HUD-метрики), остальное — честно помеченный SIM. Полный план — новая секция «Этапы 19–26» в `EVOLUTION_PLAN.md`. Кратко по каждому подготовленному элементу, в порядке реализации:

## Этап 19 — AI-мост оболочки (фундамент для 23/24)
Элементы: чат AGI-Ω (`ask`, `ai`, `aisend`, `brief`), терминал `cmd agi`, AUTONOMOUS TASK (`tgo/tstop`), HUD `h-agi`.
- `agi_chat` — обёртка над существующей `ai_providers::ai_chat` (KeyRotation, дефолтный провайдер NVIDIA) + системный промпт; инструменты выполняются на Rust (`system_metrics`, `siem_dashboard`, `fw_status`, `soc_status`, `threats_last_scan`, vault list).
- `task_start/task_stop/task_status` — цикл автономной задачи в Rust, human-in-the-loop (propose → approve → execute по whitelist).
- UI: `sample` (window.claude) заменяется на `inv('agi_chat')`; бейдж LIVE/SIM остаётся, но теперь LIVE при реальном провайдере.

## Этап 20 — Кошелёк REAL (v-key, v-wallet)
Элементы: `kgen/kload/kshow/ksign` (уже real локально), `wsend`, `tmint` ([SIM]), `wbal/waddr`.
- Keyring в Rust: create/import/list/unlock/sign/send/balance; ключи AES-256-GCM at rest (как ai_providers), наружу — только адреса.
- `wallet_send` через JSON-RPC, **testnet first**; [SIM] снимается после live-теста. DC exchange остаётся с плашкой.

## Этап 21 — Vault PQC (v-vault)
Элемент: плашка «PQC TAG: SIM».
- Гибрид в Rust: ML-KEM-768 + AES-256-GCM (`vault_seal_pqc`/`vault_open_pqc`); первый потребитель — DID-ключи. Плашку снять после round-trip live-теста.

## Этап 22 — DIGITAL ID персистентность (v-id)
Элементы: `idgen/idsign`, плашка «DID: WIP».
- `did_create/did_list/did_sign_challenge/did_verify`; приватный ключ — в зашифрованный vault; `did:w420:…` становится персистентным.

## Этап 23 — AGI-Ω FM, настоящий эфир (v-radio)
Элементы: `rbtn/rvol/rvoice/rreq/rask/ebtn/esay/evault`, плашка «запасные реплики: SIM».
- `radio_script` через `agi_chat` (этап 19), озвучка через `voice_say` (TTS real), выпуск эпизода из реального audit-лога.

## Этап 24 — MIND MAP AGI-GEN (v-map)
Элементы: `madd/mdel` (real), плашка «AGI-GEN: SIM», новая кнопка «СГЕНЕРИРОВАТЬ ИИ».
- `map_generate(prompt)` → JSON-схема узлов/рёбер → валидация → `w420.map`.

## Этап 25 — HUD mesh/agi
`h-mesh` → реальные узлы из `bridge_status` (или удалить карточку); `h-agi` — по этапу 19. Остальные HUD-индикаторы уже real.

## Этап 26 — Зачистка и финал
Dead-команды аудита (`security_ai_*` — в UI или удалить; `config_parse_*` — проверить bridge-config.js), маппинг 13 имён команд плана, `edr_agents_list`; финальный full-аудит, 0 SIM без плашки, пересборка .deb/.rpm/ISO, итоговый отчёт в топик 252.

Шаблон каждого этапа: Rust-модуль → регистрация в `generate_handler!` → UI-wiring по id → `cargo test --workspace` → `cargo build --release` → `node --check` + баланс HTML → live `#[ignore]`-тест → DONE в плане → отчёт в 252.

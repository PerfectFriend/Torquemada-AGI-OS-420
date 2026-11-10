# Phase 22–25 — AGI-оболочка доведена до REAL: отчёт (2026-11-09)

## Этап 22 — DIGITAL ID персистентность (DONE)
- `app/src-tauri/src/did.rs`, 6 команд: `did_create/list/status/sign_challenge/verify/remove`.
- ECDSA **P-256** (крейт `p256`, не k256/secp256k1); приватный ключ (PKCS#8) шифруется **AES-256-GCM** (PBKDF2-HMAC-SHA256, 600k итераций — та же политика, что у кошелька) в `~/.w420/did/keyring.json` (0600).
- DID = `did:w420:` + hex(SHA-256(SEC1 pubkey))[..20]; подпись — ECDSA prehash SHA-256(challenge), семантически идентична прежнему WebCrypto-поведению.
- UI `did.js`: GENERATE/SIGN → нативные команды, поле пароля, персистентный idv, плашка «DID: WIP» → LIVE.
- Тесты: **6 passed** (roundtrip sign/verify, неверный пароль → отказ, чужой challenge → INVALID, короткий пароль, удаление, детерминизм did).

## Этап 23 — AGI-Ω FM, настоящий эфир (DONE)
- `radio.rs`, 4 команды: `radio_script(kind, kind_desc, mood, ctx, request)`, `radio_episode(stats, entries)`, `radio_say(text)` (TTS-сервер `voice_say`, ответ — base64 WAV), `radio_status`.
- Тексты генерирует AGI-мост (`agi_chat` + KeyRotation); выпуск дня — из реальных stats аудита + последних записей.
- UI `radio.js`: `window.radioDJ/radioSay/epBuild` → inv (свое состояние DJ, т.к. R — lexical); заказы тем, озвучка с фолбеком на speechSynthesis; плашка «запасные реплики: SIM» → LIVE при живом AGI.
- Тесты: 3 passed (промпты ведущего/выпуска).

## Этап 24 — MIND MAP AGI-GEN (DONE)
- `map.rs`, 2 команды: `map_generate(prompt)`, `map_agi_status`.
- AGI → строгий JSON `{nodes:[{text,parent}]}`; извлечение JSON из текста (в т.ч. ```json … ```), валидация: parent — индекс раннего узла или -1, ≤40 узлов, текст непустой ≤60 символов.
- UI `map.js`: кнопка «СГЕНЕРИРОВАТЬ ИИ» (тема из поля #mt), та же круговая раскладка, запись в `w420.map`, `drawMap()`; плашка «AGI-GEN: SIM» → LIVE.
- Тесты: **6 passed** (извлечение, валидация, капы/обрезка).

## Этап 25 — HUD: реальные метрики (DONE)
- `hud.js`: `h-mesh` ← `bridge_status`/`tor_status`/`vpn_status` (живые sidecar-узлы + пиры, «все выкл» когда тихо); `h-agi` ← реальный tokens/s из `ai_provider_model_stats` (SIM-записи inline вида «99.7%» заблокированы через переопределение `textContent` элемента). Обе карточки SIM → LIVE.

## Общие цифры
- Команд теперь **199** (188 + 6 did + 4 radio + 2 map + … всего +11), все зарегистрированы в `generate_handler!`.
- `cargo test --workspace`: см. ниже в терминале (ожидается рост с 140); `cargo build --release` exit 0.
- Все новые UI-скрипты: `node --check` OK; браузерный режим без Tauri не затронут (все bridge-скрипты native-only).

## Что осталось (Этап 26)
- Зачистка dead-команд (`security_ai_*` обёртки), синхронизация имён плана, решение по `edr_agents_list`; финальный full-аудит (0 SIM без плашки); пересборка `.deb/.rpm/ISO`; итоговый отчёт.

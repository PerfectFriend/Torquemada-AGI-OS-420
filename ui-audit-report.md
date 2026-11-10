# Отчёт: аудит всех элементов управления UI — REAL vs SIM/декорация (2026-11-06)

Метод: программный разбор `app/dist` (221 id, все JS-файлы + inline-скрипты): для каждого контрола искался обработчик (`onclick/onchange/addEventListener`), затем в теле обработчика — вызов `inv("команда")` (реальный бэкенд) или его отсутствие (DOM/canned). Имена команд сверены с `generate_handler!` (167/167), serde-поля ответов — с JS. Все «реальные» кнопки ведут в Rust-команды с реальным side effect (nft/wg/openssl/sqlite/process/AI), проверенные ранее тестами (121 passed) и фазовыми отчётами.

## Итоговая статистика

| Класс | Кол-во | Что это |
|---|---|---|
| REAL — кнопка → `inv()` → реальная команда | **60** | все операционные карточки |
| REAL — локальная реализация в браузере (crypto/storage/audio) | ~12 | vault, DID, кошелёк, mind map, радио |
| REAL — HUD/навигация/настройки | ~10 | системные метрики, табы, settings, i18n |
| SIM — честно помечено плашкой/префиксом | ~15 | AGI-чат, h-agi/h-mesh, wsend/tmint и др. |
| Декорация (нет обработчика) | 31 id | почти все — **display-выводы** (out/div), а не контролы |

## По вкладкам (10 views)

### REAL — операционные карточки (все кнопки → inv → Rust)
- **СЕТЬ (v-net)**: n-scan/n-refresh/n-diff/h-add → `net_scan_subnet`, `net_scan_last`, `net_scan_diff`, `hosts_add` — реальный ping-скан, diff, БД. + карточки FW (fw-apply/rules/isolate/logs → `fw_profile_apply`, `fw_rules_list`, `fw_isolate_host`, `fw_logs` — реальный nft), SIEM (ingest/dash/ai/search + 7 кнопок правил/инцидентов → sqlite + rule-engine + AI), EDR (scan/conns/base/diff/watch/kill/isolate/events → sysinfo-скан процессов, реальный kill pid), PATCH (scan/list/sec/deploy/rollback/ai → apt + БД), VPN (init/add/list/up/down/status/traffic → wg + sing-box sidecar), WEB-СКАН (net/vuln/vlist/hosts/ai/status/report → скан + БД + AI-отчёт), PKI (init/issue/list/revoke/crl/renew → openssl CA), AI SOC (status/cycle/incidents/ai/forecast/chat → автономный цикл + NVIDIA), THREAT MONITOR (7 кнопок → trivy/CVE), Emergency (alarm/e-apply/e-off → `emergency_set`, реальный lockdown), Voice (tts_start/stop, voice_* → реальный TTS-сервер).
- **Настройки (⚙)**: gear/spanel/s-lang/s-theme/s-reset/s-close → `settings_get`/`settings_set` (`~/.w420/settings.json`), в браузере — localStorage fallback. REAL.

### REAL, но локально в браузере (без бэкенда)
- **VAULT (v-vault)**: `vput` — настоящий WebCrypto **AES-256-GCM** (PBKDF2-ключ из пароля), шифр в локальный vault. Плашка «PQC TAG: SIM» честная: постквантовая часть — симуляция.
- **DIGITAL ID (v-id)**: `idgen` — настоящий ECDSA P-256 keygen (WebCrypto), `did:w420:<fingerprint>`; «DID: WIP» — честно (персистентность WIP).
- **WALLET KEYS (v-key)**: `kgen/kload/kshow/ksign` — настоящие локальные ключи ethers (`Wallet.createRandom/fromPhrase`), адрес и подпись. «NETWORK: WIP» — честно.
- **MIND MAP (v-map)**: `madd/mdel` — настоящий граф в localStorage (`w420.map`) + canvas. «AGI-GEN: SIM» — генерация ИИ — сим.
- **RADIO (v-radio)**: `rbtn/rvol/esay` — настоящий звук через `speechSynthesis`; тексты — от модели или из «запасных реплик» (плашка SIM честная). Выпуск эпизода (ebtn) собирает статистику из реального audit-лога.
- **TERMINAL (v-term)**: `cmd` — настоящие локальные команды (`hash`/sha256); `agi …` → тот же чат.

### SIM — и честно об этом говорит UI
- **AGI ASSISTANT (v-ai)**: чат `ask/ai/aisend/brief` → `askAGI`. Если рантайм дал модель (`window.claude?.use('sample')`) — настоящий диалог с tool use; иначе — canned-ответы с префиксом `[SIM]`, а бейдж сам переключается LIVE↔SIM (`#aib`). Плашка на карточке: SIM. Честная симуляция с автоиндикацией.
- **AUTONOMOUS TASK (HUD)**: `tgo/tstop` — цикл задачи через модель с human-in-the-loop (propose → approve); без модели сразу пишет «модель недоступна». Инструмент `wallet_balance_sim` так и назван.
- **HUD-индикаторы**: h-clock/h-fps/h-heap/h-net/h-bat/h-sto/h-cores — **настоящие** (часы, rAF-FPS, performance.memory, navigator.connection, getBattery, storage.estimate; в Tauri — ещё и `system_metrics`). **h-agi = 99+random, h-mesh = 47 статично** — чистая декорация, но карточки помечены SIM.
- **CRYPTO (v-wallet)**: `wsend`/`tmint` — кнопки прямо подписаны **[SIM]**, баланс — локальная переменная, в логе честно «транзакция НЕ отправлена».

### Декорация (31 id без обработчика)
Почти все — **display-элементы** (выводы `out`, `feed`, `n-hosts`, `fw-out`, `e-stat`, `h-*`…), которые заполняются textContent из обработчиков других контролов — это не «мёртвые кнопки», а поля вывода. Кнопок/инпутов без какой-либо ссылки в JS среди них нет (кроме элементов внутри SIM-вкладок, перечисленных выше).

## Вывод

- **60 операционных кнопок — все REAL**, связаны с 167 зарегистрированными командами, покрыты тестами (121 passed) и фазовыми live-проверками.
- **Локальные REAL-функции** (шифрование vault, DID, кошелёк, карта, радио, терминал) работают в браузере по-настоящему — то, что симулируется (PQC, сеть кошелька, AGI-gen, модель чата вне рантайма), **явно помечено SIM/WIP прямо в UI**, включая автопереключение бейджа LIVE/SIM.
- **Фейков (заявлено одно, делает другое без пометки) — не найдено.** Единственная «серая зона»: чат AGI-Ω в отсутствие `window.claude` тихо отвечает canned-текстом, но с префиксом `[SIM]` и бейджем SIM — по правилам аудита это честная нереализованность, не обман.

# ТЕХНИЧЕСКОЕ ЗАДАНИЕ
## «WINDOWS 420 / W420» — кибербезопасностная ОС на базе ИИ (дебютная платформа «AGI OS»)

**Версия ТЗ:** 1.0 (2026-11-06) · **Статус:** рабочее, для передачи внешнему разработчику ·
**Основано на:** реальный проект `w420-install` (Tauri v2 + Rust + тонкий JS-клиент), 188 зарегистрированных backend-команд, 221 элемент интерфейса, этапы эволюции 1–21 завершены, 22–26 спланированы.

---

## 1. Общие положения

### 1.1 Назначение
Единая настольная платформа («AI shell») для эксплуататора безопасности: брандмауэр, SIEM, EDR, сканеры, VPN, PKI, AI SOC, кошелёк, PQC-vault, агентный ИИ-ассистент, радио, mind map, аудит-цепочка. Всё управление — из одного окна; бизнес-логика — в Rust; интерфейс — тонкий клиент; внешние инструменты — sidecar-бинарники под управлением Rust.

### 1.2 Целевые платформы
- **Linux (основная)**: Ubuntu 24.04+/Debian; root-операции (nftables, tcpdump, suricata, открытие портов) — только с повышением через sudo пользователя, без приёма пароля в приложение.
- **Windows/macOS (вторичные)**: сборка Tauri; функции, зависящие от Linux-инструментов, деграрадируют корректно (честная плашка WIP/SIM, не падение).

### 1.3 Что считается «система не уступает» (паритет-критерии)
См. §16 — чек-лист из 40 пунктов. Система обязана закрыть: (а) весь реализованный функционал §6.4–6.31 в эквиваленте или лучше; (б) весь backlog §8; (в) все требования безопасности §5; (г) процесс верификации §13.

---

## 2. Термины
- **REAL / SIM / WIP** — метки элемента UI: реально работает / симуляция (честно помечена) / в разработке.
- **Thin client** — HTML/CSS/JS не содержит бизнес-логики: только отображение и `invoke`.
- **Sidecar** — внешний бинарник (Go sing-box, Arti Tor, TTS-сервер, suricata), которым управляет Rust.
- **HITL** — human-in-the-loop: ИИ предлагает действие (`PROPOSE`), оператор нажимает APPROVE/REJECT.
- **KeyRotation** — перебор API-ключей AI-провайдеров по латентности с fallback при 401/429/5xx.
- **Конверт** — результат гибридного PQC-шифрования: `(kem_ct, nonce, ct)`.

---

## 3. Технологический стек (обязателен к воспроизведению)

| Слой | Технология | Примечание |
|---|---|---|
| Оболочка | Tauri v2 (Rust + WebView) | трей, меню, single-instance, autostart-плагин (по умолчанию выключен) |
| Backend | Rust 2021, edition stable ≥1.90 | крейты: `tauri`, `serde`, `serde_json`, `tokio`, `sysinfo 0.30`, `rusqlite`, `chrono`, `reqwest`, `sha2`, `sha3` (Keccak), `hmac`, `hkdf`, `aes-gcm`, `pbkdf2`, `zeroize`, `k256`, `bip39` (tiny-bip39), `rlp`, `hex`, `rand`, `ml-kem 0.2` (ML-KEM-768) |
| Workspace-крейты | `w420-core` (общая логика), `w420-ai` (AI-провайдеры: SQLite + AES-GCM + ротация) | — |
| Frontend | Чистый JS (ES2019+, `const`/arrow, async/await, DOM API), без фреймворков; vendor-библиотеки по месту (ethers UMD) | тонкий клиент |
| Файловая система | `~/.w420/` (keyring кошелька, AI-БД, keyring PKI), `/opt/w420` (установленная копия) | права 0600 на секреты |
| Sidecar | Go `sing-box` (Xray-совместимые конфиги); Rust Arti-client (Tor onion-service); TTS-сервер (Python/Rust, порт 8420, заголовок `X-W420-Token`); `suricata`, `tcpdump`, `nmap`, `trivy`, `gitleaks` — внешние бинарники | управление и парсинг — в Rust |
| Упаковка | `.deb` (dpkg), `.rpm`, ISO-производный (Ubuntu, preseed + nocloud autoinstall + LUKS) | скрипты `scripts/build_deb.sh`, `build_rpm.sh`, `build_iso.sh`, `luks_setup.sh`, `root_setup.sh` |

---

## 4. Архитектура

### 4.1 Схемa
```
┌──────────────────────────────────────────────────────────────┐
│ UI: тонкий клиент (index.html + dist/*.js, 221 элемент)       │
│   invoke('cmd', args) ──► результат/ошибка в DOM              │
│   bridge-скрипты (agi.js, wallet.js, pqc.js, threats.js…)     │
└───────────────┬──────────────────────────────────────────────┘
                │ Tauri IPC (команды 188 = 188 в generate_handler)
┌───────────────▼──────────────────────────────────────────────┐
│ Rust core: модули (§6) — вся бизнес-логика, крипто, sidecar   │
│   Управляемое состояние: Mutex-менеджеры (Siem, Soc, Threats, │
│   Pki, Firewall…) через .manage(); файловые keyring'и с lock  │
├──────────────────────────────────────────────────────────────┤
│ Sidecars: sing-box (Go) · Arti (Tor) · TTS:8420 · suricata ·  │
│ trivy/gitleaks/nmap/tcpdump (по требованию)                   │
└───────────────┬──────────────────────────────────────────────┘
                │ sudo (от имени пользователя, интерактивно)
        ┌───────▼────────┐
        │ ОС: nftables, sshd, systemd, /etc/hosts, PF/keychain  │
        └────────────────┘
```

### 4.2 Принципы
1. **Один invoke = одна атомарная операция** с типизированным результатом (`serde_json::Value` или `#[derive(Serialize)]`); ошибки — `Result<_, String>` с человекочитаемым текстом (на языке UI).
2. **Весь тяжёлый/долгий код — в Rust.** JS никогда не парсит системный вывод, не шифрует чувствительное (исключение — legacy-пути vault/DID, помеченные как таковые), не обращается к RPC/сети напрямую (кроме WebCrypto-vault и mind map).
3. **Секреты не покидают Rust.** Наружу — только маски (`…abcd`), адреса, подписи, статусы.
4. **Состояние UI извлекается идемпотентно**: `*_status`-команды опрашиваются, а не кэшируются вслепую.
5. **Деградация честная**: если Linux-инструмента нет или прав нет — ясная ошибка/плашка WIP, не молчаливый ноль.

---

## 5. Модель безопасности (жёсткие требования)

1. **API-ключи AI-провайдеров и парольные ключи** — AES-256-GCM at rest (PBKDF2-HMAC-SHA256, 200k–600k итераций); файлы keyring'ов — режим 0600; пароли не логируются.
2. **Маскирование**: любые «показать ключ» отдают `…abcd` (последние 4). Мнемоники кошелька/PQC-DID — отображаются один раз по явному действию с паролем.
3. **Привилегии**: root-действия (nftables apply, tcpdump capture, suricata, apt/install) — через `sudo -n` из уже настроенного окружения (NOPASSWD для узкого набора команд) либо интерактивный `sudo` пользователя. Пароль sudo **никогда** не принимается приложением.
4. **Сеть**: кошелёк отправляет транзакции **только после явного указания chain_id/RPC**; по умолчанию Sepolia testnet (`https://rpc.sepolia.org`, chain 11155111); UI требует confirm перед отправкой.
5. **ИИ-барьер**: агент (AGI-Ω/задачи) имеет **только read-only whitelist** инструментов (`system_status`, `siem_dashboard`, `soc_status`, `threats_last_scan`); любое изменение — через `PROPOSE` → ручной APPROVE; в чате — текстовый ответ.
6. **Аудит**: hash-chain журнал действий (`SHA-256`, prev-hash), максимальная длина ~300 записей с ротацией; тред-источники в SIEM — через ingest API.
7. **TTS/voice-канал**: локальный сервер, токен `X-W420-Token`; токен — в файле 0600 вне git.

---

## 6. Функциональные требования (реализовано — эталоны)

### 6.1 Общее ядро (`core`, 6 команд)
`system_metrics` (CPU/RAM/OS/host/uptime из sysinfo), `set_agent_status`, `set_tray_alert`, `notify` (системное уведомление), `tts_start`, `tts_stop`.
Требование: метрики — свежий `System::new_all()` на вызов, не кэшированный слепок.

### 6.2 Брандмауэр (`firewall`, 7) — nftables
`fw_profile_apply` (профили правил), `fw_status` (сухой прогон + текущие правила), `fw_rules_list`, `fw_rule_add`, `fw_rule_remove`, `fw_isolate_host` (полная изоляция IP), `fw_logs`.
Требование: построение набора правил — чистые функции (тестируемы); применение — через sudo nft; откат при ошибке применения.

### 6.3 Режим ЧС (`emergency`, 4)
`emergency_status`, `emergency_set`, `emergency_rules_preview`, `emergency_apply_saved`.
Профиль «всё закрыто, минимум сервисов»; предпросмотр до применения; применение — только подтверждённое.

### 6.4 VPN-мост (`bridge`, 8) — sidecar Go `sing-box`
`bridge_start`, `bridge_stop`, `bridge_status`, `config_parse_link`, `config_parse_profiles`, `config_parse_wireguard`, `config_parse_ovpn`, `config_build`.
Парсинг: vless/vmess/hysteria/wireguard/ovpn ссылок и подписок; сборка JSON-конфига sing-box; старт/стоп sidecar; статус (PID, порт, healthy). Правило: конфиги — в `~/.w420/bridge`, поиск бинарника sing-box по PATH и vendor-каталогу.

### 6.5 Tor (`tor`, 3)
`tor_start/stop/status` — встроенный Arti-client (Rust), onion-service-client; статус = bootstrap-состояние.

### 6.6 Обнаружение хостов (`net_scan`, 6; `hosts`, 9)
`net_scan_subnet` (nmap -sn + разбор), `net_parse_cidr`, `net_default_ports`, `net_scan_last`, `net_scan_history`, `net_scan_diff` (появились/исчезли хосты).
`hosts_add/list/remove/get/status/status_all/connect/disconnect/exec` — SSH-инвентарь (имя, IP, пользователь, порт, ОС), выполненные команды с таймаутом; ключи/пароли не логируются.

### 6.7 SIEM (`siem`, 13)
`siem_ingest` (событие), `siem_correlate` (окна/правила), `siem_events`, `siem_search`, `siem_dashboard` (сводка+топ-источники), `siem_ai_summary`, `siem_rules_list/add/remove/toggle`, `siem_incidents_list/create/set_status`.
Хранилище: SQLite (`~/.w420/siem.db`); правила — порог+окно+severity; корреляция — детерминированная, без ИИ.

### 6.8 IDS/трафик (`traffic`, 11) — suricata/tcpdump
`traffic_start_ids` (запуск suricata с нужким интерфейсом), `traffic_stop`, `traffic_status`, `traffic_alerts`, `traffic_stats`, `traffic_capture` (tcpdump), `traffic_block_ip/unblock_ip/blocked_list` (взаимодействие с firewall), `traffic_eve_sync` (парсинг eve.json), `traffic_ai_analyze` (AI-разбор алертов).

### 6.9 EDR (`edr`, 10)
`edr_scan_processes`, `edr_connections`, `edr_baseline_set`, `edr_diff`, `edr_events`, `edr_watch_start/stop/status`, `edr_kill_pid`, `edr_respond` (реакции: isolate/kill/monitor).
Baseline — JSON-слепок процессов/соединений; diff — массив изменений с severity.

### 6.10 Патч-менеджмент (`patch_mgmt`, 7)
`patch_scan_local`, `patch_scan_all`, `patch_list_updates`, `patch_deploy` (apt, подтверждённо), `patch_rollback_plan` (план откатa), `patch_status`, `patch_ai_assess` (AI-оценка обновлений).

### 6.11 Угрозы/CVE (`threats`, 7)
`threats_scan` (поиск уязвимостей локальной системы), `threats_sync` (обновление базы CVE), `threats_list`, `threats_alerts`, `threats_acknowledge_alert`, `threats_sources`, `threats_last_scan`.

### 6.12 Веб-скан (`web_scan`, 8)
`web_scan_net`, `web_scan_targets`, `web_vulns_list`, `web_scan_results`, `web_ack_host`, `web_ai_report`, `web_scan_status`, `web_scan_report` (MD). Основа — nmap NSE-профили; отчёты — детерминированные + AI-сводка отдельно.

### 6.13 PKI (`pki`, 8)
`pki_ca_init`, `pki_issue`, `pki_revoke`, `pki_verify`, `pki_crl`, `pki_list`, `pki_status`, `pki_cert_renew` (≤30 дней). Свой CA (rcgen/openssl-совместимый), хранение в `~/.w420/pki`, CRL обновляется при revoke.

### 6.14 VPN-сервер (`vpn`, 8)
`vpn_server_init` (WG-ключи), `vpn_peer_add/revoke/list`, `vpn_server_start/stop`, `vpn_status`, `vpn_traffic` (счётчики по peers). Sidecar/сервер — WireGuard.

### 6.15 Усиление (`harden`, 6; `sysops`, 6; `updates`, 1)
`harden_sysctl_plan/apply/revert`, `harden_ssh_plan/apply/revert`; `sysops_set_scope/get_scope`, `sysops_scan_trivy`, `sysops_scan_gitleaks`, `sysops_fim_baseline/check`; `updates_check`.
Правило: plan/apply/revert — всегда тройка, plan показывается до apply.

### 6.16 Голос (`voice`, 4)
`voice_status`, `voice_say` (TTS через локальный сервер 8420, `X-W420-Token`), `voice_hear_b64` (STT из base64-аудио), `voice_command` (распознавание → маршрутизация команды).
Требование ТЗ пользователя: **TTS/STT работают из коробки** — сервер стартует вместе с приложением, деградация — честная плашка.

### 6.17 AI-провайдеры (`ai_providers`, 17) — крейт `w420-ai`
`ai_providers_list/status/test/test_all`, `ai_provider_add/add_key/remove/set_enabled/set_default/test`, `ai_key_remove/set_active`, `ai_provider_list_models/set_models/test_models`, `ai_provider_model_stats`, `ai_chat`.
Хранилище: SQLite `~/.w420/ai_providers.db`. Ключи шифруются AES-256-GCM. Провайдеры: NVIDIA NIM (`https://integrate.api.nvidia.com/v1`, модель по умолчанию `mistralai/mistral-large-4-1t-a52b`, ответ может прийти в `reasoning_content` — фолбек обязателен), OpenAI-совместимые, Anthropic, Mistral, Groq, OpenRouter, DeepSeek, xAI, Perplexity (по конфигу). **KeyRotation**: сортировка по latency, fallback при 401/429/5xx, статистика токенов/латентности. Добавление ключей — из файла `/home/thomas/Документы/ObsidianVault/LLM-API-KEYS.md` (формат `nvapi-…`) или вручную в панели настроек.

### 6.18 Security-AI (`security_ai`, 8)
`security_ai_analyze/auto_response/report/config/set_config/analyses/auto_responses/reports` — анализ alerts/events, автоматические реакции по политике (confirm-gated для опасных).

### 6.19 AI SOC (`ai_soc`, 8)
`soc_status`, `soc_autonomous_cycle`, `soc_incidents`, `soc_playbook_run`, `soc_feedback`, `soc_ai_cycle_report`, `soc_chat`, `soc_forecast`.
Плейбуки — детерминированные; AI — только текст-разбор; обратная связь оператора меняет приоритеты.

### 6.20 AGI-мост (`agi`, 8) — Этап 19
`agi_status` (есть ли активный провайдер → LIVE/SIM), `agi_chat(prompt, history)` (мультиход, системный промпт AGI-Ω, KeyRotation, маски), `agi_tools_list`, `agi_tool_exec` (whitelist: `system_status`, `siem_dashboard`, `soc_status`, `threats_last_scan`), `task_start(goal, interval≥5c, max≤10)`, `task_stop`, `task_status`, `task_approve(id, approve)`.
Задача — цикл в tokio; ответ модели парсится: строки `PROPOSE: {json}` → pending-предложения; остальное — заметки в терминал. APPROVE выполняет только whitelisted чтение; статусы pending→approved→executed/failed|rejected. Состояние — один `Arc<Agi>` (OnceLock), все команды видят один и тот же экземпляр.

### 6.21 Кошелёк (`wallet`, 9) — Этап 20
BIP-39/BIP-32/secp256k1 (`bip39`, `k256`) в Rust: m/44'/60'/0'/0/0; адрес = keccak(uncompressed pubkey)[12:]; keyring `~/.w420/wallet/keyring.json` (0600), мнемоника под PBKDF2-600k + AES-256-GCM.
Команды: `wallet_create` (24 слова, показ один раз), `wallet_import`, `wallet_list`, `wallet_reveal`, `wallet_remove`, `wallet_sign_tx` (legacy, EIP-155, RFC-6979), `wallet_balance`, `wallet_send` (nonce pending → sign → `eth_sendRawTransaction`), `wallet_status`.
Эталон теста: «test test … junk» → `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`, ключ `0xac09…ff80`.

### 6.22 PQC-vault (`pqc`, 4) — Этап 21
ML-KEM-768 (FIPS 203) + HKDF-SHA256 + AES-256-GCM. Команды: `vault_pqc_keygen` (ek 1184 б / dk 2400 б, dk — один раз), `vault_pqc_seal(pk_hex, text)` → `(kem_ct 1088 б, nonce, ct)`, `vault_pqc_open`, `vault_pqc_status`.
Отказы: неверный dk → ошибка; порча ct → ошибка (AEAD-tag); битая длина → ошибка.

### 6.23 Локальные REAL-пути UI (без backend)
- **QFS Vault**: WebCrypto AES-256-GCM + PBKDF2 200k, localStorage (записи имя/ct/nonce/salt).
- **DIGITAL ID**: ECDSA P-256 ключ в памяти вкладки (персистетность — Этап 22).
- **MIND MAP**: узлы/рёбра в localStorage, drag-n-drop, layout.
- **AGI-Ω FM**: Web Audio генерация + speechSynthesis; AI-реплики — Этап 23.
- **AUDIT LOG**: SHA-256 hash-chain, verify/seal/clear.
- **HUD-метрики**: FPS/heap/net/battery/storage — реальные браузерные метрики.
- **AGI ASSISTANT [SIM]-заглушка** — заменена Этапом 19 на нативный GPT-мост; в браузере без Tauri остаётся stub.

### 6.24 Sidecar'ы и интеграции
- sing-box (Go): поиск `PATH`/vendor, запуск с `--config`, health.
- TTS-сервер: `http://127.0.0.1:8420/health`, `X-W420-Token`.
- JSON-RPC: reqwest, timeout 20 c, метод/параметры/ошибка → текст.

---

## 7. UI-требования (тонкий клиент)

### 7.1 Структура
- Одна страница (`index.html`), 221 управляемый элемент id; навигация — табы (`show(id)`); HUD-статусбар сверху.
- Вкладки: `TERMINAL`, `QUANTUM FS VAULT`, `DIGITAL ID`, `AGI-Ω FM`, `AUDIT LOG`, `WALLET · OFFLINE KEYS`, `CRYPTO · WALLET · MINT · DC EXCHANGE`, `MIND MAP`, `AGI ASSISTANT`, `СЕТЬ · ОБНАРУЖЕНИЕ ХОСТОВ`, `FIREWALL`, `SIEM`, `EDR`, `PATCHES`, `VPN`, `WEB SCAN`, `PKI`, `AI SOC`, `THREAT MONITOR`, `AUTONOMOUS TASK`, `SETTINGS` (панель + i18n).
- Бейджи статуса: `LIVE` / `SIM` / `WIP` — **честные**: SIM-элементы помечены и не выдают себя за рабочие.

### 7.2 Паттерны взаимодействия
- **Invoke-паттерн**: кнопка → `inv('cmd', args)` → вывод в `#*-out` / `#*-stat`; ошибка → текст ошибки в тот же блок + цвет `var(--wip)`.
- **HITL**: предложения ИИ — карточки в `#chat` с APPROVE/REJECT → `task_approve`.
- **Уведомления вне окна**: `notify` при pending-предложениях, при остановке задачи; трей-статус — `set_agent_status`/`set_tray_alert`.
- **confirm-gate**: потенциально необратимые действия (отправка tx, deploy патчей, apply nft) — `confirm()` в UI и отдельная подтверждающая команда в Rust.

### 7.3 Порядок скриптов (критично)
`index.html` inline → `ai-provider.js` → `voice.js` → `emergency.js` → `net.js` → `fw.js` → `edr.js` → `ops.js` → `bridge-config.js` → `bridge.js` → `sysops.js` → `threats.js` → (Tauri-bridge inline) → **`agi.js` → `wallet.js` → `pqc.js`**.
Правила: глобалы инлайн-скрипта (`$`, `store`, `hist`, `task`, `say`, `p`, `fd`, `audit`) — **не переобъявлять** (глобальная лексическая область); переопределяемые функции (`askAGI`, `startTask`, `stopTask`) — через `window.x` (иначе hoisting-ловушка); native-only скрипты выходят при отсутствии `window.__TAURI__` (браузерный режим не ломается).

---

## 8. Нереализованный функционал / backlog (этапы 22–26 и далее)

### Этап 22 — DIGITAL ID: персистентность
- `did_create` (ECDSA P-256 → ключ в зашифрованный keyring), `did_list`, `did_sign_challenge`, `did_verify`; UI `idgen/idsign/idv/idsig` → inv; снять плашку «DID: WIP»; idv = `did:w420:…`.

### Этап 23 — AGI-Ω FM: настоящий эфир
- `radio_script(topic, mood)` через `agi_chat`; озвучка — `voice_say` (TTS-сервер); `radio_episode_build` — выпуск из реального audit-лога + AI-обводка; расписание; снять плашку «запасные реплики: SIM».

### Этап 24 — MIND MAP AGI-GEN
- `map_generate(prompt)` → `agi_chat` → строгий JSON `{nodes,edges}` → валидация схемы → запись в `w420.map`; кнопка «СГЕНЕРИРОВАТЬ ИИ»; снять «AGI-GEN: SIM».

### Этап 25 — HUD mesh/agi
- `h-mesh` → `bridge_status` (реальные узлы/порт) или удалить карточку; `h-agi` — реальная метрика нагрузки AI (model_stats, tok/s).

### Этап 26 — Зачистка и финал
- Dead-команды аудита: `security_ai_*` (7 обёрток) — подключить к UI или удалить; `config_parse_*` — сверить с `bridge-config.js`; 13 имён плана, переименованных в коде — синхронизировать `EVOLUTION_PLAN.md`; `edr_agents_list` — реализовать или убрать.
- Финальный аудит по методике `ui-audit-report.md`: 0 SIM без плашки; пересборка `.deb/.rpm/ISO`; итоговый отчёт.

### Прочее (известные SIM/декорации)
- `tmint`, `mkt`, `led`, `wsend`-legacy — минт/биржа/леджер: отдельная подсистема (не в скоупе кошелька).
- `h-agi` «сознание», `h-mesh` — заменить на реальные метрики (Этап 25) или удалить.
- ISO live-проверка загрузки (нет VM/дисплея на dev-хосте) — критерий приёмки на целевой машине.

---

## 9. Хранилища данных

| Путь | Содержимое | Режим |
|---|---|---|
| `~/.w420/wallet/keyring.json` | PQC-кошельки: адрес, label, salt/nonce/ct | 0600 |
| `~/.w420/ai_providers.db` | провайдеры, ключи (AES-GCM), статистика | — |
| `~/.w420/pki/` | CA, сертификаты, CRL | — |
| `~/.w420/siem.db` | события, правила, инциденты | — |
| `~/.w420/bridge/` | конфиги sing-box | — |
| `~/.w420/threats/`, `~/.w420/edr/` | CVE-база, baselines | — |
| `/opt/w420/` | установленная копия: dist/, sidecars | — |

---

## 10. Нефункциональные требования
- **Отклик UI**: invoke ≤ 3 c для лёгких команд; долгие (скан/деплой) — асинхронно с прогрессом в статус-строку.
- **Логи**: без секретов и паролей; аудит-цепочка применима к действиям агента.
- **Тесты**: unit на чистых функциях (парсинг, конверты, крипто-векторы); `#[ignore]` live-тесты для сети/AI; порог приёмки — 100% зелёных unit + build exit 0.
- **Совместимость**: Ubuntu 24.04+ (deb), Fedora/RHEL (rpm), ISO-autoinstall (preseed + nocloud + LUKS).
- **i18n**: RU (базовый), EN/ES (панель настроек).

---

## 11. Сборка, упаковка, доставка
1. `cargo build --release` → бинарник; `cargo test --workspace` — все зелёные.
2. `.deb`: staging → `/opt/w420` (dist, sidecars, скрипты); нет вложенных `dist/dist`; размер ~11 МБ.
3. `.rpm`: спек-эквивалент; проверка `rpm -qlp`.
4. ISO: свежий `.deb` + preseed + nocloud-autoinstall с LUKS; проверка `isoinfo`/bootability.
5. Обновление: `w420-update.sh` (версия, откат).
6. Root-настройка (`root_setup.sh`, `luks_setup.sh`) — запускается **пользователем** от своего имени; приложение sudo-пароль не принимает.

---

## 12. Правила разработки (сохранить как есть)
- Комментарии и код-док — по-русски, подробно; имена команд/модулей — `snake_case`, UI-id — kebab/snake как в §7.
- Ключи/мнемоники/токены — никогда во фронтенд, git, логи, отчёты.
- Тонкий клиент: любая новая логика — в Rust; HTML/CSS не меняется (кроме панели настроек и i18n).
- `sing-box` — остаётся Go-sidecar'ом; управление — из Rust.
- Каждый этап: Rust-модуль → `generate_handler!` → UI-wiring → `cargo test --workspace` → `cargo build --release` → `node --check` + баланс HTML → live-тест где применимо → DONE в плане → md-отчёт в канал доставки → финальная пересборка пакетов.
- Этапные отчёты — md-файлы, доставка в операционный канал (`MEDIA` в Telegram-топик).

---

## 13. Верификация (критерии приёмки каждой поставки)
1. **Wiring**: число `#[tauri::command]` = числу в `generate_handler!`; все `inv('cmd')` из dist резолвятся в зарегистрированные команды (0 неразрешённых).
2. **Тесты**: целевой счёт растёт монотонно; на момент ТЗ — 140 passed / 0 failed / 7 ignored (live-игноры: NVIDIA/voice/kernel).
3. **Сборка**: `cargo build --release` exit 0; `node --check` всех JS; баланс `<div>` = 0; все id из JS есть в HTML.
4. **Крипто-векторы**: кошелёк (Hardhat), PQC roundtrip, AI-маска `…abcd`.
5. **Безопасность**: 0 секретов в diff/логах; keyring-файлы 0600.

---

## 14. Тест-план (минимум)
- Unit: парсинг (subs/links/CIDR), конверты PQC, eth/gwei→wei, legacy-подпись (детерминизм), seal/open (roundtrip + негативы), parse_task_reply, whitelist.
- Интеграционные (ignored live): NVIDIA chat, voice health, wallet balance (Sepolia RPC), nft apply на тестовом правиле.
- UI: `node --check` всех скриптов; баланс тегов; наличие всех id.

---

## 15. Поставка и артефакты
- Исходники: git-репозиторий (origin + форк), пуш ребейзом.
- Пакеты: `packaging/w420_<ver>_amd64.deb` (~11 МБ), `.rpm`, `w420-os-<date>.iso` (~2.8 ГБ).
- Отчёты: `phase<N>-*-report.md`, `EVOLUTION_PLAN.md` (статусы DONE), `ui-audit-report.md`, `audit-*-report.md`.
- Документация: `TECHNICAL_DOCS.md`, `SYSADMIN_GUIDE.md`, `FINAL_REPORT.md`.

---

## 16. Чек-лист паритета (40 пунктов)
Ядро: метрики ОС · трей/уведомления · TTS/STT из коробки · настройки+i18n · monospace-терминал с командами (help/status/hash/whoami/vault/wallet/agi/clear).
Сеть/безопасность: nftables профили+rules+isolate · emergency-режим · hosts SSH-инвентарь · net scan + diff · SIEM (rules, incidents, dashboard) · IDS (suricata eve) · EDR (watch, baseline, respond) · web scan + AI-отчёт · Threat monitor (CVE) · hardening plan/apply/revert · FIM/trivy/gitleaks · patch mgmt (plan/rollback).
VPN/PKI/кошелёк: bridge (vless/vmess/wg/ovpn → sing-box sidecar) · tor (arti) · VPN WG server · PKI CA/issue/revoke/CRL/renew · кошелёк HD+keyring+sign+balance+send(testnet).
ИИ: провайдеры+ротация+маски+NVIDIA-модели · AI SOC (playbooks, forecast) · AGI чат+инструменты whitelist · автономные задачи HITL · Security-AI (анализ/реакции).
Крипто-оболочка: vault AES-GCM · PQC ML-KEM hybrid · DID (по Этапу 22) · mind map · радио (по Этапу 23) · audit hash-chain.
Платформа: deb/rpm/ISO+LUKS · root_setup/luks_setup от пользователя · wiring-аудит · монотонный рост тестов · отчёты в канал · честные бейджи LIVE/SIM/WIP.

---

**Конец ТЗ. Приёмка: все пункты §16 закрыты, §13 verification зелёный, backlog §8 имеет владельцев и даты.**

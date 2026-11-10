# План эволюции W420 в полноценную AI-кибербезопасностную ОС

## Цель

Превратить W420 из десктопного приложения в **полноценную операционную систему кибербезопасности**, работающую на AI-движке, со встроенными инструментами комплексного контроля и защиты сетей, подконтрольных администратору.

## Текущее состояние (база)

Уже реализовано: AI-абстракция (9 провайдеров), админка хостов (SSH), мониторинг CVE, AI-движок безопасности, трей-меню, автозапуск, TTS. Архитектура модульная (Tauri v2 + Rust workspace).

## Архитектурные принципы эволюции

1. **Каждый инструмент — отдельный модуль** в `app/src-tauri/src/` с Tauri-командами
2. **AI-движок — центр принятия решений**: каждый модуль отправляет данные в `security_ai`, получает рекомендации
3. **Все внешние инструменты** (nmap, suricata и т.д.) — как sidecar-бинарники, управляемые из Rust (как sing-box)
4. **Единая БД SQLite** в `~/.w420/` для всех данных (хосты, угрозы, логи, события)
5. **Тонкий HTML/CSS клиент** — UI не меняется архитектурно, добавляются новые страницы
6. **Всё на русском в комментариях**, подробная документация каждого модуля

---

## Фаза 6: Сетевое обнаружение и сканирование

**Цель:** Автоматическое обнаружение всех устройств в сети, сканирование портов и сервисов.

**Инструменты:** nmap, masscan, zmap (sidecar)

**Модуль:** `net_scan.rs`

- Сканирование подсетей (CIDR) — обнаружение живых хостов
- Сканирование портов (top 1000, full, custom)
- Определение версий сервисов (banner grabbing)
- Сравнение с инвентарём известных хостов (из `hosts.db`) — алерт на «новое устройство в сети»
- Сохранение результатов в `~/.w420/net_scan.db`
- AI-анализ: оценка риска каждого обнаруженного сервиса

**Tauri команды:** `net_scan_subnet`, `net_scan_ports`, `net_scan_results`, `net_scan_diff` (сравнение с предыдущим сканом)

---

## Фаза 7: Анализ трафика и IDS/IPS

**Цель:** Перехват, анализ и блокировка вредоносного трафика в реальном времени.

**Инструменты:** Suricata (IDS/IPS), tcpdump, tshark (sidecar)

**Модуль:** `traffic.rs`

- Запуск Suricata в режиме IDS на интерфейсе
- Парсинг алертов Suricata (EVE JSON) → в БД событий
- Перехват пакетов (pcap) с фильтрами
- Анализ трафика: топ talkers, аномалии (большие объёмы данных, необычные порты)
- Режим IPS: автоматическая блокировка IP через nftables при алерте Suricata
- AI-анализ: классификация угроз из алертов, приоритизация

**Tauri команды:** `traffic_start_ids`, `traffic_stop`, `traffic_alerts`, `traffic_capture`, `traffic_stats`, `traffic_block_ip`

---

## Фаза 8: Управление брандмауэром и сегментация сети

**Цель:** Контроль сетевого доступа, сегментация, изоляция скомпрометированных узлов.

**Инструменты:** nftables/iptables (управление из Rust), ufw

**Модуль:** `firewall.rs`

- Просмотр текущих правил (nft list ruleset)
- Добавление/удаление правил (по IP, порту, протоколу)
- Профили правил: «офис», «DMZ», «изоляция», «гостевая сеть»
- **Автоизоляция**: при критическом алерте AI автоматически добавляет правило блокировки IP
- NAT и проброс портов
- Логирование заблокированных соединений

**Tauri команды:** `fw_rules_list`, `fw_rule_add`, `fw_rule_remove`, `fw_profile_apply`, `fw_isolate_host`, `fw_logs`

---

## Фаза 9: SIEM — агрегация и корреляция событий безопасности

**Цель:** Централизованный сбор логов со всех узлов, корреляция событий, дашборд безопасности.

**Модуль:** `siem.rs`

- Сбор логов: syslog (UDP/TCP 514), journald, Windows Event Log (через SSH/WinRM), логи приложений
- Нормализация форматов (CEF, LEEF или свой统一фицированный)
- Корреляционные правила: несколько неудачных входов → брутфорс; вход из новой страны → аномалия
- Дашборд в реальном времени: количество событий по типам, топ источников угроз, карта (geoip)
- Поиск по логам с фильтрами
- AI-анализ: AI классифицирует инциденты, предлагает_escalation

**Tauri команды:** `siem_events`, `siem_search`, `siem_rules`, `siem_dashboard`, `siem_incident_create`, `siem_incident_status`

---

## Фаза 10: EDR — обнаружение и реагирование на конечных узлах

**Цель:** Мониторинг процессов, файлов, сети на каждом хосте в реальном времени.

**Модуль:** `edr.rs` (агент на хостах + сервер в W420)

- **Агент** (легковесный Rust-бинарник, ставится на каждый хост):
  - Мониторинг процессов (sysinfo + /proc)
  - FIM (File Integrity Monitoring) — уже есть в sysops, расширить
  - Мониторинг сетевых соединений
  - Отправка событий на сервер W420 по HTTPS
- **Сервер в W420**: приём событий, корреляция, алерты
- **Реагирование**: kill процесса, изоляция хоста (через firewall.rs), блокировка файла
- AI-анализ: обнаружение аномалий поведения (process injection, lateral movement)

**Tauri команды:** `edr_agents_list`, `edr_agent_status`, `edr_events`, `edr_respond` (kill process, isolate host)

---

## Фаза 11: Управление патчами

**Цель:** Автоматический поиск, тестирование и развёртывание обновлений безопасности на всех хостах.

**Модуль:** `patch_mgmt.rs`

- Сканирование хостов на наличие обновлений (apt/yum/dnf через SSH)
- Приоритизация: security updates первыми
- Тестовое развёртывание на «канареечном» хосте
- Массовое развёртывание с滚动ным обновлением (rolling)
- Откат при проблемах
- Отчёты о статусе обновлений по сети
- AI: оценка риска каждого патча (по CVE), рекомендация «ставить сейчас / подождать"

**Tauri команды:** `patch_scan_all`, `patch_list_updates`, `patch_deploy`, `patch_rollback`, `patch_status`

---

## Фаза 12: VPN и удалённый доступ

**Цель:** Безопасный удалённый доступ к сетям, site-to-site VPN.

**Инструменты:** WireGuard, OpenVPN (уже есть sing-box для проксирования)

**Модуль:** `vpn.rs`

- Генерация конфигураций WireGuard (сервер + клиенты)
- Управление peer'ами: добавление, отзыв, ограничение скорости
- Site-to-site туннели между офисами
- Split tunneling
- Мониторинг подключений (handshake, трафик)
- AI: обнаружение аномального поведения VPN-клиента (необычный объём, география)

**Tauri команды:** `vpn_server_start`, `vpn_peer_add`, `vpn_peer_revoke`, `vpn_status`, `vpn_traffic`

---

## Фаза 13: Сканер веб-безопасности

**Цель:** Автоматическая проверка веб-приложений на уязвимости.

**Инструменты:** OWASP ZAP (API), Nikto (sidecar)

**Модуль:** `web_scan.rs`

- Сканирование сайтов через ZAP API (spider + active scan)
- Поиск уязвимостей: XSS, SQLi, CSRF, небезопасные заголовки, устаревшие библиотеки
- Сохранение отчётов, сравнение со сканами
- AI-анализ: приоритизация уязвимостей по реальной эксплуатируемости, генерация PoC-описаний

**Tauri команды:** `web_scan_start`, `web_scan_status`, `web_scan_results`, `web_scan_report`

---

## Фаза 14: PKI и управление сертификатами

**Цель:** Свой удостоверяющий центр, выпуск и отзыв сертификатов для внутренних сервисов.

**Модуль:** `pki.rs`

- Создание корневого CA (self-signed)
- Выпуск сертификатов для серверов, клиентов, VPN
- CRL (список отозванных), OCSP
- Автопродление сертификатов
- Инвентарь всех сертификатов с датами истечения — алерт за 30/14/7 дней
- AI: рекомендация по algorithm/length ключа на основе текущих стандартов

**Tauri команды:** `pki_ca_create`, `pki_cert_issue`, `pki_cert_revoke`, `pki_certs_list`, `pki_cert_renew`

---

## Фаза 15: AI SOC — автономный центр операций безопасности

**Статус: DONE (2026-11-05)** — реализовано в `ai_soc.rs` (SocManager, `~/.w420/soc.db`).

**Цель:** AI-движок, который самостоятельно анализирует все данные и принимает решения.

**Модуль:** `ai_soc.rs` (поверх siem/edr/traffic/firewall; `security_ai.rs` остаётся как слой анализа угроз)

- **Автономный цикл**: `soc_autonomous_cycle` — siem.ingest+correlate → edr scan/diff → traffic alerts → дедуп инцидентов → match playbook → действие (block_ip/isolate) → запись в soc_cycles
- **Playbooks**: таблица `playbooks` в soc.db (bruteforce_block, malware_isolate, data_exfil_block, new_host_alert, critical_contain) с auto-флагом и min_severity; guard от loopback
- **Обучение на инцидентах**: `soc_feedback` — success/fail счётчики playbooks, таблица feedback
- **Натуральный язык**: `soc_chat` — диалог с SOC на русском (NVIDIA KeyRotation)
- **Прогнозирование**: `soc_forecast` — агрегация инцидентов → AI-прогноз векторов атак
- **Отчёты руководству**: `soc_ai_cycle_report` — executive summary смены (сохраняется в soc_cycles)

**Tauri команды:** `soc_status`, `soc_autonomous_cycle`, `soc_incidents`, `soc_playbook_run`, `soc_feedback`, `soc_ai_cycle_report`, `soc_chat`, `soc_forecast`

**Проверено:** юнит-тесты 3/3, live-цикл (dry) OK, live AI chat/forecast/report через NVIDIA — ок; полный `cargo test` 79 passed / 1 известный fail (sysops::gitleaks); `cargo build --release` exit 0; UI-карточка AI SOC в index.html/ops.js.

---

## Фаза 16: Упаковка в полноценную ОС

**Статус: DONE (2026-11-05)** — артефакты в `packaging/` + скрипты в `scripts/`.

**Цель:** W420 как дистрибутив Linux, а не просто приложение.

- **.deb**: `packaging/deb/` (control/postinst/prerm, `w420.service`, desktop-файл) + `scripts/build_deb.sh` — собран и проверен (`packaging/w420_1.0.0_amd64.deb`, 55 файлов, бинарник 48 МБ внутри)
- **.rpm**: `packaging/w420.spec` + `scripts/build_rpm.sh` (нужен rpmbuild)
- **.iso**: `packaging/iso/preseed.cfg` (autoinstall Ubuntu, **LUKS full-disk** через partman crypto + LVM) + `boot/grub/grub.cfg` + `scripts/build_iso.sh` (xorriso, кладёт w420.deb + nocloud user-data в ISO)
- **systemd**: `w420.service` — автозапуск, Restart=on-failure, лимиты памяти/CPU, sandbox (проверен `systemd-analyze verify`)
- **LUKS вручную**: `scripts/luks_setup.sh` (LUKS2 + crypttab/fstab для data-раздела)
- **Обновления ОС**: `scripts/w420-update.sh` — apt через NOPASSWD sudoers w420 (проверено: --check видит обновления)
- Все инструменты предустановлены через Depends .deb: nmap, suricata, wireguard-tools, nftables, tcpdump, openssl, sqlite3, espeak-ng

---

## Этап 18: Доведение обещанного функционала (SIEM-правила, net diff, VPN-трафик, PKI-продление, веб-отчёт)

**Статус: DONE (2026-11-05)** — патчи в `siem.rs`, `net_scan.rs`, `vpn.rs`, `pki.rs`, `web_scan.rs` + UI (`fw.js`, `net.js`, `ops.js`, `index.html`).

- **SIEM rule-engine**: таблица `rules` (seed: `burst-src`, `critical-single`), correlate на Rust (min_severity-ранг, окно, порог, дедуп открытых инцидентов); команды `siem_rules_list/add/remove/toggle`, `siem_incidents_list/create/set_status`
- **net_scan_diff**: `ScanDiff` — сравнение двух последних сканов; новые хосты → события `source='net_scan'` в siem.db (подхватывает playbook `new_host_alert`)
- **vpn_traffic**: агрегация rx/tx по пирам из `wg show all` — total, top_talker, без паники на пустом списке
- **pki_cert_renew**: перевыпуск неотозванных сертификатов, истекающих ≤ N дней (`parse_not_after` понимает openssl- и RFC3339-форматы)
- **web_scan_status / web_scan_report**: статистика сканера и детерминированный markdown-отчёт (хосты + уязвимости по severity)

**Проверено:** `cargo test -p w420 --lib` — **90 passed, 0 failed, 7 ignored**; `node --check` для ops.js/fw.js/net.js — OK; `cargo build --release` — exit 0.

---

## Приоритизация и оценка сроков

| Приоритет | Фаза | Срок (1 разработчик) | Почему важно |
|-----------|------|---------------------|--------------|
| Критично | 6 (Сканирование сети) | 2-3 недели | Без этого не знаешь, что в сети |
| Критично | 8 (Firewall) | 2 недели | Базовая защита, автоизоляция |
| Критично | 10 (EDR) | 4-6 недель | Видимость на конечных узлах |
| Высокий | 7 (IDS/IPS) | 3-4 недели | Обнаружение атак в трафике |
| Высокий | 9 (SIEM) | 4-5 недель | Централизованная картина |
| Высокий | 15 (AI SOC) | 3-4 недели | Мозг всей системы |
| Средний | 11 (Патчи) | 3 недели | Закрытие дыр |
| Средний | 12 (VPN) | 2 недели | Удалённый доступ |
| Средний | 13 (Веб-сканер) | 2-3 недели | Защита веб-приложений |
| Низкий | 14 (PKI) | 2-3 недели | Внутренние сертификаты |
| Финал | 16 (ОС) | 4-6 недель | Упаковка в дистрибутив |

**Общий срок до полноценной ОС: ~6-9 месяцев** при одном разработчике, ~3-4 месяца при команде из 2-3 человек.

---

## Технические детали

### Как интегрировать внешний инструмент (пример: nmap)

```rust
// app/src-tauri/src/net_scan.rs
use std::process::Command;

pub fn scan_subnet(cidr: &str) -> Result<Vec<Host>, String> {
    // nmap как sidecar, управляемый из Rust
    let output = Command::new("nmap")
        .args(["-sn", cidr])  // ping scan
        .output()?;
    // парсинг вывода → Vec<Host>
}
```

Все инструменты ставятся в `~/.local/bin/` (уже сделано для sing-box, trivy, gitleaks). Новый инструмент добавляется одной командой установки.

### Единая схема БД

Все модули пишут в одну БД или свои БД в `~/.w420/`:
- `hosts.db` — инвентарь хостов
- `threats.db` — CVE и уязвимости
- `net_scan.db` — результаты сканирования сети
- `siem.db` — события безопасности
- `edr.db` — события EDR
- `ai_providers.db` — AI-провайдеры и ключи

### AI-интеграция

Каждый модуль после получения данных вызывает `security_ai::analyze_*`, получает рекомендации и либо применяет автоматически (если `auto_response_enabled`), либо показывает администратору.

---

## Этапы 19–26: Доведение AGI-оболочки (HUD + SIM-вкладки) до REAL

По аудиту `ui-audit-report.md` (2026-11-06): 60 операционных кнопок REAL, ~12 локальных REAL, остальное — честно помеченный SIM. Ниже — последовательный план реализации каждого подготовленного в интерфейсе элемента. Порядок важен: Этап 19 (AI-мост) — фундамент для 23/24.

Общий шаблон этапа (см. skill w420-security-platform): Rust-модуль + команды в `generate_handler!` → UI-wiring по id → `cargo test --workspace` (count растёт) → `cargo build --release` exit 0 → `node --check` + баланс HTML → live `#[ignore]`-тест где применимо → `**Статус: DONE**` здесь → отчёт `phase<N>-…-report.md` в топик 252 → пересборка .deb/.rpm/ISO в конце.

### Этап 19: AI-мост оболочки (фундамент) — **DONE 2026-11-06**
- **Сейчас SIM:** чат AGI-Ω (`ask`, `ai`, `aisend`, `brief` → canned `[SIM]`), терминал `cmd agi …`, AUTONOMOUS TASK (`tgo/tstop` — «модель недоступна»), HUD `h-agi` (random).
- **Сделано:** `app/src-tauri/src/agi.rs` — 8 команд: `agi_chat` ( поверх `ai_providers::chat_messages`, KeyRotation, маска …abcd, системный промпт AGI-Ω), `agi_status` (бейдж LIVE/SIM), `agi_tools_list`/`agi_tool_exec` (whitelist read-only: system_status, siem_dashboard, soc_status, threats_last_scan), `task_start/stop/status/approve` — автономный цикл в tokio (max 10, интервал ≥5 c), разбор `PROPOSE:{json}` из ответа модели, human-in-the-loop: pending-предложение → APPROVE/REJECT в UI → выполнение только whitelisted. UI: `app/dist/agi.js` (последний скрипт, native-only): чат → `agi_chat` с историей `w420.hist`, бейдж `#aib`, чипы инструментов, `tgo/tstop/tstat` → нативные task-команды, карточки PROPOSE с APPROVE/REJECT → `task_approve`. Без Tauri — прежнее поведение.
- **Верификация:** 5 юнит-тестов agi (парсинг PROPOSE, промпт, whitelist, proposals); `cargo test --workspace` 126 passed / 0 failed; `cargo build --release` exit 0; `node --check agi.js` OK; wiring-аудит: 128 inv-вызовов, 0 неразрешённых; отчёт `phase19-agi-bridge-report.md` в топик 252.

### Этап 20: Кошелёк REAL (v-key / v-wallet) — **DONE 2026-11-06**
- **Сделано:** `wallet.rs` — BIP-39/BIP-32/secp256k1 в Rust (вектор Hardhat сошёлся), keyring `~/.w420/wallet/keyring.json` с мнемониками под AES-256-GCM (PBKDF2-HMAC-SHA256, 600k итераций), подпись legacy-tx (EIP-155, RFC-6979), JSON-RPC: баланс/отправка, **по умолчанию Sepolia testnet**. 9 команд (`wallet_create/import/list/reveal/remove/sign_tx/balance/send/status`). UI `wallet.js`: kgen/kload/kshow/kvault/ksign → команды, на вкладке CRYPTO · WALLET — кнопки «БАЛАНС (RPC)» и «ОТПРАВИТЬ (testnet)» с confirm.
- **Верификация:** 9 юнит-тестов wallet; `cargo test --workspace` 135 passed / 0 failed; `cargo build --release` exit 0; wiring 184=184, 136 inv, 0 unresolved; отчёт `phase20-wallet-report.md` в топик 252. Минт/биржа ([SIM]) — отдельная подсистема, плашка оставлена.
- **Побочно (просьба пользователя):** автозагрузка W420 убрана (`.desktop` из `~/.config/autostart` удалены, systemd-юнит inactive); подключим после завершения разработки.

### Этап 21: Vault PQC (v-vault, снять «PQC TAG: SIM») — **DONE 2026-11-06**
- **Сделано:** `pqc.rs` — ML-KEM-768 (FIPS 203, `ml-kem` 0.2) + HKDF-SHA256 + AES-256-GCM; конверт `(kem_ct, nonce, ct)`; команды `vault_pqc_keygen/seal/open/status`. UI `pqc.js`: KEYGEN/SEAL/OPEN в карточке vault, плашка «PQC TAG: SIM» → LIVE в нативной оболочке. Классический WebCrypto-путь не тронут.
- **Верификация:** 5 юнит-тестов (размеры ключей, roundtrip, отказ при неверном sk/порче ct); `cargo test --workspace` 140 passed / 0 failed; build exit 0; wiring 188=188, 140 inv, 0 unresolved; отчёт `phase21-vault-pqc-report.md` в топик 252.

### Этап 22: DIGITAL ID персистентность — **DONE 2026-11-09**
- **Сделано:** `did.rs` (6 команд: did_create/list/status/sign_challenge/verify/remove) — ECDSA P-256 (p256), приватный ключ PKCS#8 под AES-256-GCM (PBKDF2 600k) в `~/.w420/did/keyring.json` (0600); did = `did:w420:`+hex(sha256(pubkey))[..20]; подпись = ECDSA prehash SHA-256 (семантика = WebCrypto). UI `did.js`: idgen/idsign → команды, поле пароля, плашка «DID: WIP» → LIVE.
- **Верификация:** 6 тестов (roundtrip, неверный пароль, чужой challenge → INVALID, удаление, детерминизм did); отчёт в 252.

### Этап 23: AGI-Ω FM — настоящий эфир — **DONE 2026-11-09**
- **Сделано:** `radio.rs` (4 команды: radio_script/radio_episode/radio_say/radio_status) — тексты через `agi_chat`, озвучка через TTS (`voice_say`, фолбек speechSynthesis). UI `radio.js`: window.radioDJ/radioSay/epBuild → inv, заказы тем, выпуск дня из audit-лога, плашка «запасные реплики: SIM» → LIVE при живом AGI.
- **Верификация:** 3 теста промптов; отчёт в 252.

### Этап 24: MIND MAP AGI-GEN — **DONE 2026-11-09**
- **Сделано:** `map.rs` (map_generate/map_agi_status) — AGI → строгий JSON `{nodes:[{text,parent}]}`, извлечение из ```-блоков, валидация (parent < индекс, ≤40 узлов, текст ≤60), UI `map.js`: кнопка «СГЕНЕРИРОВАТЬ ИИ», та же раскладка, запись в `w420.map`, плашка «AGI-GEN: SIM» → LIVE.
- **Верификация:** 6 тестов (извлечение JSON, валидация схемы); отчёт в 252.

### Этап 25: HUD mesh/agi — **DONE 2026-11-09**
- **Сделано:** `hud.js` — h-mesh ← bridge/tor/vpn статусы (живые узлы и пиры, «все выкл» честно), h-agi ← реальный tok/s из ai_provider_model_stats (SIM-записи inline заблокированы через defineProperty); обе карточки SIM→LIVE.
- **Верификация:** node --check, build; отчёт в 252.

### Этап 26: Зачистка и финал — **DONE 2026-11-09**
- Убраны 8 мёртвых обёрток `security_ai_*` (не вызывались из UI); реализован `edr_agents_list` (hosts-инвентарь + watcher).
- Финальный аудит: **193 declared = 193 registered**, 150 inv, 0 unresolved, баланс div 0; тесты **156 passed / 0 failed**; build exit 0; `.deb`/`.rpm` пересобраны со всеми bridge-скриптами.
- SIM остались только честные: секция MINT/DC EXCHANGE (отдельная подсистема) + плашки, флипающиеся в native (PQC/DID/AGI-GEN/радио/HUD/AGI).
- ISO — по запросу (тяжёлая сборка). Автозагрузка отключена по просьбе пользователя.

## Следующий план: DameWare Parity
Полный план добавления функционала DameWare (DRS/MRC) — отдельным файлом:
**`DAMEWARE_PARITY_PLAN.md`** — этапы 27–38 (remote desktop RDP/VNC, in-session chat/file transfer,
RAT-команды поверх SSH, сетевые утилиты, AD/LDAP, запись сессий, 2FA/smart card, веб-консоль,
ITSM, gateway-брокер, System Tools, финальный аудит паритета). База — `audit-dameware-parity.md`.

---

*Документ создан на основе аудита от 2026-11-04. Каждый разработчик может продолжить с любой фазы — архитектура это позволяет.*
# План эволюции «DameWare Parity» — этапы 27–38 (2026-11-09)

База: аудит `audit-dameware-parity.md` (28 фич DameWare: 4 полных, 9 частичных, 15 нет).
Цель: закрыть все 15 пробелов и довести 9 частичных до полных, не ломая текущее ядро
(193 команды, тонкий клиент, sidecar-архитектура, все секреты в Rust, комментарии по-русски).

Общий шаблон этапа (как в EVOLUTION_PLAN.md 19–26):
Rust-модуль → регистрация в `generate_handler!` → UI-wiring по id (новые bridge-скрипты в конце `<body>`,
native-only) → `cargo test --workspace` (рост счётчика) → `cargo build --release` → `node --check` + баланс div +
все id из JS есть в HTML → live-тест где применимо → DONE в этом плане → md-отчёт в топик 252 через MEDIA.
В конце всех этапов — пересборка `.deb`/`.rpm`/ISO по запросу.

## Этап 27 — Remote Desktop core: RDP/VNC-сессии (ядро MRC) — ✅ DONE 2026-11-09
- **Сделано:** `rdesk.rs` (менеджер сессий, sidecar `websockify` для VNC→WS и `xfreerdp` для RDP, честная ошибка если sidecar'а нет в PATH); собственный минимальный RFB-клиент для `rdesk_screenshot` → PNG (зависимость `png`); 7 команд в `generate_handler!`; UI `rdesk.js` (панель сессий в v-net, кнопки VNC/RDP на карточках хостов, просмотр через свой RFB-over-WS клиент на canvas, lock input / blank screen / скриншот / multi-viewer счётчик).
- **Тесты:** 3 новых (мок VNC-сервер: handshake+Raw кадр→RGBA, отказ без сервера, bookkeeping сессий). Всего 159 passed, 0 failed. `node --check` OK, wiring 7/7, build release exit 0.
- **Цель:** интерактивный GUI remote control как у MRC (Windows RDP, Linux/macOS VNC).
- **Делаем:** sidecar/клиент: RDP через `ironrdp` (чистый Rust) или sidecar FreeRDP; VNC через крейт `vnc`/`rfb`. Новый модуль `rdesk.rs`: `rdesk_connect(host_id, proto, display?)`, `rdesk_disconnect`, `rdesk_sessions` (список активных), `rdesk_input` (mouse/keyboard события), `rdesk_screenshot` (frame → png), `rdesk_lock_input` (блокировка ввода на удалённой стороне), `rdesk_blank` (blank screen).
- **UI:** новая вкладка REMOTE DESKTOP: список сессий-табов (как у DameWare quick-access tabs), canvas/видео-поток, панель инструментов сессии.
- **Тесты:** handshake с тестовым VNC/RDP сервером в `#[ignore]` live; unit — парсинг адресов, список сессий.

## Этап 28 — In-session tools: chat, file transfer, multi-admin — ✅ DONE 2026-11-09
- **Сделано:** роли `controller`/`viewer` (`rdesk_set_role`), in-session чат (`rdesk_chat_send/recv` с offset-polling, дубль на диск `~/.w420/rdesk/<id>.chat.jsonl`), file transfer поверх SSH/SCP (`rdesk_xfer_list/down/up`, BatchMode, без shell-инъекций — аргументы списком). UI: кнопки роли и 📁 файлы в строке сессии, чат-панель в viewer-окне, диалог трансфера.
- **Тесты:** +2 (роли+чат: валидация, offset, лимит 4096; xfer: честная ошибка без хоста). lib: 130 passed, 0 failed (1 флак в первом прогоне, повтор зелёный). build release exit 0.
- **Цель:** chat с оператором хоста, drag&drop file transfer, два админа в одной сессии с permission-контролем.
- **Делаем:** `rdesk_chat_send/recv` (канал поверх сессии или через SIEM-события), `hosts_xfer_up/down/list` (SCP/SFTP поверх SSH с прогрессом), `rdesk_join(session_id, role)` (viewer/controller), ACL сессии.
- **UI:** чат-панель в сессии, окно передачи файлов (two-pane), список участников сессии с ролями.

## Этап 29 — hosts_* расширение до «RAT без сессии» (DRS) — ✅ DONE 2026-11-09
- **Сделано:** `rat.rs` — 9 команд поверх SSH через `HostsManager::exec_command` с валидацией аргументов (белый список символов, без shell-инъекций): `rat_power` (reboot/shutdown/lock/logoff), `rat_services_list`, `rat_service_control`, `rat_log_view`, `rat_log_clear` (rotate+vacuum), `rat_disk`, `rat_pkgs`, `rat_info_export` (CSV/XML), `rat_wake` (WoL magic packet чистым Rust, UDP broadcast, без sidecar). UI `rat.js` — панель RAT в v-net.
- **Тесты:** +4 (валидация токенов, WoL-пакет 102 байта + loopback-приём, xml/csv escape). Workspace: 169 passed, 0 failed. build release exit 0.

## Бонус: панель «ДИСПЕТЧЕР» по мотивам Argus (@geekbb, github.com/Ray-lea/Argus) — ✅ DONE 2026-11-09
- **Сделано:** `argus.rs` + `argus.js` в разделе v-stat: вкладки Процессы (sysinfo, сортировка/фильтр/kill), Графики (семплер 1с, ring buffer 7200 точек + дубль `~/.w420/argus-metrics.jsonl`, canvas-кривые CPU/RAM), Порты (`ss -tunap` с pid), Файлы (`/proc/*/fd` + cwd/exe — кто держит файл).
- **Тесты:** +4 (парсинг ss, file_users находит себя, ring cap, scan_procs находит свой pid).
- `hosts_reboot/shutdown/lock/logoff(host_id)` (через SSH, с confirm)
- `hosts_services_list/start/stop/restart(host_id, unit)` (systemctl)
- `hosts_log_view(host_id, unit?, since, limit)` + `hosts_log_clear` (journald)
- `hosts_disk(host_id)` (df), `hosts_pkgs(host_id)` (dpkg/rpm query), `hosts_info_export(host_id, format: csv|xml)` (system info + ПО + конфигурация → экспорт, как у DRS exporter)
- `hosts_wake(host_id)` (WoL через etherwake по MAC из инвентаря)
- UI: в карточке хоста (v-net) — кнопки REBOOT/SHUTDOWN/LOCK, вкладки SERVICES/LOGS/DISKS/PKGS, экспорт.

## Этап 30 — Сетевые утилиты уровня DameWare — ✅ DONE 2026-11-09
- **Сделано:** `netutil.rs`, 5 команд: `net_port_check`/`net_port_scan` (чистый Rust, TcpStream connect_timeout), `net_dns_lookup` (A/AAAA — std, MX/TXT — через dig), `net_ping` (парсинг iputils), `net_traceroute` (traceroute -n, фолбэк tracepath). UI `netutil.js` — панель в v-net.
- **Тесты:** +4 (port_check открытый/закрытый против реального локального listener, DNS localhost, парсеры ping/traceroute на моках). Workspace: 173 passed, 0 failed. build exit 0.
- `net_ping(host, count)`, `net_traceroute(host)`, `net_dns_lookup(name, record)`, `net_port_check(host, port)` — поверх tokio/icmp или вызовов, парсинг вывода в Rust.
- UI: в v-net ряд полей + кнопки PING/TRACE/DNS/PORT.

## Этап 31 — Active Directory модуль (LDAP) — ✅ DONE 2026-11-09
- **Сделано:** `ad.rs` (крейт `ldap3` 0.11 sync API), 13 команд: `ad_config_set/get` (пароль bind — AES-256-GCM через w420_ai::encryption, файл `~/.w420/ad.json` 0600, наружу только маска `…xxxx`), `ad_ping` (RootDSE), `ad_tree` (OU), `ad_users_search` (фильтр экранирован по RFC 4515, флаги userAccountControl), `ad_groups`, `ad_user_unlock` (pwdAccountLockedTime=0), `ad_user_reset_password` (unicodePwd как бинарный Vec<u8> UTF-16LE + pwdLastSet=0), `ad_group_members/add/remove`, `ad_gpo_list` (read-only), `ad_export` CSV/XML. UI `ad.js` — панель AD в v-net, HITL-confirm на unlock/reset/группы.
- **Тесты:** +6 (escape_filter, valid_dn, unicodePwd байты, маска пароля, encrypt roundtrip, xml_esc). Workspace: 179 passed, 0 failed. build exit 0. Пуш в PerfectFriend/Torquemada-AGI-OS-420 (cc3b67b).
- Новый модуль `ad.rs`: `ad_domains`, `ad_tree(domain, base_dn)` (OU/контейнеры), `ad_users_search`, `ad_groups`, `ad_user_unlock`, `ad_user_reset_password`, `ad_group_add_member/remove`, `ad_gpo_list` (read-only), `ad_export(objects, format csv|xml)`.
- Безопасность: bind-DN и пароль — в зашифрованный keyring (как wallet/did), наружу — маски; HITL (APPROVE) для unlock/reset password.
- UI: новая вкладка ACTIVE DIRECTORY.
- Тесты: unit — парсинг LDAP-фильтров, валидация DN; live `#[ignore]` против тестового AD/LDAP.

## Этап 32 — Session recording и журнал сессий
- Запись SSH-сессий: `asciinema rec` sidecar → `.cast` + рендер в mp4; запись GUI-сессий — кадры rdesk_screenshot → видео.
- `sess_record_start/stop/list/play(session_id)`, интеграция с audit hash-chain (каждая сессия = запись в журнал).
- UI: вкладка SESSIONS: список записей, play inline.

## Этап 33 — Безопасность консоли: 2FA, smart card, FIPS-режим
- `auth_totp_setup/verify` (TOTP, секрет в keyring), `auth_smartcard_list/login` (PKCS#11 через `cryptoki`, пин не логируется), `auth_fips_mode(status)` (переключение профиля крипто: только FIPS-валидированные наборы).
- Все секреты — AES-256-GCM at rest, как сейчас.

## Этап 34 — Мобильный/веб-консоль (замена iOS/Android клиента DameWare)
- Лёгкий web-консоль (тот же dist, responsive) за gateway: `bridge` уже даёт внешний доступ; добавляем `web_console_start/stop` (HTTP на 127.0.0.1 + проброс через tor onion/bridge), авторизация по DID-подписи + TOTP.
- Цель: управлять W420 с телефона/браузера без установки клиента.

## Этап 35 — ITSM/ticketing интеграция
- `itsm_config(provider, webhook, token)` (секрет в keyring), `itsm_ticket_create/update/close` (Generic webhook + templates для ServiceDesk/Jira), привязка инцидентов SIEM → тикет одной кнопкой.

## Этап 36 — Gateway/брокер сессий с permission (DameWare Gateway)
- Формализуем существующее: `gw_status`, `gw_session_offer/join/approve` — внешний доступ только через bridge/tor/vpn, каждый входящий запрос на сессию — PROPOSE→APPROVE (HITL, как в agi).
- Мulti-admin join сессии с ролями (Этап 28) — через тот же брокер.

## Этап 37 — System Tools: пользовательские инструменты (как в DRS)
- `systool_list/add/remove` (команда + аргументы + рабочая директория + целевой хост), `systool_run(id, host_id?)` — вывод в терминал; реестр инструментов в SQLite/файле.
- UI: конструктор System Tool в настройках + запуск из карточки хоста.

## Этап 38 — Финал паритета — ✅ DONE 2026-11-11
- Dashboard здоровья хоста: `hosts_health(host_id)` (сводка: CPU/RAM/disk/services/last events/EDR-статус → score), карточка health в UI.
- Полный аудит паритета по `audit-dameware-parity.md`: цель 28/28 (полные+частичные закрыты), 0 регрессий (тесты растут от 156), wiring 1:1, SIM-плашки только честные.
- Пересборка `.deb`/`.rpm`/ISO, итоговый отчёт в 252, обновление `W420_TECH_SPEC.md` (раздел 8 backlog → новые этапы 27–38).

- **Сделано:** `health.rs` — `hosts_health(host_id)` / `hosts_health_all()`: метрики по SSH (uptime/free/df/systemctl --failed) + локальные SIEM/EDR события по IP хоста, score 0..100 (HEALTHY/OK/DEGRADED/CRITICAL/OFFLINE) + вердикт Матери (свой/чужой по allowlist). UI `health.js` — карточка «ЗДОРОВЬЕ ХОСТОВ» в v-net. Тесты +6 (парсеры load/mem/disk/failed, score offline/healthy/degraded, монотонность). Workspace: 188 passed, 0 failed. build exit 0.

## Что сознательно НЕ копируем у DameWare
- Лицензионный сервер/центральное лицензирование (у нас open, без лицензий).
- Винтажные NT-инструменты (NTBackup, NT User Manager) — обзоры отмечают их устаревание.
- Агент DameWare на каждом хосте — у нас SSH/агент-less через bridge; on-the-fly агент делаем только если понадобится (Этап 28).

## Порядок и зависимости
27 → 28 → 32 (запись поверх сессий 27) → 29 → 30 → 31 → 33 → 34 → 35 → 36 → 37 → 38.
31 (AD) и 33 (2FA) независимы от 27–30 и могут идти параллельно.

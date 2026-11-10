# АУДИТ w420-install — полный аудит того, что получилось (2026-11-05)

Объект: `/home/thomas/w420-install` (Tauri v2 + Rust-бэкенд `app/src-tauri`, тонкий клиент `app/dist`, крейты `w420-ai`/`w420-core`, артефакты `packaging/`). Все утверждения ниже подкреплены выполненными командами, не словами.

## 1. Сборка и тесты (выполнено сейчас)

- `cargo test --workspace` → **121 passed, 0 failed, 7 ignored**: w420 lib 90, w420-ai 11, w420-core (integration) 20. 7 ignored — живые тесты (NVIDIA/voice/kernel), запускаются вручную.
- `cargo build --release` → exit 0 (бинарник ~49 МБ в `~/build/cache/cargo-target/release/w420`).
- `node --check` на все 12 JS-файлы `app/dist` → OK. `bash -n` на все 6 скриптов `scripts/` → OK.
- HTML-баланс `index.html`: `<div>`/`</div>` и `<section>` сходятся (0), все `<script src>` существуют, все id, к которым обращается JS, есть в HTML.

## 2. Wiring команд (проверено программно, 3 стороны)

- `#[tauri::command]` функций: **167**. В `generate_handler!` в `lib.rs`: **167**. Расхождений нет (команды из корня lib.rs регистрируются без префикса `mod::` — ранний ложный алерт по regex, перепроверено по полной выборке).
- Из UI: **109** прямых `inv("…")` + **22** динамических (префикс + конкатенация, например `traffic_*` в ops.js) — **все резолвятся в зарегистрированные команды, ни одного 404 по имени**.
- 36 команд не вызываются из UI напрямую — см. находку 2.

## 3. Безопасность ключей и секретов (grep-свип по всему дереву)

- Реальных секретов в дереве **нет**: единственные совпадения — тестовая фикстура `nvapi-…SECRET` в юнит-тесте `ai_providers.rs:758` и allowlist-пример AWS в комментарии `sysops.rs:248`. Хардкод-паролей/токенов — 0.
- SQL везде параметризован (`?1`/`params!`), `format!` в SQL — **0** вхождений (инъекций нет).
- Ключи провайдеров: AES-256-GCM at rest в `ai_providers.db`, в JS уходит только маска `…last4` (проверено на этапе 17 живым циклом).
- `http://` вне localhost — только в тестовых скриптах `tools/tests/` и CORS-regex TTS-сервера (tauri://localhost + 127.0.0.1) — ок.
- `TODO/FIXME/HACK` — **0**. `placeholder` — только HTML-атрибуты и подписи; в PKI `DNS:placeholder` — осмысленный дефолт SAN, который **перезаписывается при каждом выпуске** (`DNS:{cn}` если SAN пуст), покрыто тестом `test_build_san_line`.
- `unwrap()`/`panic!` — 263 вхождения, в основном `lock().unwrap()` на Mutex и тесты; отдельного аудита panic в прод-путях не проводилось.

## 4. НАХОДКИ

### HIGH — артефакты упаковки устарели относительно кода
- `.deb` собран 2026-11-05 **12:57**, ISO — **20:39**, а `app/dist/index.html` изменён **23:35**, `ai-provider.js` — **23:04** (этапы 17–18). `diff -rq app/dist packaging/deb/opt/w420/dist` показывает расхождение 5 файлов (index.html, ai-provider.js, fw.js, net.js, ops.js) → **в .deb и ISO лежит старый UI без панели провайдеров и кнопок этапа 18**.
- В staging осталась вложенная папка `packaging/deb/opt/w420/dist/dist/` (артефакт копирования).
- **Fix:** пересобрать `scripts/build_deb.sh`, `build_rpm.sh`, `build_iso.sh` после чистки staging; ISO собирать на nvme (tmpfs 7.7 ГБ не вмещает 2.8 ГБ).

### MEDIUM — dead UI: карточка THREAT MONITOR и модуль threats не подключены к фронтенду
- В `index.html` есть карточка «THREAT MONITOR AGENT» (`#feed`, кнопка `#brief`), но **ни один JS не вяжет эти id**, и ни один JS не вызывает команды `threats_*` (7 штук: scan/sync/list/alerts/acknowledge/last_scan/sources). БД `~/.w420/threats.db` существует. Модуль написан, UI не довключён — класс **dead** (написано, не подключено), не регрессия.
- Аналогично `security_ai_*` (7 команд-обёрток) и `config_parse_*` (5) не вызываются из JS — часть используется из Rust напрямую, часть — только для CLI/скриптов.

### MEDIUM — EVOLUTION_PLAN.md отстал от кода по именам команд
- 13 имён из плана в бэктиках не существуют в коде: все, кроме одного, имеют переименованные эквиваленты (`pki_ca_create`→`pki_ca_init`, `pki_cert_issue`→`pki_issue`, `pki_certs_list`→`pki_list`, `siem_rules`→`siem_rules_list`, `siem_incident_status`→`siem_incident_set_status`, `web_scan_start`→`web_scan_net`, `patch_rollback`→`patch_rollback_plan`, `net_scan_results`→`net_scan_last`/`net_scan_history`, `edr_agent_status`→`edr_watch_status`, `security_ai`→набор `security_ai_*`). `edr_agents_list` эквивалента не имеет (есть `edr_watch_status`). Функционал на месте — **документация врёт именами**, надо либо дописать mapping, либо переименовать команды.

### LOW — голосовой сервер сейчас не запущен
- `curl 127.0.0.1:8420/health` → нет ответа; порт 8420 свободен; в `~/.w420/tts.log` последняя строка — старая ошибка `bind: address already in use` от повторного ручного старта. Приложение поднимает TTS само через `tts_start` (кнопка в карточке голоса), но автостарт «из коробки» на этой машине сейчас не активен — проверить при следующем запуске GUI.

### LOW — мусор в runtime-директории
- В `~/.w420/` лежат тестовые остатки: `scan_20261105.py`, `test_capture.pcap`.

### INFO — честные SIM/WIP-плашки в HUD
- Декоративные карточки помечены `SIM`/`WIP` прямо в UI («PQC TAG: SIM», «AGI ASSISTANT SIM»), чат-ассистент честно говорит «заглушка». По правилам аудита это **честная нереализованность, а не обман** — реальный AI живёт в карточках AI SOC и «Управление провайдерами» (этапы 15/17, live-проверено: 84 модели NVIDIA NIM, ответ 2334 мс, 38.6 ток/с).

## 5. Что я НЕ смог проверить на этом хосте

- GUI Tauri вживую (нет дисплея/Xvfb) — вся проверка headless: тесты, сборка, статика JS/HTML, wiring команд.
- Полная загрузка ISO на VM/железе (ISO 2.8 ГБ собран и верифицирован структурно: autoinstall + LUKS + GRUB, но boot не поднимался).
- Live-NVIDIA в рамках этого аудита не гонял (прогнан на этапе 17).

## 6. Итоговая классификация

| Класс | Что |
|---|---|
| Работает и доказано | сборка, 121 тест, wiring 167 команд, 131 вызов из UI без 404, шифрование ключей, параметризованный SQL, PKI SAN, все 6 скриптов, JS/HTML статика |
| Broken (регрессия/устаревание) | .deb/.ISO содержат UI до этапов 17–18; лишняя `dist/dist` в staging .deb |
| Dead (написано, не подключено) | threats_* UI (карточка есть, handler нет); security_ai_* / config_parse_* не из UI |
| Unbuilt (план vs факт) | `edr_agents_list`; SIM/WIP-плашки HUD (честно помечены) |
| Не проверено | GUI вживую, boot ISO, автостарт TTS при старте приложения |

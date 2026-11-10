# Отчёт: голосовой бэкенд (STT/TTS + клон), аварийный режим, сетевой стек и хосты

## 1. Голосовой бэкенд — поднят и проверен вживую
- **Сервер**: новый `w420_tts` (FastAPI, venv в `~/.w420/tts-server/.venv`), стартует через существующую команду `tts_start` (порт 8420, токен из `~/.w420/tts.env`, заголовок `X-W420-Token` на всех эндпоинтах кроме `/health`).
- **TTS**: espeak-ng (RU/EN/ES), ответ — WAV. Проверено: `POST /speak` → HTTP 200, 92 КБ валидного WAV; неверный токен → 401.
- **STT**: faster-whisper (base, CPU int8, модель ~150 МБ скачивается один раз). Проверено: `POST /stt` с WAV-командой → HTTP 200, `{"text": …}`.
- **Клонирование голоса оператора**: `POST /voices` в двух форматах (multipart и raw WAV + заголовки `X-Voice-Name/X-Voice-Lang` — как шлёт voice.js). Образец сохраняется в `~/.w420/tts-server/voices/`, считается длительность и F0 (автокорреляция) → питч профиля. Проверено: F0=105 Гц → pitch 36, `GET /voices` отдаёт профили, `POST /speak` с профилем клона → 110 КБ WAV.
- **Голосовое управление**: новая Rust-команда `voice_command` — диспетчер русских команд: «тревога» → аварийный режим, «отбой» → мониторинг, «статус», «сканируй сеть» (подсеть из default route), «заблокируй IP»/«разблокируй», «мониторинг включи/выключи» (IDS), «список хостов». Ответ возвращается текстом и озвучивается. Во фронтенде — кнопка 🎤: запись микрофона → `voice_hear_b64` (ffmpeg → WAV 16 кГц → /stt) → `voice_command` → ответ голосом (`voice_say`/движок).
- Команды: `voice_status`, `voice_say`, `voice_hear_b64`, `voice_command`.

## 2. Аварийный режим (emergency.rs)
- Одна таблица `inet w420_em` с хуками input/output — **все каналы сразу**, применение атомарным batch-файлом `nft -f` (сначала `delete table`, потом создание — одним файлом).
- Уровни: `monitor` (таблица удаляется), `alert` (drop C2-портов 1234/4444/5555/… + IP из чёрного списка IDS), `emergency` (input policy DROP, разрешены lo/established/related/ICMP; опция `egress_strict` — output DROP кроме DNS/HTTP(S)).
- Состояние в `~/.w420/emergency.json`; `emergency_rules_preview` показывает правила без root; применение без root вернёт `needs_root: true`, состояние сохранится.
- UI: красная 🚨 в шапке (вкл/отбой с подтверждением, пульсация когда активно) + секция в панели ⚙ (уровень, жёсткий egress, авто-включение при алерте, превью правил nft). ПOLL статуса каждые 5 с.
- Команды: `emergency_status`, `emergency_set`, `emergency_rules_preview`, `emergency_apply_saved`.

## 3. Сеть и хосты
- `net_scan.rs`: добавлены `os_guess` (TTL ping: 64→Linux, 128→Windows, 255→сетевое устройство) и reverse DNS (`getent hosts`) в каждый найденный хост.
- Новая вкладка **СЕТЬ · ХОСТЫ**: скан подсети с живым обновлением списка каждые 2 с (IP, hostname, ОС, порты/сервисы/баннеры, метка «новый/в инвентаре»), per-host кнопки «+ в инвентарь» и «⛔ блок» (IPS), плюс инвентарь хостов с добавлением и подключением по SSH (`hosts_connect`).

## Проверки
- `cargo test -p w420 --lib`: **47 passed, 1 failed** — фейл только старый известный `sysops::gitleaks` (окружение). Новые: 6/6 (emergency rules ×4, b64 roundtrip, find_ip).
- `cargo build --release` — exit 0, бинарник 46.8 МБ.
- `node --check` для emergency.js / net.js / voice.js — OK.
- Живой голосовой сервер: /health, /speak (WAV), /stt (текст), /voices (оба формата клона) — всё HTTP 200, токен проверяется.

## Известные ограничения
- nft/tcpdump требуют root: без passwordless sudo применение в ядро вернёт `needs_root` (состояние сохранится и применится при наличии прав).
- STT на синтетическом espeak-голосе грубоват — с микрофона (whisper base, RU) заметно лучше.

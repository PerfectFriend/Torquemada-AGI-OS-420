# Этап 32 — Запись сессий + hash-chain журнал — DONE

## Что сделано (`sessrec.rs`, 7 команд)
- `sessrec_start/stop` — запись интерактивной shell-сессии (или одной команды): **asciinema .cast v2**, если бинарник есть, иначе фолбэк на `script` (typescript). Файлы в `~/.w420/sessions/`, метка валидируется.
- `sessrec_list` — список записей (формат, размер, mtime); `sessrec_read_cast` — разбор .cast в события для inline-просмотра; `sessrec_render_mp4` — рендер в mp4 (asciinema+agg), если утилиты есть.
- **Аудит-цепочка** `~/.w420/audit-chain.jsonl`: каждая запись = `{ts, hash=sha256(prev‖payload), prev, payload}`; `sessrec_verify_chain` проверяет всю цепочку.
- UI `sessrec.js`: старт/стоп, список, просмотр, MP4, индикатор цепочки (OK / повреждена).

## Проверено
- +4 теста: формат .cast, стабильность chain_hash, verify_chain на реальной цепочке, **реальная запись one-shot команды через `script` с маркером в выводе**. Workspace: **183 passed, 0 failed**; build exit 0; `node --check` OK.
- Пуш: PerfectFriend/Torquemada-AGI-OS-420.

## Честные ограничения
- .cast пишется только при наличии asciinema; в dev-окружении фолбэк `script` (проверен тестом).
- MP4-рендер требует asciinema+agg — в UI честно сообщает, если нет.

## Следующий этап
33 — Smart-Card / PKCS#11 подпись (уже есть pki.rs — расширить HSM/SmartCard через pcsc-lite).

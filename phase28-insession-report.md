# Этап 28 — In-session chat, file transfer, multi-admin роли — DONE

## Что сделано (rdesk.rs, +6 команд)
- **Multi-admin роли**: поле `role` у сессии (`controller`/`viewer`), команда `rdesk_set_role(id, role)` с валидацией. Viewer не шлёт ввод (UI), controller — управляет.
- **In-session чат**: `rdesk_chat_send(id, author, text)` / `rdesk_chat_recv(id, since)` — offset-polling, чтобы несколько UI-вкладок (multi-admin) читали одно и то же; лимит 4096 символов; дубль каждого сообщения на диск `~/.w420/rdesk/<id>.chat.jsonl` (audit-friendly).
- **File transfer поверх SSH**: `rdesk_xfer_list(host_id, remote_path)` (ssh ls -la), `rdesk_xfer_down(host_id, remote, local)` и `rdesk_xfer_up(host_id, local, remote)` через `scp -O` с `BatchMode=yes` и таймаутом; пути валидируются, аргументы передаются списком — без shell-инъекций; пароли/ключи не участвуют (ssh-agent/ключи хоста).
- **UI (rdesk.js)**: в строке сессии кнопки 🎮/👁 роль и 📁 файлы; в viewer-окне — чат-панель с polling 2с; отдельный диалог трансфера (листинг каталога, ⬆ залить, ⬇ скачать в `~/.w420/dl-*`).

## Проверено
- `cargo test -p w420 --lib`: **130 passed, 0 failed** (новые: роли+чат — валидация ролей, offset-чтение, лимит длины, чужая сессия; xfer — ошибка без хоста до любого ssh). Первый прогон workspace поймал 1 флак (тайминговый), повторный — зелёный.
- `node --check rdesk.js` OK; все 13 `invoke('rdesk_*')` совпадают с зарегистрированными командами.
- `cargo build --release` → exit 0.

## Честные ограничения
- Чат — in-memory + jsonl на диске; при рестарте приложения история сессии поднимется из файла (сейчас отдаётся только с момента старта — доработаем в этапе 32 вместе с записью сессий).
- Xfer идёт через системный ssh/scp хоста-источника; прогресс-бар — нет (есть итоговый размер файла).
- Live-scр против реального хоста тут не гонялся (нет ssh-цели в dev-окружении); валидация путей и ошибки — покрыты тестами.

## Следующий этап
29 — hosts_* как RAT: reboot/shutdown/lock/logoff, systemctl сервисы, journald, диски, пакеты, экспорт инвентаря CSV/XML, WoL.

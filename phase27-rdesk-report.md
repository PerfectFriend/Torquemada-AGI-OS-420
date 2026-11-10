# Этап 27 — Remote Desktop core (DameWare Parity) — DONE

## Что сделано
- **Rust `app/src-tauri/src/rdesk.rs`**: менеджер сессий `RdeskManager` (connect/disconnect/list, флаги lock-input/blank-screen, счётчик viewers). VNC: sidecar `websockify <ws_port> <host:5900>` → WebSocket; RDP: sidecar `xfreerdp /v:host /u:user /f` отдельным окном ОС. Если sidecar'а нет в PATH — честная ошибка, не тихий отказ.
- **Скриншоты**: собственный минимальный RFB-клиент (`rfb_grab_frame`): handshake → ServerInit → SetPixelFormat(32bpp LE, R16/G8/B0) → SetEncodings(Raw) → FramebufferUpdate → RGBA → PNG (крейт `png` в workspace). Команда `rdesk_screenshot(host, port, out_path)`.
- **7 команд** зарегистрированы в `generate_handler!`, состояние — `.manage(RdeskManager::default())`.
- **UI `app/dist/rdesk.js`** (native-only): панель REMOTE DESKTOP в разделе v-net (список сессий, viewer'ы, lock/blank, скриншот, закрытие), кнопки 🖥VNC / 🪟RDP на карточках хостов, просмотр VNC прямо в приложении — свой RFB-over-WebSocket клиент рисует кадры на `<canvas>` (Raw encoding, без внешних библиотек).
- `index.html`: добавлен `<script src="rdesk.js"></script>`.

## Проверено
- `cargo test --workspace`: **159 passed, 0 failed** (3 новых: мок VNC-сервер → кадр 4x3 → RGBA конверсия, отказ при отсутствии сервера, bookkeeping сессий/флагов).
- `node --check app/dist/rdesk.js` OK; все 7 `invoke('rdesk_*')` совпадают с зарегистрированными командами; `id="v-net"` на месте.
- `cargo build --release` → exit 0.

## Известные ограничения (честно)
- VNC требует на целевой машине `websockify`, RDP — `freerdp` (ставятся пакетом w420-os; на текущем dev-хосте их нет, поэтому live-подключение тут не гонялось — мок-сервер в тестах покрывает RFB-часть).
- lock-input/blank-screen — клиентские флаги + UI (как overlay); server-side блокировка ввода появится в этапе 28 вместе с in-session контролем.
- RDP на headless-хосте не откроет окно — там будет работать только VNC-путь.

## Следующий этап
28 — in-session chat, file transfer (SCP UI), multi-admin join с ролями.

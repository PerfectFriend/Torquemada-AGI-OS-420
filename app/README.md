# WINDOWS 420 — нативная оболочка (Tauri 2)

Каркас: страница W420 (папка `dist/`) внутри нативного окна + Rust-команда
`system_metrics` (реальные CPU/RAM/ОС через `sysinfo`). Внутри Tauri HUD
автоматически переключается на нативные данные (мост в конце `dist/index.html`).

## Запуск
1. Установи Rust (rustup) и системные зависимости Tauri 2: https://v2.tauri.app/start/prerequisites/
2. `npm install`
3. Иконки (обязательно, один раз): `npx tauri icon путь/к/квадратной-картинке.png`
4. Разработка: `npm run tauri dev`
5. Сборка: `npm run tauri build`
6. Android: `npx tauri android init`, затем `npx tauri android dev` (нужен Android Studio + NDK)

## Статус каркаса
- Написан без запуска: сборку я не проверяла. Если компилятор ругнётся на версии
  (особенно `sysinfo`, чей API меняется между релизами) — пришли текст ошибки.
- `csp: null` и CDN-шрифты/ethers в `index.html` — только для разработки.
  Перед релизом: положить ethers и шрифты локально и включить строгий CSP.
- Права: в `capabilities/default.json` только `core:default`. Новые возможности
  (shell, fs, сеть) добавляй по одной и осознанно. Произвольный shell из страницы
  не открыт специально: его мог бы вызвать любой текст, попавший в страницу.

## Следующие шаги (по плану)
1. Tor и Tailscale как sidecar-бинарники (`bundle.externalBin`) + команды start/stop/status.
2. Реальные Tor/mesh-метрики в HUD вместо SIM-индикаторов.
3. Локальная модель (llama.cpp sidecar) как запасной вариант ядра AGI.
4. Фоновый режим: агенты в Rust-процессе, переживающие закрытие окна.
5. RPC-запросы к Sepolia из Rust (баланс и отправка подписанных транзакций).

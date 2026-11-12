# Деплой новой версии (этапы 39–40) в рабочую папку

**Бинарник:** `$HOME/build/cache/cargo-target-w420/release/w420` — пересобран `cargo build --release` (Nov 12 13:13), скопирован также в w420-кэш (первый путь в `launch.sh`).
**Тесты:** `cargo test --workspace` → 188+11+20 passed, 0 failed.
**В бинарнике зашит свежий `app/dist`** (сборка после правок 13:05): `desktop.js` (Desktop OS: окна, taskbar TOOLS, трей, Alt+Enter fullscreen), `w420-desktop.css`, 6 тем (`matrix/amber/cyan/violet/red/light`) в настройках.
**Старые настройки** `theme:"dark"` маппятся на `matrix` — ничего не ломается.
**Иконка на десктопе** (`w420.desktop` → `launch.sh`) подхватит новый бинарник автоматически.

Запуск: двойной клик по иконке «Torquemada 228 AGI» на рабочем столе.

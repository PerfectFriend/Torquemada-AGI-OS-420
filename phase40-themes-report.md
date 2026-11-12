# Этап 40 — Темы / скины интерфейса

**Коммит:** `929062c` в `PerfectFriend/Torquemada-AGI-OS-420`.

## Что сделано
Темы — наборы CSS-переменных на `:root[data-theme="…"]` в `index.html`; выбор в меню «⚙ Настройки → Тема», сохраняется через `settings_set` (Tauri) + localStorage фолбэк.

| Скин | `--live` | Характер |
|---|---|---|
| **matrix** (дефолт) | `#00ff41` | зелёный неон, как был |
| **amber** | `#ffb000` | янтарный терминал |
| **cyan** | `#00e5ff` | циановый |
| **violet** | `#b26bff` | фиолетовый |
| **red** | `#ff2244` | красная тревога |
| **light** | `#0a7a2f` | светлая (была раньше) |

`dark` оставлен легаси-алиасом matrix (старые настройки не ломаются).

## Интеграция с Desktop OS
- Все жёсткие цвета в `desktop.js` (окна, taskbar, трей, меню, уведомления) заменены на `var(--live/--panel/--head/--ink/--glow)` — окна следуют теме мгновенно.
- `w420-desktop.css` уже работал на переменных.
- `i18n.js`: `applyTheme` ставит тему как есть, дефолт `matrix`, `syncPanel` отражает выбор в select.

## Проверено в браузере (:8421)
- Перебор 6 тем: computed `--live`/`--bg` меняются корректно (matrix `#00ff41`, amber `#ffb000`, cyan `#00e5ff`, violet `#b26bff`, red `#ff2244`, light `#0a7a2f`).
- Сквозной путь: `select#s-theme = violet` + change → `data-theme="violet"`, `localStorage.w420.settings.theme = "violet"`, `--live = #b26bff`. Обратно на matrix — ок.
- `node --check` для `i18n.js` и `desktop.js` — OK.

# RC1 — баннеры от Grok интегрированы, репозиторий готов

**Коммит:** `34ad959` в `PerfectFriend/Torquemada-AGI-OS-420` (public).

## Баннеры
Grok сгенерировал 3 баннера по промптам из `BANNER-PROMPTS.md` — все проверены визуально, текст читаемый, артефактов нет:

| Файл | Размер | Где в README |
|---|---|---|
| `banner-hero.jpg` | 1200×421 | hero-блок, под ним H1 |
| `banner-features.jpg` | 1200×786 | секция «Возможности» (4 панели: default-deny firewall · Madre AI helm · host health dashboard · i18n in 3 languages) |
| `banner-install.jpg` | 1200×764 | раздел «Установка» (bash SETUP.sh → install complete) |

Кроп настроен так, чтобы все ключевые элементы попали в кадр (фигура Матери, щит-файрвол, глобус RU/EN/ES, терминал с `cargo build --release` 78%, меню приложений Torquemada). SVG-версии (`banner-hero.svg`, `banner-features.svg`, `banner-features.svg` и др.) оставлены как альтернатива — ссылка на векторную версию указана под баннером.

## Итог RC1 по всем этапам
- **Однокомандная установка:** `bash SETUP.sh` — проверка зависимостей, сборка/загрузка deb, sidecars, автозагрузка (`.desktop` + `systemd --user`), root-setup по согласию; ISO не нужен (`build_iso.sh` — заглушка).
- **i18n:** `app/dist/i18n.js` (ключ = русская строка, MutationObserver); `i18n.en.js` + `i18n.es.js` — по 701 ключу, симметрично, 87% покрытия UI; переключение RU/EN/ES в меню «⚙ Настройки», подтверждено в браузере.
- **Документация:** README.md (русская, с баннерами, таблицами, структурой), SETUP.md, RC1-PLAN.md, BANNER-PROMPTS.md, MIT LICENSE.
- **Диаграммы:** `arch-rc1.svg`/`.png` (архитектура), `install-flow.svg`/`.png` (поток установки).
- **Коммиты:** i18n-отчёт (376d57b) · баннеры-отчёт (3ed40a4) · i18n 701 ключей (2bf6cea) · README/баннеры (14124af) · интеграция Grok (34ad959).
- Отчёты отправлены в топик Telegram 252 — все `sent`.

Репозиторий готов: открытый, с автозапуском, прозрачным provision ресурсов и глобальной локализацией.

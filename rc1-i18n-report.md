# RC1: i18n + open-source репозиторий — отчёт

**Коммит:** `a8a8e9f` в `PerfectFriend/Torquemada-AGI-OS-420` (public).

## Сделано
- README.md пересобран (RU, бейджи, таблица фич, one-command install).
- `SETUP.sh` + `SETUP.md`: автоустановка без ISO; `build_iso.sh` — заглушка; `root_setup.sh` спрашивает согласие.
- Диаграммы: `arch-rc1.svg`, `install-flow.svg`.
- `BANNER-PROMPTS.md`: 3 промпта для Grok (hero 1200×260, фичи 1200×300, установка 1200×260), EN + короткие варианты.
- i18n: движок `app/dist/i18n.js` (ключ = RU-строка, MutationObserver, переключатель в «⚙ Настройки»). Словари расширены: **EN 430 ключей, ES 257** (вся статика index.html на обоих языках + ~150 JS-UI строк EN).

## Проверено в браузере (http.server 8421)
- RU→EN→ES→RU переключение работает; словари грузятся (dictEN=430, dictES=257); placeholder переводится; выбор языка сохраняется. Непереведённое падает на RU (fallback).

## Осталось
- ES-перевод ~380 оставшихся JS-строк (сейчас fallback RU).
- Баннеры сгенерировать по промптам из BANNER-PROMPTS.md.

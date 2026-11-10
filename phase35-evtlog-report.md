# Этап 35 — Журнал событий (Event Log) — DONE

## Что сделано (`evtlog.rs`, 7 команд)
- **Локальный журнал**: sqlite `~/.w420/events.db` (ts, level, source, message, tags, индексы) — `evt_log`, `evt_query` (фильтр level/since/поиск LIKE/limit), `evt_stats` (по уровням), `evt_prune` (retention — оставить N свежих).
- **Удалённый Windows Event Log** через SSH: `evt_remote_logs` (`wevtutil el`), `evt_remote_query` (`wevtutil qe <log> /q:XPath /f:xml /c:N /rd:true`). Имя лога и XPath валидируются (белый список, запрет `";&|` и `..`), count клампится 1..1000. XML парсится вручную в JSON: provider (тег или атрибут Name=), event_id, level, time, computer, message (EventData/Data или RenderingInfo/Message).
- UI `evtlog.js`: статистика по уровням, таблица с фильтрами, запись события, удалённый query с чекбоксом «только ошибки (Level≤2)».

## Проверено
- +5 тестов: валидаторы (лог/XPath), сборка wevtutil (кламп count, отказ на инъекции), парсер wevt XML на 2 событиях (атрибутный и self-closing Provider, unescape), локальный sqlite roundtrip, xml_unescape. Workspace: **197 passed, 0 failed**; build exit 0; `node --check` OK.
- Пуш: PerfectFriend/Torquemada-AGI-OS-420.

## Честные ограничения
- Live wevtutil не проверялся (нет Windows-хоста); проверены сборка команд, валидация и парсинг XML.

## Следующий этап
36 — удалённый Task Manager расширенный (процессы с деревом, завершение с дампом, автозапуск/Scheduled Tasks через schtasks).

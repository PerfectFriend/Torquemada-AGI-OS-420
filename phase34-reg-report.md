# Этап 34 — Реестр (локальный + удалённый Windows) — DONE

## Что сделано (`reg.rs`, 7 команд)
- **Локальный реестр w420**: sqlite `~/.w420/registry.db`, таблицы `kv` + `kv_history` — `reg_local_get/set/list/history` (set пишет в историю в транзакции).
- **Удалённый реестр Windows** через существующий SSH-канал `hosts.exec_command`: `reg_remote_query/set/delete` → `reg.exe query/add/delete`. Пути валидируются (hive HKLM/HKCU/… + безопасный набор символов), имена/значения квотятся, инъекции (`;`, `&`, кавычки) режутся; сборщики команд — чистые функции.
- UI `reg.js`: локальный kv (set/get/история), удалённый query/add/delete с выбором хоста и типа REG_*.

## Проверено
- +6 тестов: валидация путей/имён/типов, сборщики reg-команд (включая отказ на инъекции), парсер вывода `reg query`, квотирование, **реальный sqlite roundtrip set→get→history**. Workspace: **192 passed, 0 failed**; build exit 0; `node --check` OK.
- Пуш: PerfectFriend/Torquemada-AGI-OS-420.

## Честные ограничения
- Live reg.exe не проверялся (нет Windows-хоста в dev); проверены сборка/валидация команд и парсинг вывода. SSH-путь — тот же, что у hosts_exec.

## Следующий этап
35 — удалённый Event Log (wevtutil через SSH + локальный журнал событий w420 с фильтрами).

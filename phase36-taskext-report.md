# Этап 36 — Расширенный Task Manager — DONE

## Что сделано (`taskext.rs`, 8 команд)
- **Локально (Linux)**: `taskext_tree` — дерево процессов через sysinfo (pid/ppid/имя/cpu/mem/статус + children); `taskext_proc_info` (exe, cmd, cwd, start_time); `taskext_kill` (TERM/KILL, защита pid 0/1 и себя); `taskext_autostart_list` (включённые systemd --user units + `~/.config/autostart/*.desktop` с Hidden).
- **Удалённо (Windows через SSH)**: `taskext_remote_procs` (`tasklist /fo csv /nh` + парсер CSV с `""`-экранированием), `taskext_remote_kill` (`taskkill /PID|/IM /F`, валидация имени), `taskext_remote_tasks` (`schtasks /query /fo csv [/tn]`), `taskext_remote_autostart` (reg query Run HKCU+HKLM, парсер в записи автозапуска).
- UI `taskext.js`: локальная таблица с фильтром и кнопками Инфо/TERM/KILL, автозапуск, удалённые процессы с Kill /F, schtasks, Run keys.

## Проверено
- +6 тестов: CSV-парсер (включая `""`), tasklist, сборщики taskkill/schtasks (отказ на инъекции), парсер Run keys, **дерево процессов находит себя**. Workspace: **203 passed, 0 failed**; build exit 0; `node --check` OK.
- Пуш: PerfectFriend/Torquemada-AGI-OS-420.

## Честные ограничения
- Live taskkill/schtasks не проверялись (нет Windows-хоста); проверены сборка команд, валидация, парсеры.

## Следующий этап
37 — удалённый файловый менеджер поверх SSH (SFTP/SCP): листинг, чтение/запись, права, поиск, архив.

# Этап 30 — Сетевые утилиты (ping/traceroute/DNS/port check) — DONE

## Что сделано (`netutil.rs`, 5 команд)
- `net_port_check(host, port, timeout_ms)` / `net_port_scan(host, ports[], timeout)` — **чистый Rust**: резолв через `ToSocketAddrs`, connect через `TcpStream::connect_timeout`; скан до 1024 портов за раз.
- `net_dns_lookup(name, record)` — A/AAAA/ANY через std; MX/TXT/SRV/… через `dig +short` (честная ошибка, если dig нет).
- `net_ping(host, count)` — `ping -c N -W 2`, парсер вывода (sent/received/loss%/rtt min-avg-max) в чистую функцию `parse_ping`.
- `net_traceroute(host, max_hops)` — `traceroute -n -m N -w 2`, фолбэк на `tracepath`, парсер хопов в `parse_traceroute`.
- UI `netutil.js`: панель «СЕТЕВЫЕ УТИЛИТЫ» в v-net — поле хоста + кнопки ping/traceroute/порт/DNS.

## Проверено
- `cargo test --workspace`: **173 passed, 0 failed** (+4 новых: port_check против реального локального TcpListener открытый/закрытый, DNS localhost → 127.0.0.1, parse_ping loss 0%/50% + rtt, parse_traceroute 4 хопа со `* * *`).
- `node --check netutil.js` OK; все 4 `invoke('net_*')` в панели совпадают с командами; build release exit 0.

## Честные ограничения
- ping/traceroute требуют системных бинарников (iputils, traceroute/tracepath) — в w420-os они в базовом образе.
- DNS не-A записи зависят от dig.

## Следующий этап
31 — модуль Active Directory (LDAP): OU/users/groups, unlock, reset password (HITL), GPO read-only, экспорт.

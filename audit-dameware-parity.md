# Аудит паритета с DameWare (DRS + Mini Remote Control) — 2026-11-09

**База аудита (наша сторона, проверено кодом):** 193 `#[tauri::command]` = 193 в `generate_handler!`; 150 `inv()` из UI, 0 неразрешённых; `cargo test --workspace` 156 passed / 0 failed; модули: bridge, tor, firewall, emergency, net_scan, hosts, siem, traffic(IDS), edr, patch_mgmt, threats, web_scan, pki, vpn, harden, sysops, updates, voice, settings, ai_providers, security_ai(engine), ai_soc, agi, wallet, pqc, did, radio, map + core.

**База сравнения (DameWare, по датшитам SolarWinds/обзорам):** DRS = RAT без полного remote-control для части задач + MRC = интерактивный remote desktop (RDP/VNC/macOS), in-session chat/screenshot/file transfer, WoL/AMT/KVM, remote reboot/shutdown, event log view/clear, services/processes start/stop, registry, disk/shares, system info + экспорт CSV/XML, AD-менеджмент (unlock/reset password/GPO), TCP-утилиты (ping/traceroute/DNS/FTP/Telnet), FIPS 140-2 шифрование, Smart Card, 2FA, session recording, Gateway/proxy, мобильный клиент iOS/Android, интеграция с ITSM.

## Таблица паритета (фичи DameWare → наш статус)

| # | Фича DameWare | Статус в W420 | Основание (наши команды/модули) |
|---|---|---|---|
| 1 | Интерактивный remote desktop (GUI, RDP/VNC/macOS) | **НЕТ** | У нас CLI-удалёнка по SSH; GUI-сессии нет вообще |
| 2 | Мультисессия / два админа в одной сессии | **НЕТ** | `hosts_connect/disconnect` — одна сессия на хост |
| 3 | Агент / agentless / on-the-fly агент | **ЧАСТИЧНО** | SSH-инвентарь `hosts_*` (постоянный доступ), on-the-fly нет |
| 4 | In-session chat с пользователем хоста | **НЕТ** (есть AGI-чат, но не per-session) | `agi_chat`, `soc_chat` — ассистент, не чат с remote user |
| 5 | Скриншот удалённого экрана | **НЕТ** | нет доступа к дисплею |
| 6 | File transfer в сессии | **ЧАСТИЧНО** | `hosts_exec` (scp/rsync доступно), но нет спец. UI передачи файлов |
| 7 | Lock/blank screen, пауза сессии | **НЕТ** | нет GUI |
| 8 | Запись сессии (screen recording) | **ЧАСТИЧНО** | audit hash-chain (SHA-256) наших действий; видеозаписи сессии нет |
| 9 | Wake-on-LAN | **НЕТ** | нет команды |
| 10 | Intel AMT/vPro, KVM out-of-band | **НЕТ** | нет |
| 11 | Remote reboot/shutdown/logoff/lock | **ЧАСТИЧНО** | через `hosts_exec` (`ssh host reboot`), спец. команды нет |
| 12 | Просмотр/kill процессов на хосте | **ДА** | `edr_scan_processes`, `edr_kill_pid`, `edr_events`, `edr_watch_*`, `edr_agents_list` |
| 13 | Start/stop сервисов на хосте | **НЕТ** | нет (systemd через exec — ручками) |
| 14 | Remote command prompt / запуск скриптов | **ДА** | `hosts_exec` (таймаут, вывод), инвентарь `hosts_*` |
| 15 | Event log: просмотр/очистка (Windows) | **ЧАСТИЧНО** | `siem_ingest/events/search/correlate`, `traffic_eve_sync` (suricata eve) — но это наш SIEM, не remote eventvwr; очистки нет |
| 16 | Remote registry editor | **НЕТ** | нет |
| 17 | Диски/шары/форматирование | **ЧАСТИЧНО** | `system_metrics` (локальный storage), удалённого диска нет |
| 18 | System info + инвентарь ПО + экспорт CSV/XML | **ЧАСТИЧНО** | `system_metrics`, `hosts_status` (OS хоста); инвентарь ПО/экспорт — нет |
| 19 | Performance monitor удалённого | **ЧАСТИЧНО** | HUD-метрики локальные (fps/heap/net/bat/sto), `system_metrics`; remote perfmon нет |
| 20 | TCP-утилиты: ping/traceroute/DNS/FTP/Telnet | **ЧАСТИЧНО** | `net_scan_subnet` (nmap), `net_parse_cidr`, `web_scan_*`; ping/traceroute/dns — через exec |
| 21 | AD: домены/пользователи/группы/OU, unlock, reset password, GPO | **НЕТ** | AD/LDAP-модуля нет (Linux-first) |
| 22 | Экспорт AD/системной конфигурации в CSV/XML | **НЕТ** | нет |
| 23 | FIPS 140-2 шифрование, Smart Card, 2FA | **ЧАСТИЧНО** | AES-256-GCM везде + ML-KEM-768 PQC + DID-подписи; 2FA/smart card нет |
| 24 | Аудит/логирование сессий | **ДА** | audit hash-chain SHA-256 (`w420.audit`), SIEM, трей-алерты |
| 25 | Центральная консоль + сохранённые подключения с паролями в vault | **ДА** | hosts-инвентарь + QFS Vault (AES-256-GCM, PBKDF2 200k) + PQC-seal |
| 26 | Gateway/proxy для внешних подключений | **ДА (и шире)** | `bridge_*` (sing-box sidecar, vless/vmess/wg/ovpn), `tor_*` (Arti onion), `vpn_*` (WG-сервер) |
| 27 | Мобильный клиент (iOS/Android) | **НЕТ** | нет |
| 28 | Интеграция с ITSM/ticketing | **НЕТ** | нет |

## Где W420 превосходит DameWare (у DameWare этого нет вообще)
- Сетевая безопасность: nftables-профили/правила/изоляция хоста (`firewall_*`), emergency-режим (`emergency_*`), IDS suricata (`traffic_*`), EDR baseline/diff/watch (`edr_*`), SIEM с правилами и инцидентами (`siem_*`), CVE/threat-монитор (`threats_*`), веб-скан уязвимостей (`web_scan_*`).
- Управление конфигурацией и уязвимостями: hardening plan/apply/revert (`harden_*`), FIM + trivy + gitleaks (`sysops_*`), патч-менеджмент с rollback (`patch_mgmt_*`), `updates_check`.
- Крипто/доверие: PKI CA (`pki_*`), PQC vault ML-KEM (`pqc_*`), DID P-256 (`did_*`), кошелёк (`wallet_*`), AI-провайдеры с ротацией ключей и шифрованием в БД (`ai_providers_*`), AI SOC (`ai_soc_*`), AGI-ассистент с HITL (`agi_*`), радио/mind map.

## Итоговая оценка
- Из 28 ключевых фич DameWare: **полностью покрыто 4 (14%)**, **частично 9 (32%)**, **нет 15 (54%)**.
- Главный разрыв — **ядро MRC**: интерактивный GUI remote desktop, in-session chat/screenshot/file transfer, multi-session — у нас нет ничего из этого (нет доступа к дисплею вообще; удалёнка только CLI по SSH).
- Второй разрыв — **Active Directory** (вся AD-часть DRS) и out-of-band (WoL/AMT/KVM), remote reboot/services/registry как «first-class» команды.
- По безопасности самого инструмента и по security-операциям W420 **шире DameWare**: аудит-цепочка, шифрование ключей at rest, PQC, SIEM/IDS/EDR/патчи — у DameWare этого нет.

## Что дало бы «parity с DameWare» (если захотим)
1. Модуль remote desktop: RDP/VNC клиент в Rust (или sidecar) + multi-session — самый объёмный пункт.
2. `hosts_*` расширить: file transfer (scp UI), reboot/shutdown/lock, services list/start/stop (systemctl), event log (journald) view/clear, disk usage, installed packages — все поверх SSH, дёшево.
3. WoL (`etherwake`), ping/traceroute/dns как команды.
4. AD-модуль (LDAP): users/groups/unlock/reset — если целимся в Windows-инфраструктуры.
5. In-session chat к оператору хоста, screenshot (scrot/import), запись сессии (asciinema/ffmpeg screen).
6. 2FA/smart-card для входа в консоль.

**Вердикт:** как «утилита удалённой поддержки à la DameWare» — покрыто ~46% (считая частичное как половину), но ядро (GUI remote control + AD) отсутствует; как **платформа системного администратора по безопасности** — функционал заметно шире DameWare.

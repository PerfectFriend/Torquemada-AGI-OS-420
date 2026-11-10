# W420 — Фазы 11–12 (патч-менеджмент + WireGuard сервер) — 2026-11-05

## Фаза 11: patch_mgmt.rs — ГОТОВО
- `patch_scan_local/all`: `apt list --upgradable` локально + по ssh на хосты из hosts.db (BatchMode, 5с). **Live: на этой машине сейчас 13 пакетов, из них security — по origins `-security`** (`live_scan_local ... ok`).
- Приоритизация security, история сканов в `~/.w420/patch.db`.
- `patch_deploy(security_only)` — `sudo -n apt-get install -y …`; если apt-get не в sudoers → `needs_root` + готовая команда (в root_setup.sh добавлены NOPASSWD для apt/apt-get — **перезапусти скрипт один раз**).
- `patch_rollback_plan` — парсит `/var/log/apt/history.log`, строит команды downgrade (только план, без выполнения).
- `patch_ai_assess` — AI-оценка риска security-пакетов через KeyRotation (NVIDIA).
- Команды: patch_scan_local/scan_all/list_updates/deploy/rollback_plan/status/ai_assess. UI: карточка «ПАТЧ-МЕНЕДЖМЕНТ» (`ops.js`).

## Фаза 12: vpn.rs — WG-сервер ПРОВЕРЕН LIVE
- **LIVE full cycle пройден**: init (ключи, порт 51820) → peer_add (allowed_ip из пула, applied_live=true) → server_start (up=true, ошибок нет) → `wg show` видит peer с allowed-ips → stop (down). Тест `live_vpn_full_cycle ... ok`.
- Барьеры, найденные и закрытые: AppArmor-профиль `wg` читает только `/etc/wireguard/` → живой конфиг льём через `sudo -n tee /etc/wireguard/w420wg.conf` (sudoers: точный путь, wildcard запрещён); `wg setconf` не ест wg-quick-поля → `to_wg_setconf_conf()` чистит до wg(8)-формата; NAT — через nft таблицу `w420_nat` (masquerade 10.77.0.0/24), а не iptables.
- root_setup.sh: добавлены `/usr/bin/wg`, `/usr/bin/wg-quick`, `/usr/sbin/ip`, `tee /etc/wireguard/w420wg.conf`, `apt-get`, `cat /var/log/apt/history.log` + `mkdir /etc/wireguard (700)`. **Скрипт прогнан владельцем — все NOPASSWD работают.**
- UI: карточка «VPN · WIREGUARD СЕРВЕР» (`ops.js`).

## Проверено
- Новые тесты 8/8 (parse apt upgradable/history, build_server_conf, remove_peer_block, parse_wg_show/transfer, live apt scan, live wg status). Вся lib: 68 passed / 1 известный fail (gitleaks) / 2 ignored.
- `cargo build --release` — чисто. JS `node --check` OK, HTML-баланс 0.
- WG примитивы вживую: `wg genkey | wg pubkey` → валидная пара.

## Действие владельца
`sudo bash /home/thomas/w420-install/scripts/root_setup.sh` — добавит NOPASSWD для wg/wg-quick/ip/apt-get + AppArmor override; после этого `vpn_server_start` и `patch_deploy` работают без пароля.

## Далее (Фазы 13–16): веб-сканер, PKI, AI SOC (doрáботка), упаковка в ОС

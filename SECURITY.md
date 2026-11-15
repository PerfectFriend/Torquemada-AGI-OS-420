# Security Policy

## Reporting a vulnerability

If you find a security issue in Torquemada-AGI-OS-420, please **do not open a public issue**.
Report it privately to the repository owner via GitHub (DM / private contact listed in the profile)
or by email. Include a reproducer if possible. We aim to acknowledge within 72 hours.

## Scope notes

- This is a **personal / research-grade** desktop tool (RC1). It is not a hardened enterprise product.
- The app intentionally runs **local privileged helpers** (nftables firewall, sysctl hardening, ssh config)
  via narrow `NOPASSWD` sudoers entries created by `scripts/root_setup.sh`. Review that script before running it.
- API keys of LLM providers are stored **only** encrypted (AES-256-GCM) in `~/.w420/ai_providers.db`;
  the UI receives only masks (`…abcd`). The Hermes key pool (`~/.hermes/auth.json`) is read at startup
  to seed keys and is never sent anywhere except the provider's own endpoint.
- Secrets scan of full git history is clean at audit time (2026-11-13): only fake test keys
  (`nvapi-aaaa…`, `nvapi-abcdef…SECRET`) appear in unit tests.

## Supported versions

Only the latest commit on `main` is supported. There are no release branches yet (RC1 stage).

---

## ⚠️ Предупреждение об области применения (аудит 14.11.2026, п. 2.2)

> **Это инструмент системного администратора. Не устанавливайте его на недоверенные рабочие станции. Компрометация приложения = компрометация всех подключённых хостов.**

Поверхность привилегий (осознанный выбор «инструмента администратора»):

- RAT-команды на удалённых хостах (`rat_power`, `rat_service_control`, `rat_log_clear` и др.);
- применение nft-правил (Madre/Firewall/emergency), изоляция хостов;
- установка пакетов через root-хелпер `w420-apt-install`;
- отзыв WireGuard peer'ов, деплой патчей.

### Hardened-режим (`W420_HARDENED=1`)

Включите env-переменную `W420_HARDENED=1` (или `"hardened": true` в `~/.w420/settings.json`). В этом режиме **полностью отключены**:

- `rat_power` (reboot/shutdown/lock/logoff);
- `rat_log_clear` (очистка журналов);
- `rat_service_control` с действиями stop/restart;
- `fw_isolate_host`, `fw_profile_apply`;
- `emergency_set`, `emergency_apply_saved`;
- `vpn_peer_revoke`, `patch_deploy`.

Вне hardened-режима все перечисленные destructive-команды **требуют явного подтверждения** (`confirm=true` в аргументах вызова). Каждый вызов (разрешённый, отклонённый, заблокированный) пишется в журнал аудита `~/.w420/audit.db` (таблица `cmd_audit`: ts, cmd, host_id, result).

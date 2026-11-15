# Ответ на аудит безопасности 14.11.2026

Отчёт: `AUDIT-SECURITY-SAFETY-2026-11-14.md`. Все правки — один автор, по приоритетам, отдельными коммитами.

## P0

| Пункт | Статус | Коммит |
|---|---|---|
| TARGET_USER в `root_setup.sh` (убран хардкод `thomas`) | ✅ `SUDO_USER`/`logname`, отказ при root, sudoers-шаблон с `$TARGET_USER`, `chown` в `$TARGET_HOME/.w420`; `bash -n` + `visudo -c` на сгенерированном шаблоне пройдены | `76b8ec7` |
| `W420_HARDENED` + human-in-the-loop + аудит | ✅ новый модуль `hardened.rs`: env `W420_HARDENED=1` или `"hardened": true` в settings.json блокирует `rat_power`, `rat_log_clear`, `rat_service_control(stop/restart)`, `fw_isolate_host`, `fw_profile_apply`, `emergency_set/apply_saved`, `vpn_peer_revoke`, `patch_deploy`; вне hardened все они требуют `confirm=true`; каждый вызов → `~/.w420/audit.db` (`cmd_audit`: ts/cmd/host_id/result) | `6573b18` |
| Предупреждение в SECURITY.md | ✅ цитата «инструмент системного администратора…» + список привилегий + описание hardened-режима | `6573b18` |

## P1

| Пункт | Статус | Коммит |
|---|---|---|
| Honeypot bind из конфига | ✅ `honeypot_bind` в `MadreConfig`, дефолт `127.0.0.1` (было `0.0.0.0`), валидация IP, занятый порт логируется и пропускается | `8e6e290` |
| `.unwrap()`/poisoned mutex + clippy | ✅ на затронутых путях — `map_err`/match + запись MUTEX_POISONED в аудит вместо паники; `#[warn(clippy::unwrap_used)]` на модулях `madre, firewall, rat, hosts, ai_providers` | `6573b18`, `3752de6` |

## P2

| Пункт | Статус | Коммит |
|---|---|---|
| Узкий DNS в Madre | ✅ голый `udp dport 53 accept` убран; наружу DNS только к резолверам из `/etc/resolv.conf` (`ip daddr <ns> udp/tcp dport 53 accept`) | `3752de6` |
| Supply-chain sidecar-ов | ✅ `app/src-tauri/binaries/SHA256SUMS`; SETUP.sh сверяет хеш и прерывает установку при несовпадении | `3752de6` |
| SETUP.sh: fail-fast + автостарт по согласию | ✅ прерывание при отсутствии обязательных зависимостей; XDG-autostart только при `--autostart`/`W420_AUTOSTART=1` | `53a1b1a` |

## P3

| Пункт | Статус |
|---|---|
| Сверка документации с командами | ✅ руководство по эксплуатации содержит полный список команд, сверенный скриптом с исходниками (289 имён, 0 расхождений) — `docs/РУКОВОДСТВО-ПО-ЭКСПЛУАТАЦИИ.md` |

## Проверки

- `cargo build --release` — чисто; `cargo test -p w420 --lib` — **189 passed, 0 failed**.
- Единственный падающий тест `bridge::tests::rejects_bad_config_then_starts_serves_and_stops` — **pre-existing,環境альный**: ему нужен исполняемый sidecar `sing-box` (падает на spawn, ENOENT загрузчика); к изменениям аудита отношения не имеет.
- `bash -n SETUP.sh scripts/root_setup.sh` — OK; `visudo -c` на сгенерированном sudoers-шаблоне — parsed OK.
- Бинарник пересобран и задеплоен в `~/build/cache/cargo-target-w420/release/w420`.

## Открыто (намеренно)

- Полная замена всех `.unwrap()` в prod-путях — lint включён как warn, рефакторинг точечный по мере touched-кода.
- `W420_PREFIX`/`--prefix` для SETUP.sh — отложено, текущая завязка на `$HOME/.w420` задокументирована.

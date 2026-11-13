# Ответ на внешний аудит (13.11.2026)

Отчёт: `Downloads/Torquemada-AGI-OS-420-Audit-Report.md` (оценка 7.2/10). Ниже — статус каждого замечания.

## Критичные

| # | Замечание | Статус |
|---|-----------|--------|
| 1 | Устаревшие артефакты .deb/ISO | ISO сознательно исключён из репозитория (`.gitignore`: `*.iso`, `*.deb`, `packaging/`); установка — только через `SETUP.sh` из исходников, релизные бинарники не распространяются. Сборка `cargo build --release` проверена (exit 0). |
| 2 | Dead UI: Threat Monitor и др. | **Закрыто.** `threats.js` подключён ко всем кнопкам `th-*` (`threats_scan/sync/list/alerts/acknowledge_alert/sources/last_scan`). Все 53 ранее неиспользуемые tauri-команды выведены в UI карточкой **ADVANCED COMMANDS** в окне Network (коммит `7f0f8f5`). |
| 3 | Security-review `root_setup.sh`/sudoers | **Закрыто** (коммит `7f0f8f5`): убран NOPASSWD для `nft`/`tcpdump` (теперь setcap `cap_net_admin,cap_net_raw`), `wg-quick`, полный `apt-get`, `mkdir`; `ip` — только 5 фиксированных команд; `tee` — только в `/etc/wireguard/w420wg.conf` с фильтром содержимого; apt — только через валидатор `/usr/local/sbin/w420-apt-install` (имена пакетов по regex, 1–50 аргументов). `visudo -c` пройден. |
| 4 | CI на test/clippy/build | **Закрыто** (коммит `7f0f8f5`): `.github/workflows/ci.yml` — `cargo test -p w420-core -p w420-ai -p w420-installer`, `cargo build --release`, `cargo clippy --workspace --all-targets` на push/PR в main. |

## Важные

| # | Замечание | Статус |
|---|-----------|--------|
| 5 | Документация отстаёт от кода | Частично: phase-отчёты ведутся; имена команд в EVOLUTION_PLAN могут расходиться — принимаем PR. |
| 6 | Много `unwrap()` в прод-путях | Открыто: запланирован отдельный аудит prod-путей (ai_soc, vpn, firewall). |
| 7 | CONTRIBUTING / CODE_OF_CONDUCT | **Закрыто:** `CONTRIBUTING.md` (коммит `7f0f8f5`), `CODE_OF_CONDUCT.md` добавлен сейчас. |
| 8 | Разделение core/optional | Открыто: структура workspace уже модульная (`w420-core`, `w420-ai`, `w420-installer`); further split — в roadmap. |

## Желательные

| # | Замечание | Статус |
|---|-----------|--------|
| 9 | Issues/labels/roadmap | Roadmap — `DESKTOP-EVOLUTION-PLAN.md`, `RC1-PLAN.md`; labels настраиваются в GitHub UI. |
| 10 | SECURITY.md | **Закрыто** (коммит `7f0f8f5`): приватный репортинг уязвимостей, NOPASSWD-политика, AES-256-GCM хранение ключей, скан чистой истории. |

## Что изменено после аудита
- Threat Monitor проверен подключённым (не dead).
- Добавлен `CODE_OF_CONDUCT.md`.
- Режимы UI: desktop-режим по умолчанию, классический UI — отдельным приложением (коммит `b55a4a8`).

## Честная самооценка (согласны с аудитором)
Проект — **мощный персональный cyber-агент / RC1**, а не enterprise-OS. WIP/SIM-пометки в UI намеренно оставлены: это прозрачность, а не баг.

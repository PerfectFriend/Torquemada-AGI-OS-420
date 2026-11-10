# Этап 33 — Smart-Card (PKCS#11 / OpenSC) — DONE

## Что сделано (`smartcard.rs`, 7 команд)
- Обёртка над `pkcs11-tool` (пакет opensc), модуль автоопределяется по типичным путям.
- `sc_status` (наличие tool+модуля), `sc_slots`, `sc_tokens` (метки/серийники), `sc_objects`, `sc_certs` (только публичные данные), `sc_sign` — подпись данных закрытым ключом (RSA-PKCS), данные идут через временный файл в `~/.w420/`, **PIN валидируется (4–16 цифр) и нигде не логируется**, временные файлы удаляются сразу.
- UI `smartcard.js`: статус, токены, сертификаты, выбор ключа, поле PIN (password, очищается после), подпись hex.

## Проверено
- +3 теста парсеров: `parse_slots`/`parse_token_labels` (id слота, фильтр present), `parse_objects` (cert vs private_key), `valid_pin`. Workspace: **186 passed, 0 failed**; build exit 0; `node --check` OK.
- Пуш: PerfectFriend/Torquemada-AGI-OS-420.

## Честные ограничения
- В dev-окружении opensc/карты нет — проверены парсеры и валидация; live-подпись требует реальную карту + `apt install opensc`. Команды в таком случае возвращают понятную ошибку, UI показывает бейдж.

## Следующий этап
34 — Remote registry / удалённый реестр (через SSH `reg.exe` на Windows-хостах + локальный sqlite-реестр конфигов).

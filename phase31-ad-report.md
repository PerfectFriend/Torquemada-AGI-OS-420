# Этап 31 — Active Directory (LDAP) — DONE

## Что сделано (`ad.rs`, ldap3 0.11 sync, 13 команд)
- **Конфиг**: `ad_config_set/get` — сервер/порт/bind DN/base DN в `~/.w420/ad.json` (права 0600), пароль шифруется AES-256-GCM (`w420_ai::encryption`), в UI/ответах — только маска `…xxxx`.
- **Чтение**: `ad_ping` (RootDSE), `ad_tree` (OU), `ad_users_search` (фильтр экранирован RFC 4515; флаги из userAccountControl: locked/disabled/no_password/password_never_expires), `ad_groups`, `ad_group_members`, `ad_gpo_list` (read-only, CN=Policies).
- **Запись (с HITL-confirm в UI)**: `ad_user_unlock` (pwdAccountLockedTime=0), `ad_user_reset_password` (unicodePwd как **бинарный** Vec<u8> UTF-16LE в кавычках — не lossy-строка; pwdLastSet=0 для смены при входе; минимум 8 символов), `ad_group_add_member/remove_member`.
- **Экспорт**: `ad_export users|groups → CSV/XML`.
- UI `ad.js`: панель AD в v-net (форма конфига, ping, OU/users/groups/GPO, unlock/reset/группы с confirm, экспорт).

## Проверено
- `cargo test --workspace`: **179 passed, 0 failed** (+6 новых: escape_filter, valid_dn, unicodePwd побайтово, маска, encrypt/decrypt roundtrip с ретраем от гонки соли, xml_esc). Один тест сначала падал в параллельном прогоне из-за чужой перегенерации соли — сделан ретрай, зелёный.
- `node --check ad.js` OK; 12 `invoke('ad_*')` совпадают с командами; `cargo build --release` exit 0.
- Пуш в https://github.com/PerfectFriend/Torquemada-AGI-OS-420 (публичный), коммит `cc3b67b`.

## Честные ограничения
- Live-проверка против настоящего DC тут не проводилась (нет домена в dev-окружении); unit-тесты покрывают парсинг/валидацию/кодировки, сетевой слой — ldap3.
- LDAPS по умолчанию (use_tls=true, порт 636); для StartTLS — доработаем при необходимости.

## Следующий этап
32 — запись сессий (asciinema/кадры → видео) + журнал сессий с hash-chain.

# W420 — root-работа выполнена (2026-11-04, через scripts/root_setup.sh)

Пароль не покидал терминал владельца; скрипт выполнен под sudo локально.

## Проверено вживую после выполнения
- `sudo -n nft list tables` — работает без пароля (sudoers.d/w420: NOPASSWD для /usr/sbin/nft, /usr/bin/tcpdump).
- `getcap`: tcpdump = cap_net_admin,cap_net_raw=ep; nft = cap_net_admin=ep → захват пакетов и управление nft **от обычного пользователя**.
- `nmap 7.98` и `suricata` установлены (`/usr/bin/nmap`, `/usr/bin/suricata`).
- nft live-тест: таблица `inet w420_em` применена атомарно (`nft -f`), показана, снята — APPLY_OK/REVERTED_OK.
- tcpdump захватил пакеты от uid 1000 (3 пакета, 0 dropped); pcap-артефакт `~/.w420/test_capture.pcap` (2313 байт) записан через /tmp + копирование.

## Найденная и исправленная ловушка
AppArmor-профиль `usr.bin.tcpdump` разрешает запись только в /tmp — прямая запись в `~/.w420` давала Permission denied даже с setcap. Исправлено двумя способами:
1. В приложении (`traffic.rs::capture_pcap`): tcpdump пишет во временный файл в /tmp, после завершения файл копируется в `~/.w420/pcaps/` — работает всегда.
2. В `root_setup.sh` (пункт 7): local-override AppArmor `owner /home/thomas/.w420/** rwk,` — после перезапуска профиля прямая запись тоже разрешена. **Перезапусти скрипт, чтобы применить override:** `sudo bash /home/thomas/w420-install/scripts/root_setup.sh`

## Что теперь доступно приложению без пароля
- IDS-захват tcpdump (start_ids) — работает от пользователя благодаря setcap.
- IPS/аварийный режим: `nft` / `sudo -n nft` — обе ветки в `traffic.rs`/`emergency.rs` теперь исполняются.
- Сканирование nmap/suricata как sidecar — бинарники на месте.

`cargo check -p w420` после правки — чисто.

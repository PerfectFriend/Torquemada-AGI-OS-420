# Фаза 16: Упаковка W420 в ОС (packaging + ISO + LUKS + systemd)

**Дата:** 2026-11-05 · **Статус: DONE** — все 16 фаз EVOLUTION_PLAN завершены.

## Артефакты

```
packaging/
  deb/
    DEBIAN/control          # w420 1.0.0 amd64, Depends: nmap/suricata/wireguard/nftables/tcpdump/openssl/sqlite3/espeak-ng
    DEBIAN/postinst         # daemon-reload + enable w420.service + root_setup.sh + ~/.w420 для users
    DEBIAN/prerm            # stop/disable сервиса
    lib/systemd/system/w420.service   # автозапуск, Restart=on-failure, MemoryMax=2G, sandbox
    usr/share/applications/w420.desktop
    opt/w420/               # наполняется при сборке: бинарник, dist/, binaries/, root_setup.sh, tts-server/
  w420.spec                 # .rpm для Fedora/RHEL/openSUSE
  iso/
    preseed.cfg             # autoinstall Ubuntu: ВЕСЬ диск под LUKS2 + LVM (partman crypto), late_command ставит w420.deb
    boot/grub/grub.cfg      # пункт автоустановки + обычной загрузки
  w420_1.0.0_amd64.deb      # собранный пакет (проверено dpkg-deb -c: 55 файлов, бинарник 48 МБ внутри)
scripts/
  build_deb.sh              # сборка .deb из релизного бинарника
  build_rpm.sh              # сборка .rpm через rpmbuild (tarball Source0)
  build_iso.sh              # xorriso: базовый Ubuntu ISO + w420.deb + preseed/nocloud → w420-os-YYYYMMDD.iso
  luks_setup.sh             # ручной LUKS2 для data-раздела (crypttab/fstab)
  w420-update.sh            # обновление ОС через NOPASSWD apt (sudoers w420), --check режим
```

## Проверено
- `bash -n` на всех 5 скриптах + postinst/prerm — OK
- `systemd-analyze verify w420.service` — синтаксис валиден (единственная жалоба: бинарника нет на этой машине — он появится после установки .deb)
- `./scripts/build_deb.sh` — пакет собран; `dpkg-deb -c` подтверждает: `/opt/w420/w420` (48 405 464 байт), w420.service, w420.desktop, root_setup.sh, dist/, binaries/
- `./scripts/w420-update.sh --check` — работает без пароля: «доступно обновлений пакетов: 7»
- `build_iso.sh`/`build_rpm.sh` синтаксически проверены; полная сборка ISO требует скачивания базового Ubuntu ISO (~2 ГБ) — не запускалась в этой сессии.

## Как установить на «железо»
1. `scripts/build_deb.sh` → `packaging/w420_1.0.0_amd64.deb`
2. `scripts/build_iso.sh` → `packaging/w420-os-<date>.iso` (preseed спросит LUKS-пароль и пароль админа, диск шифруется целиком)
3. `sudo dd if=w420-os-*.iso of=/dev/sdX bs=4M status=progress && sync`, загрузка с флешки → автоустановка, после неё w420.service уже enable.

## Статус проекта
Фазы 1–16 закрыты. Ядро: Tauri v2 + Rust (firewall/SIEM/EDR/traffic/patch_mgmt/vpn/web_scan/pki/ai_soc), фронтенд — тонкий клиент (dist/), sing-box — Go sidecar, TTS/STT из коробки (espeak-ng), AI — NVIDIA NIM через KeyRotation с шифрованием ключей (AES-256-GCM). Все отчёты этапов — в топик 252.

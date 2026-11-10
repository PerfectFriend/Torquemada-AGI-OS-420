#!/usr/bin/env bash
# build_iso.sh — сборка установочного ISO W420 на базе официального Ubuntu Server/Desktop ISO.
# Требует: xorriso, wget/curl, root (или sudo) для mount/loop — но мы работаем через xorriso без loop-mount.
# Использование: ./scripts/build_iso.sh [base-iso-url] [w420-deb]
#   base-iso-url по умолчанию: ubuntu-26.04-live-server-amd64.iso (скачивается в /tmp)
# Результат: packaging/w420-os-<дата>.iso
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

BASE_URL="${1:-https://releases.ubuntu.com/26.04/ubuntu-26.04.1-live-server-amd64.iso}"
DEB="${2:-$ROOT/packaging/w420_1.0.0_amd64.deb}"
WORK="$(mktemp -d "$ROOT/packaging/.iso-work.XXXXXX")"   # на nvme, не в tmpfs /tmp
trap 'rm -rf "$WORK"' EXIT

[ -f "$DEB" ] || { echo "нет .deb: $DEB (сначала scripts/build_deb.sh)" >&2; exit 1; }
BASE_ISO="$WORK/base.iso"
if [ -f "$BASE_URL" ]; then
    cp "$BASE_URL" "$BASE_ISO"   # локальный файл вместо скачивания
elif [ -f /home/thomas/w420-base.iso ]; then
    cp /home/thomas/w420-base.iso "$BASE_ISO"
else
    echo "[w420] качаю базовый ISO: $BASE_URL"; curl -fL --retry 3 -o "$BASE_ISO" "$BASE_URL"
fi

echo "[w420] распаковываю базовый ISO..."
xorriso -osirrox on -indev "$BASE_ISO" -extract / "$WORK/iso" 2>/dev/null
chmod -R u+w "$WORK/iso"   # xorriso сохраняет read-only права из ISO — снимаем, иначе cp/rm падают

# --- кладём w420.deb и preseed в корень ISO ---
cp "$DEB" "$WORK/iso/w420.deb"
cp "$ROOT/packaging/iso/preseed.cfg" "$WORK/iso/preseed.cfg"
# nocloud datasource: user-data с autoinstall
mkdir -p "$WORK/iso/nocloud"
cat > "$WORK/iso/nocloud/user-data" <<'EOF'
#cloud-config
autoinstall:
  version: 1
  source:
    id: ubuntu-server
    search_drivers: false
  # интерактивность минимальная: LUKS-пароль и пароль админа спросит инсталлятор
  interactive-sections: [network, storage, identity]
  late-commands:
    - curtin in-target -- cp /cdrom/w420.deb /target/opt/ 2>/dev/null || true
    - curtin in-target -- dpkg -i /opt/w420.deb || true
    - curtin in-target -- systemctl enable w420.service || true
EOF
touch "$WORK/iso/nocloud/meta-data"

# --- подменяем grub.cfg на автоустановку ---
cp "$ROOT/packaging/iso/boot/grub/grub.cfg" "$WORK/iso/boot/grub/grub.cfg"

OUT="$ROOT/packaging/w420-os-$(date +%Y%m%d).iso"
echo "[w420] собираю ISO: $OUT"
# База Ubuntu 26.04 — GRUB-only (нет isolinux): BIOS через eltorito.img, EFI через bootx64.efi
xorriso -as mkisofs \
    -r -V "W420-OS" \
    -o "$OUT" \
    -J -joliet-long \
    -b boot/grub/i386-pc/eltorito.img -c boot.catalog \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    -eltorito-alt-boot -e EFI/boot/bootx64.efi -no-emul-boot \
    "$WORK/iso"

echo "[w420] готово: $OUT ($(du -h "$OUT" | cut -f1))"
echo "Записать на флешку: sudo dd if=$OUT of=/dev/sdX bs=4M status=progress && sync"

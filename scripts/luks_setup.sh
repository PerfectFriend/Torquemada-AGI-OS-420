#!/usr/bin/env bash
# luks_setup.sh — ручная настройка полного шифрования диска (LUKS2) на уже установленной системе.
# Сценарий: шифруем НЕ root-раздел (root уже смонтирован), а выделенный раздел под данные /home или /data.
# Для шифрования root при установке используйте preseed.cfg из ISO.
# Использование: sudo ./scripts/luks_setup.sh /dev/sda4 [имя_тома]   (имя по умолчанию: w420data)
set -euo pipefail

DEV="${1:-}"
NAME="${2:-w420data}"
[ -n "$DEV" ] || { echo "использование: sudo $0 /dev/sdXN [имя]" >&2; exit 1; }
[ -b "$DEV" ] || { echo "нет устройства $DEV" >&2; exit 1; }

read -r -p "Зашифровать $DEV как LUKS2 том '$NAME'? ВСЕ ДАННЫЕ НА НЁМ БУДУТ УНИЧТОЖЕНЫ [y/N]: " ans
[ "$ans" = "y" ] || exit 0

command -v cryptsetup >/dev/null || { apt-get update && apt-get install -y cryptsetup; }

# 1) создаём LUKS2-контейнер (пароль спросит cryptsetup дважды)
cryptsetup luksFormat --type luks2 "$DEV"
# 2) открываем
cryptsetup luksOpen "$DEV" "$NAME"
# 3) файловая система
mkfs.ext4 -L "$NAME" "/dev/mapper/$NAME"
# 4) монтируем и прописываем в crypttab + fstab
mkdir -p "/mnt/$NAME"
mount "/dev/mapper/$NAME" "/mnt/$NAME"
grep -q "^$NAME " /etc/crypttab 2>/dev/null || echo "$NAME $DEV none luks" >> /etc/crypttab
grep -q "/mnt/$NAME" /etc/fstab 2>/dev/null || echo "/dev/mapper/$NAME /mnt/$NAME ext4 defaults,noatime 0 2" >> /etc/fstab

echo "[w420] LUKS-том '$NAME' готов: /dev/mapper/$NAME смонтирован в /mnt/$NAME"
echo "После перезагрузки: cryptsetup luksOpen $DEV $NAME && mount /dev/mapper/$NAME /mnt/$NAME"

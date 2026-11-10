#!/usr/bin/env bash
# build_deb.sh — сборка .deb пакета W420 из релизной сборки.
# Использование: ./scripts/build_deb.sh [путь-к-бинарнику]
# Результат: packaging/w420_<версия>_amd64.deb
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

BIN="${1:-${W420_TARGET_DIR:-$HOME/build/cache/cargo-target-w420}/release/w420}"
[ -x "$BIN" ] || { echo "бинарник не найден: $BIN (сначала cargo build --release)" >&2; exit 1; }

STAGE="$ROOT/packaging/deb"
VER="$(grep -m1 '^Version:' "$STAGE/DEBIAN/control" | awk '{print $2}')"
ARCH="$(grep -m1 '^Architecture:' "$STAGE/DEBIAN/control" | awk '{print $2}')"

# --- наполняем /opt/w420: бинарник, фронтенд, sidecar-бинарники, скрипты, голосовой сервер ---
install -Dm755 "$BIN" "$STAGE/opt/w420/w420"
# staging чистим от прошлых сборок (иначе остаётся вложенный dist/dist и старый UI)
rm -rf "$STAGE/opt/w420/dist" "$STAGE/opt/w420/tts-server"
cp -r "$ROOT/app/dist" "$STAGE/opt/w420/dist"
mkdir -p "$STAGE/opt/w420/binaries"
for b in sing-box trivy gitleaks; do
    src="$ROOT/app/src-tauri/binaries/$b"
    [ -f "$src" ] && install -Dm755 "$src" "$STAGE/opt/w420/binaries/$b"
done
[ -f "$ROOT/scripts/root_setup.sh" ] && install -Dm755 "$ROOT/scripts/root_setup.sh" "$STAGE/opt/w420/root_setup.sh"
[ -d "$ROOT/tts-server" ] && cp -r "$ROOT/tts-server" "$STAGE/opt/w420/tts-server"
# иконка
icon="$ROOT/app/src-tauri/icons/128x128.png"
[ -f "$icon" ] && install -Dm644 "$icon" "$STAGE/usr/share/icons/hicolor/256x256/apps/w420.png" \
             || install -Dm644 "$ROOT/app/src-tauri/icons/32x32.png" "$STAGE/usr/share/icons/hicolor/256x256/apps/w420.png"

# --- права и сборка ---
chmod 755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm"
find "$STAGE" -type d -exec chmod 755 {} +
find "$STAGE/DEBIAN" -type f -exec chmod 644 {} + ; chmod 755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm"
chown -R root:root "$STAGE" 2>/dev/null || true

OUT="$ROOT/packaging/w420_${VER}_${ARCH}.deb"
dpkg-deb --build "$STAGE" "$OUT"
echo "[w420] собрано: $OUT"
dpkg-deb -I "$OUT" | head -12

#!/usr/bin/env bash
# build_rpm.sh — сборка .rpm из spec (нужен rpmbuild; на Debian/Ubuntu: apt install rpm).
# Использование: ./scripts/build_rpm.sh
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

command -v rpmbuild >/dev/null || { echo "нет rpmbuild: sudo apt-get install -y rpm" >&2; exit 1; }
BIN="${W420_BIN:-${W420_TARGET_DIR:-$HOME/build/cache/cargo-target-w420}/release/w420}"
[ -x "$BIN" ] || { echo "нет бинарника $BIN" >&2; exit 1; }

BUILD="$ROOT/packaging/rpmbuild"
rm -rf "$BUILD"; mkdir -p "$BUILD"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
# tarball-источник: бинарник + dist + сервис + desktop
T="$BUILD/SOURCES/w420-1.0.0"
mkdir -p "$T"
install -m755 "$BIN" "$T/w420"
cp -r "$ROOT/app/dist" "$T/dist"
cp "$ROOT/packaging/deb/lib/systemd/system/w420.service" "$T/w420.service"
cp "$ROOT/packaging/deb/usr/share/applications/w420.desktop" "$T/w420.desktop"
cp "$ROOT/scripts/root_setup.sh" "$T/root_setup.sh" 2>/dev/null || true
tar -C "$BUILD/SOURCES" -czf "$BUILD/SOURCES/w420-1.0.0.tar.gz" w420-1.0.0
cp "$ROOT/packaging/w420.spec" "$BUILD/SPECS/"

# Debian/Ubuntu rpm не инициализирует БД и не знает _dbpath/_unitdir — задаём явно
rpm --define "_dbpath $BUILD/db" --initdb 2>/dev/null || true
rpmbuild -bb "$BUILD/SPECS/w420.spec" \
    --define "_topdir $BUILD" \
    --define "_dbpath $BUILD/db" \
    --define "_unitdir /usr/lib/systemd/system" \
    --define "_datadir /usr/share" \
    --define "_unitdir /lib/systemd/system"
echo "[w420] rpm готов: $BUILD/RPMS/*/w420-1.0.0-1.*.rpm"

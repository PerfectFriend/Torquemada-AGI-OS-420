#!/usr/bin/env bash
# Linux: lets the bundled sing-box create a TUN device (system-wide VPN mode) without running the whole app as root.
# File capabilities belong to the file: run again after every rebuild (a rebuilt sidecar is a new file).
set -euo pipefail
command -v setcap >/dev/null || { echo "нужен setcap (пакет libcap2-bin / libcap)"; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; n=0
for f in "$@" "$ROOT"/app/src-tauri/target/release/sing-box "$ROOT"/app/src-tauri/target/debug/sing-box "$ROOT"/app/src-tauri/binaries/sing-box-*-linux-gnu /opt/*/sing-box /usr/lib/*/sing-box; do
  [ -f "$f" ] || continue
  echo "setcap: $f"; sudo setcap cap_net_admin,cap_net_bind_service,cap_net_raw+ep "$f"; n=$((n+1))
done
[ "$n" -gt 0 ] || { echo "sing-box не найден: сначала node tools/fetch-sidecars.mjs и сборка, либо передайте путь аргументом"; exit 1; }
echo "Готово: файлов с правами для TUN: $n"

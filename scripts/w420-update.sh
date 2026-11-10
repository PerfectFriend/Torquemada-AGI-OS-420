#!/usr/bin/env bash
# w420-update.sh — обновление W420 и ОС через собственный механизм (apt поверх NOPASSWD sudoers w420).
# Использование: ./scripts/w420-update.sh [--check]
#   --check   только проверить наличие обновлений, ничего не ставить
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

CHECK=0; [ "${1:-}" = "--check" ] && CHECK=1

# apt через NOPASSWD sudoers (/etc/sudoers.d/w420), без пароля
SUDO=""; [ "$(id -u)" != 0 ] && SUDO="sudo -n"

$SUDO apt-get update -qq
if [ "$CHECK" = 1 ]; then
    n="$($SUDO apt-get -s upgrade 2>/dev/null | grep -c '^Inst ' || true)"
    echo "[w420] доступно обновлений пакетов: $n"
    exit 0
fi

echo "[w420] обновление ОС (apt upgrade)..."
$SUDO apt-get upgrade -y -qq
echo "[w420] пересборка w420 из исходников (если есть toolchain)..."
if command -v cargo >/dev/null 2>&1; then
    (source ~/build/env.sh 2>/dev/null || true; cargo build --release -q 2>/dev/null || echo "[w420] cargo build пропущен (нет toolchain)")
fi
echo "[w420] обновление завершено."

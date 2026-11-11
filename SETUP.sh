#!/usr/bin/env bash
# SETUP.sh — Торквемада 228 AGI: одномоментная установка с GitHub (без ISO).
# Использование: bash SETUP.sh [--from-release] [--skip-root] [--help]
# Результат: бинарник + фронтенд + автозагрузка + (опционально) настройка привилегий.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"
HOME_DIR="${HOME:-/home/thomas}"
W420_DIR="$HOME_DIR/.w420"
BIN_DIR="$HOME_DIR/.w420"
DESKTOP_DIR="$HOME_DIR/.local/share/applications"
USER_SYSTEMD="$HOME_DIR/.config/systemd/user"
LOG="$W420_DIR/setup.log"

info()  { printf '\033[1;34m→ %s\033[0m\n' "$1" | tee -a "$LOG"; }
ok()   { printf '\033[1;32m✔ %s\033[0m\n' "$1" | tee -a "$LOG"; }
warn() { printf '\033[1;33m⚠ %s\033[0m\n' "$1" | tee -a "$LOG"; }
err()  { printf '\033[1;31m✘ %s\033[0m\n' "$1" | tee -a "$LOG"; }

# --------------------------------------------------------------
# Проверки окружения
# --------------------------------------------------------------
req() { command -v "$1" >/dev/null 2>&1 || { warn "не хватает: $1"; MISSING="$MISSING $1"; }; }
info "Проверка зависимостей..."
req git; req curl; req jq; req sudo; req grep; req sed
if [[ -z "${W420_SKIP_BUILD:-}" ]]; then
    req cargo; req node
fi
if [[ -n "${MISSING:-}" ]]; then
    warn "некоторые зависимости отсутствуют; попробуйте:"
    if [[ -f /etc/os-release ]] && grep -q -i "ubuntu\|debian" /etc/os-release; then
        echo "   sudo apt-get install -y git curl jq sudo build-essential nodejs cargo"
    elif [[ -f /etc/os-release ]] && grep -q -i "fedora\|rhel\|centos" /etc/os-release; then
        echo "   sudo dnf install -y git curl jq sudo gcc cargo nodejs"
    else
        echo "   установите git, curl, jq, sudo, cargo (Rust), nodejs вручную"
    fi
fi

# --------------------------------------------------------------
# Клонируем репозиторий, если не на месте
# --------------------------------------------------------------
REPO="${W420_REPO:-https://github.com/PerfectFriend/Torquemada-AGI-OS-420}"
if [[ ! -d "$ROOT/.git" ]]; then
    info "клонирование репозитория $REPO → $ROOT"
    # если скрипт запущен из уже склонированной копии — пропускаем
fi
BRANCH="${W420_BRANCH:-main}"
git -C "$ROOT" fetch -q origin || true
git -C "$ROOT" checkout -q "$BRANCH" || true

# --------------------------------------------------------------
# Сборка или загрузка бинарника
# --------------------------------------------------------------
if [[ "${W420_FROM_RELEASE:-}" == "1" ]]; then
    info "загрузка релизного бинарника из GitHub..."
    REPO_OWNER="${W420_REPO_OWNER:-PerfectFriend}"
    REPO_NAME="${W420_REPO_NAME:-Torquemada-AGI-OS-420}"
    # ищем самый свежий релиз
    LATEST=$(curl -s "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest" \
        | jq -r '.assets[] | select(.name | test("deb$")) | .browser_download_url' \
        | head -1)
    if [[ -n "$LATEST" ]]; then
        DEB=$(mktemp /tmp/w420_XXXXXX.deb)
        curl -sL "$LATEST" -o "$DEB"
        DPKG_DIR=$(mktemp -d)
        dpkg-deb -x "$DEB" "$DPKG_DIR" >/dev/null
        rm -rf "$W420_DIR"/opt/w420/{dist,tts-server} || true
        cp -r "$DPKG_DIR/opt/w420" "$W420_DIR/"
        cp "$DPKG_DIR/usr/share/icons/hicolor/256x256/apps/w420.png" \
           "$ROOT/app/src-tauri/icons/128x128.png" 2>/dev/null || true
        rm -rf "$DEB" "$DPKG_DIR"
        ok "бинарник загружен из релиза"
    else
        warn "деб-пакет в релизе не найден → собираем сами"
        W420_FROM_RELEASE=0
    fi
fi

if [[ "${W420_FROM_RELEASE:-}" != "1" ]]; then
    info "сборка release-бинарника..."
    source "$HOME/build/env.sh" 2>/dev/null || true
    cargo build --release -q 2>&1 | tail -1 || {
        err "cargo build не удался; проверьте логи выше"; exit 1
    }
    BIN="$(find . -path '*/target/release/w420' -type f 2>/dev/null | head -1)"
    if [[ -z "$BIN" || ! -x "$BIN" ]]; then
        err "бинарник не найден: $BIN"; exit 1
    fi
    rm -rf "$W420_DIR/opt/w420" "$W420_DIR/binaries"
    install -Dm755 "$BIN" "$W420_DIR/opt/w420/w420"
    rm -rf "$W420_DIR/dist"
    cp -r "$ROOT/app/dist" "$W420_DIR/dist"
    ok "бинарник собран: $W420_DIR/opt/w420/w420"
fi

mkdir -p "$BIN_DIR" "$DESKTOP_DIR" "$USER_SYSTEMD" "$W420_DIR/binaries"

# --------------------------------------------------------------
# Sidecar-бинарники (включить/скачать по требованию)
# --------------------------------------------------------------
for b in sing-box trivy gitleaks; do
    if [[ -f "$ROOT/app/src-tauri/binaries/$b" ]]; then
        install -Dm755 "$ROOT/app/src-tauri/binaries/$b" "$W420_DIR/binaries/$b"
    elif [[ ! -x "$W420_DIR/binaries/$b" ]]; then
        warn "sidecar $b не найден в репе — скопируйте вручную в app/src-tauri/binaries/$b"
    fi
done

# --------------------------------------------------------------
# Иконки
# --------------------------------------------------------------
ICON_SRC="$ROOT/app/src-tauri/icons/128x128.png"
if [[ -f "$ICON_SRC" ]]; then
    install -Dm644 "$ICON_SRC" "$DESKTOP_DIR/../icons/hicolor/128x128/apps/torquemada-228.png" 2>/dev/null || true
fi

# --------------------------------------------------------------
# Автозагрузка: desktop file + systemd --user
# --------------------------------------------------------------
info "настройка автозагрузки..."
cat > "$DESKTOP_DIR/torquemada-228-desktop-agi.desktop" <<EOF
[Desktop Entry]
Name=Torquemada 228 AGI
Name[ru]=Торквемада 228 AGI
Name[en]=Torquemada 228 AGI
Name[es]=Torquemada 228 AGI
Comment=Автономная OS кибербезопасности с материнским ИИ (Madre)
Comment[ru]=Автономная ОС кибербезопасности с управляющим ИИ «Мать Торквемада»
Exec=$W420_DIR/opt/w420/w420 %U
Terminal=false
Type=Application
Categories=Security;Utility;
StartupWMClass=Torquemada228AGI
Icon=torquemada-228
X-GNOME-Autostart-enabled=true
EOF
ln -sfn "$DESKTOP_DIR/torquemada-228-desktop-agi.desktop" "$HOME_DIR/.config/autostart/" 2>/dev/null || true

cat > "$USER_SYSTEMD/torquemada-228-agi.service" <<EOF
[Unit]
Description=Torquemada 228 AGI — cybersecurity OS
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=$W420_DIR/opt/w420/w420
Restart=on-failure
RestartSec=5
Environment=HOME=$HOME_DIR
Environment=W420_DATA=$W420_DIR

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload >/dev/null 2>&1 || true
systemctl --user enable --now torquemada-228-agi.service >/dev/null 2>&1 || \
    info "systemd-юнит создан вручную — активируйте: systemctl --user enable --now torquemada-228-agi.service"

# --------------------------------------------------------------
# Настройка привилегий (только по согласию пользователя)
# --------------------------------------------------------------
if [[ "${W420_SKIP_ROOT:-}" != "1" ]]; then
    echo
    printf 'Требуется настройка прав (nftables base + narrow NOPASSWD sudo для %s).\n' "${SUDO_USER:-root}"
    printf 'Выполнить root_setup.sh? (y/N): '
    read -r ans </dev/tty
    if [[ "${ans,,}" == "y" ]]; then
        bash "$ROOT/scripts/root_setup.sh"
        ok "права настроены (см. root_setup.sh для деталей)"
    else
        warn "root-шаг пропущен — привилегированные команды потребуют sudo каждый раз"
    fi
fi

echo
info "установка завершена:"
echo "   бинарник: $W420_DIR/opt/w420/w420"
echo "   данные:   $W420_DIR"
echo "   автозагрузка: $DESKTOP_DIR/torquemada-228-desktop-agi.desktop"
echo "   язык по умолчанию: ru (меняется в меню Настройки)"
echo "   первый запуск: запустите 'w420' из терминала или через меню"

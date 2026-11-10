#!/usr/bin/env bash
# WINDOWS 420 — установщик для Linux и macOS. Подробности: README.md
set -euo pipefail
cd "$(dirname "$0")"

YES=0; DRY=0; NET=0; ANDROID=0; MODE=setup; SC=1; TTS=0; TOS=0
usage(){ cat <<'U'
Использование: ./install.sh [опции]
  --yes, -y        не спрашивать подтверждение
  --dry-run        только показать, что будет сделано; ничего не менять
  --with-network   дополнительно поставить Tor и Tailscale (нужны для следующих фаз)
  --android        добавить цели Rust для Android и выполнить `tauri android init`
                   (нужны Android Studio, NDK и переменная ANDROID_HOME)
  --no-shortcut    не создавать ярлыки
  --with-tts       поставить голосовой движок XTTS (озвучка радио, клонирование голоса): 3-7 ГБ
  --accept-xtts-license  принять лицензию XTTS (CPML, только некоммерческое использование)
                   и сразу скачать модель (около 1,8 ГБ); без флага модель скачается из приложения
  --dev            после установки запустить приложение в режиме разработки
  --build          после установки собрать релизные пакеты
U
}
for a in "$@"; do case "$a" in
  -y|--yes) YES=1;; --dry-run) DRY=1;; --with-network) NET=1;; --android) ANDROID=1;; --no-shortcut) SC=0;; --with-tts) TTS=1;; --accept-xtts-license) TTS=1; TOS=1;;
  --dev) MODE=dev;; --build) MODE=build;; -h|--help) usage; exit 0;;
  *) echo "неизвестная опция: $a"; usage; exit 1;; esac; done

say(){ printf '\033[32m[W420]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[W420] %s\033[0m\n' "$*"; }
die(){ printf '\033[31m[W420] %s\033[0m\n' "$*" >&2; exit 1; }
run(){ if [ "$DRY" = 1 ]; then echo "  [dry-run] $*"; else "$@"; fi }
have(){ command -v "$1" >/dev/null 2>&1; }
[ "$DRY" = 1 ] || exec > >(tee -a install.log) 2>&1

SUDO=""; [ "$(id -u)" != 0 ] && SUDO="sudo"
OS="$(uname -s)"; PM=""
if [ "$OS" = Darwin ]; then PM=brew
elif [ "$OS" = Linux ]; then
  [ -r /etc/os-release ] && . /etc/os-release
  case " ${ID:-} ${ID_LIKE:-} " in
    *debian*|*ubuntu*) PM=apt;; *fedora*|*rhel*|*centos*) PM=dnf;; *arch*) PM=pacman;; esac
else die "Эта ОС не поддерживается скриптом. На Windows используй install.bat"; fi
[ -n "$PM" ] || die "Дистрибутив не распознан (поддерживаются Debian/Ubuntu, Fedora/RHEL, Arch, macOS)."

say "ОС: $OS, менеджер пакетов: $PM"
cat <<PLAN
План:
  1. системные пакеты для сборки Tauri 2 ($PM)$( [ "$PM" = pacman ] && echo ', включая полное обновление системы (-Syu)')
  2. Rust (rustup, профиль minimal), если не установлен
  3. Node.js 18+ и npm, если не установлены
  4. $( [ "$NET" = 1 ] && echo 'Tor и Tailscale' || echo '(Tor и Tailscale пропущены: добавь --with-network)')
  5. конфиги: w420.config.json, rust-toolchain.toml, .gitignore
  6. npm install и генерация иконок
  7. $( [ "$TTS" = 1 ] && echo "голосовой движок XTTS (venv, PyTorch<2.9, coqui-tts)$( [ "$TOS" = 1 ] && echo ", модель 1,8 ГБ" )" || echo "(голосовой движок XTTS пропущен: добавь --with-tts)")
  8. ярлыки на рабочем столе и в меню приложений$( [ "$SC" = 1 ] || echo " (пропущены)")
PLAN
if [ "$YES" = 0 ] && [ "$DRY" = 0 ]; then read -r -p "Продолжить? [y/N] " r; [[ "$r" =~ ^[Yy]$ ]] || exit 0; fi

node_ok(){ have node && [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 18 ]; }

say "1/6 системные пакеты"
case "$PM" in
  apt) run $SUDO apt-get update
       run $SUDO apt-get install -y build-essential curl wget file git libwebkit2gtk-4.1-dev libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev;;
  dnf) run $SUDO dnf install -y webkit2gtk4.1-devel openssl-devel curl wget file git libappindicator-gtk3-devel librsvg2-devel libxdo-devel
       run $SUDO dnf group install -y "Development Tools";;
  pacman) run $SUDO pacman -Syu --needed --noconfirm webkit2gtk-4.1 base-devel curl wget file git openssl xdotool libappindicator-gtk3 librsvg;;
  brew) have brew || die "Homebrew не найден. Установи его с https://brew.sh и запусти скрипт снова."
        xcode-select -p >/dev/null 2>&1 || run xcode-select --install;;
esac

say "2/6 Rust (нужна версия 1.90+: свежий Tauri 2 не собирается на более старой)"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
rust_ok(){ have rustc && local v && v="$(rustc --version | awk '{print $2}')" && [ "$(printf '%s\n1.90.0\n' "$v" | sort -V | head -1)" = "1.90.0" ]; }
if ! have rustup; then
  warn "rustup не найден: ставлю (системный Rust из apt/dnf обычно слишком старый)"
  if [ "$DRY" = 1 ]; then echo "  [dry-run] curl https://sh.rustup.rs | sh -s -- -y --profile minimal"
  else curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal; fi
  [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
fi
if have rustup || [ "$DRY" = 0 ]; then
  run rustup toolchain install stable --profile minimal
  run rustup default stable
fi
if [ "$DRY" = 0 ] && ! rust_ok; then
  die "Rust слишком старый: $(rustc --version 2>/dev/null || echo не найден). Нужен 1.90+. Выполни: rustup update stable   (и убедись, что ~/.cargo/bin стоит в PATH раньше /usr/bin)"
fi

say "3/6 Node.js"
if ! node_ok; then
  case "$PM" in apt) run $SUDO apt-get install -y nodejs npm;; dnf) run $SUDO dnf install -y nodejs npm;;
    pacman) run $SUDO pacman -S --needed --noconfirm nodejs npm;; brew) run brew install node;; esac
  if [ "$DRY" = 0 ] && ! node_ok; then
    die "Node.js слишком старый или не найден (нужен 18+). Поставь актуальную версию через https://nodejs.org или nvm и запусти скрипт снова."; fi
else say "Node $(node -v) подходит"; fi

say "4/6 сеть (Tor, Tailscale)"
if [ "$NET" = 1 ]; then
  case "$PM" in apt) run $SUDO apt-get install -y tor;; dnf) run $SUDO dnf install -y tor;;
    pacman) run $SUDO pacman -S --needed --noconfirm tor tailscale;; brew) run brew install tor; run brew install --cask tailscale;; esac
  if [ "$PM" != pacman ] && [ "$PM" != brew ]; then
    warn "Tailscale на $PM ставится официальным скриптом: https://tailscale.com/download — установи вручную, когда понадобится."; fi
else say "пропущено"; fi

say "5/6 конфиги"
for f in "w420.config.json:app/w420.config.json" "rust-toolchain.toml:app/src-tauri/rust-toolchain.toml" "gitignore:app/.gitignore"; do
  src="config/${f%%:*}"; dst="${f##*:}"
  if [ -f "$dst" ]; then say "уже есть: $dst (не трогаю)"; else run cp "$src" "$dst"; fi
done

say "6/6 зависимости и иконки"
( cd app && run npm install --no-fund --no-audit )
say "встроенные движки моста: sing-box (проверка SHA-256)"
run node tools/fetch-sidecars.mjs
[ -f app/src-tauri/icons/icon.ico ] || ( cd app && run npx tauri icon ../assets/app-icon.png )

if [ "$ANDROID" = 1 ]; then
  say "Android"
  run rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
  if [ -z "${ANDROID_HOME:-}" ]; then warn "ANDROID_HOME не задан: установи Android Studio + NDK и запусти: cd app && npx tauri android init"
  else ( cd app && run npx tauri android init ); fi
fi

find_py(){ local c v; for c in python3.13 python3.12 python3.11 python3.10 python3; do have "$c" || continue
  v="$("$c" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)"
  case "$v" in 3.10|3.11|3.12|3.13) echo "$c"; return 0;; esac; done; return 1; }

write_tts_config(){ # $1 = путь к python из venv
  local d="$HOME/.w420"
  if [ "$DRY" = 1 ]; then echo "  [dry-run] write $d/tts.json (python=$1, dir=$PWD/tts-server, port=8420)"; return; fi
  mkdir -p "$d"; printf '{"python": "%s", "dir": "%s", "port": 8420}\n' "$1" "$PWD/tts-server" > "$d/tts.json"; }

setup_tts(){
  say "голосовой движок XTTS: понадобится 3-7 ГБ на диске"
  case "$PM" in
    apt) run $SUDO apt-get install -y python3-venv python3-pip;;
    dnf) run $SUDO dnf install -y python3 python3-pip;;
    pacman) run $SUDO pacman -S --needed --noconfirm python python-pip;;
    brew) have python3.12 || run brew install python@3.12;;
  esac
  local PY; if ! PY="$(find_py)"; then
    [ "$DRY" = 1 ] && PY=python3 || die "Нужен Python 3.10-3.13 (3.14 пока не поддерживается PyTorch 2.8). Поставь его и запусти скрипт снова."; fi
  local V="$PWD/tts-server/.venv" VPY="$PWD/tts-server/.venv/bin/python" IDX=""
  run "$PY" -m venv "$V"
  run "$VPY" -m pip install --upgrade pip
  if [ "$OS" = Linux ]; then
    IDX="https://download.pytorch.org/whl/cpu"
    if have nvidia-smi && nvidia-smi -L >/dev/null 2>&1; then IDX="https://download.pytorch.org/whl/cu128"; say "найдена видеокарта NVIDIA: ставлю PyTorch с CUDA"; else say "видеокарты NVIDIA нет: ставлю PyTorch для процессора (озвучка будет медленнее реального времени)"; fi
  fi
  [ -n "${W420_TORCH_INDEX:-}" ] && IDX="$W420_TORCH_INDEX"
  if [ -n "$IDX" ]; then run "$VPY" -m pip install "torch>=2.2,<2.9" "torchaudio>=2.2,<2.9" --index-url "$IDX"
  else run "$VPY" -m pip install "torch>=2.2,<2.9" "torchaudio>=2.2,<2.9"; fi
  run "$VPY" -m pip install -r tts-server/requirements.txt
  run "$VPY" -c "import TTS, torch; print('XTTS: библиотеки на месте, CUDA:', torch.cuda.is_available())"
  write_tts_config "$VPY"
  if [ "$TOS" = 1 ]; then
    say "скачиваю модель XTTS-v2 (лицензия CPML принята флагом --accept-xtts-license)"
    if [ "$DRY" = 1 ]; then echo "  [dry-run] COQUI_TOS_AGREED=1 python -c 'TTS(xtts_v2)'"
    else COQUI_TOS_AGREED=1 "$VPY" -c "from TTS.api import TTS; TTS('tts_models/multilingual/multi-dataset/xtts_v2', progress_bar=True)"; fi
  else say "модель скачается при первом запуске движка в приложении (после подтверждения лицензии)"; fi
}

make_shortcuts(){
  local APP="$PWD/app" ICON="$PWD/assets/app-icon-512.png" LAUNCH="$PWD/launch.sh"
  local BIN="$APP/src-tauri/target/release/w420" CMD TERM=false
  if [ -x "$BIN" ]; then CMD="$BIN"; else CMD="$LAUNCH"; TERM=true; warn "приложение ещё не собрано: ярлык запустит режим разработки (долгий первый старт). Для автономного ярлыка: ./install.sh --build"; fi
  if [ "$OS" = Linux ]; then
    local DESK; DESK="$(xdg-user-dir DESKTOP 2>/dev/null || true)"; [ -n "$DESK" ] || DESK="$HOME/Desktop"
    local MENU="$HOME/.local/share/applications/w420.desktop"
    for f in "$MENU" "$DESK/w420.desktop"; do
      [ "$f" = "$DESK/w420.desktop" ] && [ ! -d "$DESK" ] && continue
      if [ "$DRY" = 1 ]; then echo "  [dry-run] write $f"; continue; fi
      mkdir -p "$(dirname "$f")"
      cat > "$f" <<D
[Desktop Entry]
Type=Application
Name=Windows 420
Comment=AGI OS
Exec="$CMD"
Icon=$ICON
Terminal=$TERM
Categories=Utility;System;
StartupWMClass=w420
D
      chmod +x "$f"; have gio && gio set "$f" metadata::trusted true 2>/dev/null || true
    done
  else
    local DESK="$HOME/Desktop" APPB="$APP/src-tauri/target/release/bundle/macos/Windows420.app"
    if [ -d "$APPB" ]; then run ln -sfn "$APPB" "$DESK/Windows 420.app"
    elif [ "$DRY" = 1 ]; then echo "  [dry-run] write $DESK/Windows 420.command"
    else printf '#!/bin/bash\nexec "%s"\n' "$LAUNCH" > "$DESK/Windows 420.command"; chmod +x "$DESK/Windows 420.command"; fi
  fi
}

[ "$TTS" = 1 ] && setup_tts
[ "$MODE" = build ] && { say "сборка (несколько минут)"; ( cd app && run npm run tauri build ); }
if [ "$SC" = 1 ]; then say "ярлыки"; make_shortcuts; fi
case "$MODE" in
  dev)   say "запуск в режиме разработки"; ( cd app && run npm run tauri dev );;
  build) say "готово: ярлык ведёт на собранное приложение";;
  *)     say "готово. Запуск: ярлык «Windows 420» на рабочем столе или ./launch.sh";;
esac

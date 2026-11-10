#!/usr/bin/env bash
# Запуск W420: собранное приложение, если оно есть, иначе сообщение об ошибке.
cd "$(dirname "$0")" || exit 1
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
source "$HOME/build/env.sh" 2>/dev/null || true

# Реальный путь к собранному бинарнику. У W420 свой target-каталог:
# общий cargo-target делился с NeXXus и сборка одного проекта сносила бинари другого.
BINARY="${W420_TARGET_DIR:-$HOME/build/cache/cargo-target-w420}/release/w420"
if [ -x "$BINARY" ]; then
    exec "$BINARY"
elif [ -x "app/src-tauri/target/release/w420" ]; then
    cd app || exit 1
    exec src-tauri/target/release/w420
else
    echo "W420 binary not found. Build with: cargo build --release"
    exit 1
fi

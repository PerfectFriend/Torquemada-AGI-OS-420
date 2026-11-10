#!/usr/bin/env bash
# Запуск W420: собранное приложение, если оно есть, иначе сообщение об ошибке.
cd "$(dirname "$0")" || exit 1
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
source "$HOME/build/env.sh" 2>/dev/null || true

# Реальный путь к собранному бинарнику. У W420 свой target-каталог:
# общий cargo-target делился с NeXXus и сборка одного проекта сносила бинари другого.
# Проверяем в порядке: выделенный w420-кэш → общий кэш → локальная ссылка ./w420 → локальный target.
for BINARY in \
    "${W420_TARGET_DIR:-$HOME/build/cache/cargo-target-w420}/release/w420" \
    "$HOME/build/cache/cargo-target/release/w420" \
    "$(dirname "$0")/w420" \
    "$HOME/TorquemadaAGI/app/src-tauri/target/release/w420"; do
    if [ -x "$BINARY" ]; then
        exec "$BINARY"
    fi
done
echo "W420 binary not found. Build with: cargo build --release"
exit 1

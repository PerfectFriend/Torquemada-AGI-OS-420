# Setup Torquemada 228 AGI — руководство по установке (RC1)

[← назад в README](README.md)

**Цель RC1:** Torquemada 228 AGI — это открытый проект, который любой может скачать и установить с GitHub **одним автоматическим скриптом**. Без ISO, без сложных шагов, с автозагрузкой и прозрачной установкой зависимостей.

---

## 🚀 Быстрый старт

```bash
git clone https://github.com/PerfectFriend/Torquemada-AGI-OS-420
cd TorquemadaAGI
bash SETUP.sh
```

Далее — следуйте интерактивным подсказкам `SETUP.sh`. Для установки релизного бинарника вместо сборки:

```bash
bash SETUP.sh --from-release
```

---

## 📋 Что делает SETUP.sh

1. **Проверка окружения** — наличие `git`, `curl`, `jq`, `sudo`, `cargo`, `node`. Если чего-то не хватает: показывает команду установки для вашей ОС (Ubuntu/Debian или Fedora/RHEL).
2. **Клонирование** — берёт репозиторий с `main` (переменная `W420_REPO`).
3. **Бинарник** — либо загружает `w420_1.0.0_amd64.deb` из последнего GitHub-релиза, либо собирает `cargo build --release` из исходников.
4. **Фронтенд** — копирует `app/dist` в `~/.w420/dist`.
5. **Sidecar-бинарники** — `sing-box`, `trivy`, `gitleaks` (из `app/src-tauri/binaries/`).
6. **Автозагрузка** — создаёт `.desktop` файл и `systemd --user` юнит; регистрирует в `~/.config/autostart/`.
7. **root_setup.sh** (по согласию) — `setcap` для tcpdump, narrow NOPASSWD sudo, apt-пакеты (nmap, suricata), тестовая проверка nftables.

### Переменные окружения

| Переменная | Значение по умолчанию | Описание |
|---|---|---|
| `W420_REPO` | `https://github.com/PerfectFriend/Torquemada-AGI-OS-420` | Репозиторий для клонирования |
| `W420_BRANCH` | `main` | Ветка |
| `W420_FROM_RELEASE` | `0` | `1` → грузить deb из GitHub Releases |
| `W420_SKIP_ROOT` | `0` | `1` → пропустить root_setup.sh |
| `W420_SKIP_BUILD` | `""` | задать путь к готовому бинарнику |

Пример: `W420_FROM_RELEASE=1 W420_SKIP_ROOT=1 bash SETUP.sh` — только загрузить deb, без root-шага.

---

## 🔧 root_setup.sh — права и привилегии

Запускается **пользователем от своего имени**: `sudo bash root_setup.sh`. Пароль sudo вводится локально, никуда не передаётся.

### Что он делает

| Шаг | Действие |
|---|---|
| 1 | `setcap` для `/usr/bin/tcpdump` / `nft` — захват пакетов без sudo |
| 2 | `/etc/sudoers.d/w420` — narrow NOPASSWD: `nft`, `tcpdump`, `wg`, `ip`, `apt-get` |
| 3 | `apt-get install nmap suricata` (sidecar-инструменты) |
| 4 | Живая проверка: атомарное применение/снятие test-таблицы nft |
| 5 | Права на `~/.w420` — владение `thomas:thomas` |

### Безопасность

- Пароль sudo **никогда** не попадает в приложение, логи или чат.
- NOPASSWD ограничен узким набором команд (файл в `/etc/sudoers.d/w420`, режим 440).
- Проверка `visudo -c` гарантирует валидность конфига.

---

## 🎮 Первый запуск

После установки запустите:

```bash
~/.w420/opt/w420/w420
```

или откройте из меню приложений **«Торквемада 228 AGI»**.

Приложения в трее:
- Закрытие окна сворачивает в трей, полный выход — «Выход».
- Уведомления о запросах APPROVE/REJECT.

---

## 🌍 Язык

По умолчанию — русский. Переключить: **Настройки → язык** (доступны RU / EN / ES), изменение применяется мгновенно ко всему интерфейсу и голосовому движку.

---

## ❓ Устранение проблем

| Проблема | Решение |
|---|---|
| `cargo build` не удаётся — «requires rustc 1.90+» | `source ~/build/env.sh` или `rustup update stable` |
| Node.js старый из apt | Поставить актуальный через `nvm` / NodeSource |
| Sidecar `sing-box` не найден | Скопируйте бинарник в `app/src-tauri/binaries/sing-box` |
| Уведомления не приходят | Разрешите уведомления системе (особенно macOS / GNOME без AppIndicator) |
| Автозагрузка не сработала | Проверьте `~/.config/autostart/torquemada-228-desktop-agi.desktop` и `systemctl --user status torquemada-228-agi` |

---

## 📂 Куда ставить

| Элемент | Путь |
|---|---|
| Бинарник | `~/.w420/opt/w420/w420` |
| Данные | `~/.w420/` (madre.db, siem.db, edr.db, settings.json) |
| Фронтенд | `~/.w420/dist/` |
| Sidecars | `~/.w420/binaries/` |
| Автозагрузка | `~/.local/share/applications/torquemada-228-desktop-agi.desktop` |
| systemd юнит | `~/.config/systemd/user/torquemada-228-agi.service` |

---

## 📥 Получить

- Репозиторий: https://github.com/PerfectFriend/Torquemada-AGI-OS-420
- Релизы (deb): https://github.com/PerfectFriend/Torquemada-AGI-OS-420/releases
- План RC1: [RC1-PLAN.md](RC1-PLAN.md)

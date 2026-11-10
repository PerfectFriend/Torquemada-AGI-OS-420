# W420 Install — Техническая документация

## Обзор проекта

W420 Install — кибербезопасностная ОС на базе AI с архитектурой Tauri v2 (Rust бэкенд + HTML/CSS тонкий клиент). Проект включает:

- **W420 Core** — типы, ошибки, генерация конфигурации
- **W420 AI** — абстракция AI-провайдеров (9 провайдеров), ротация ключей, шифрование, БД, тестирование
- **W420 Installer** — установщик системы
- **TTS-Rust** — TTS сервер на espeak-ng
- **Tauri бэкенд** — админка хостов, мониторинг угроз, AI-движок безопасности, сисопс, бридж, тор

## Архитектура

```
W420 Install Workspace
├── crates/w420-core      — базовые типы и ошибки
├── crates/w420-ai        — AI-провайдеры, ротация, шифрование, БД, тестирование
├── crates/w420-installer — установщик
├── crates/tts-rust       — TTS сервер
└── app/src-tauri         — Tauri бэкенд (все invoke команды)
```

## Модули Tauri бэкенда

### 1. Hosts (DameWare-like админка хостов)
**Файл:** `app/src-tauri/src/hosts.rs`

Управление удалёнными хостами через SSH:
- Добавление/удаление хостов с шифрованием учётных данных (AES-256-GCM)
- Проверка статуса хоста (TCP подключение к SSH порту + измерение latency)
- Выполнение команд на хостах через системный SSH клиент
- Управление активными сессиями (подключение/отключение)

**Команды invoke:**
- `hosts_add` — добавить хост
- `hosts_list` — список хостов
- `hosts_remove` — удалить хост
- `hosts_get` — информация о хосте
- `hosts_status` — статус одного хоста
- `hosts_status_all` — статус всех хостов
- `hosts_exec` — выполнение команды по SSH
- `hosts_connect` — подключение к хосту
- `hosts_disconnect` — отключение от хоста

**База данных:** `~/.w420/hosts.db` (SQLite, таблица `hosts`)

### 2. Threats (Мониторинг киберугроз)
**Файл:** `app/src-tauri/src/threats.rs`

Отслеживание CVE уязвимостей и киберугроз:
- Хранение уязвимостей в SQLite базе
- Сканирование системы (dpkg-query, rpm, apk, brew) и сопоставление с уязвимостями
- Генерация алертов для критических и высокоуровневых угроз
- Синхронизация из внешних источников (NVD, GitHub Advisories, OSV)

**Команды invoke:**
- `threats_scan` — сканирование системы
- `threats_last_scan` — результат последнего сканирования
- `threats_list` — список уязвимостей с фильтром
- `threats_alerts` — список алертов
- `threats_acknowledge_alert` — подтверждение алерта
- `threats_sync` — синхронизация из внешних источников
- `threats_sources` — список источников угроз

**База данных:** `~/.w420/threats.db` (SQLite, таблицы: cve_vulnerabilities, threat_alerts, threat_sources, scan_results)

### 3. Security AI (AI-движок безопасности)
**Файл:** `app/src-tauri/src/security_ai.rs`

Интеграция AI-провайдеров с функционалом безопасности:
- AI-анализ уязвимостей через все 9 провайдеров w420-ai
- Автоматическое принятие решений (block/patch/monitor/ignore)
- Генерация отчётов о безопасности с помощью AI
- Ротация ключей AI при запросах

**Команды invoke:**
- `security_ai_analyze` — AI-анализ уязвимости
- `security_ai_auto_response` — автоответ на угрозу
- `security_ai_report` — отчёт о безопасности
- `security_ai_config` — конфигурация
- `security_ai_set_config` — обновление конфигурации
- `security_ai_analyses` — история анализов
- `security_ai_auto_responses` — автоответы
- `security_ai_reports` — отчёты

**Конфигурация:** `~/.w420/security_ai.json`

## AI-провайдеры (w420-ai)

9 провайдеров с unified интерфейсом:

| Провайдер | Эндпоинт | Аутентификация |
|-----------|----------|----------------|
| OpenAI | api.openai.com/v1 | Bearer токен |
| Anthropic | api.anthropic.com/v1 | Bearer токен |
| Google | generativelanguage.googleapis.com | API ключ |
| Mistral | api.mistral.ai/v1 | Bearer токен |
| Groq | api.groq.com/openai/v1 | Bearer токен |
| Together | api.together.xyz/v1 | Bearer токен |
| OpenRouter | openrouter.ai/api/v1 | Bearer токен |
| Ollama | localhost:11434 | keine |
| NVIDIA NIM | integrate.api.nvidia.com/v1 | Bearer токен |

**Шифрование:** API-ключи шифруются AES-256-GCM с PBKDF2, соль в `~/.w420/ai_encryption_salt`

**База данных:** `~/.w420/ai_providers.db` (SQLite)

## Безопасность

- Все API-ключи шифруются на диске (AES-256-GCM)
- SSH учётные данные шифруются AES-256-GCM
- SQL инъекции предотвращены параметризованными запросами
- SSH подключение использует StrictHostKeyChecking=no для автоматизации
- TTS доступен только на 127.0.0.1 с токеном X-W420-Token
- sing-box mixed-inbound только на 127.0.0.1

## Сборка

```bash
source ~/build/env.sh
cd /home/thomas/w420-install
cargo build --release
```

Целевые пакеты: .deb, .rpm, .AppImage (требуется fpm/rpmbuild)

## Тестирование

```bash
cargo test --workspace  # все тесты workspace
cargo test -p w420-ai   # тесты AI-провайдеров (11/11)
cargo test -p w420 hosts # тесты админки хостов (2/2)
cargo test -p w420 threats # тесты мониторинга угроз (2/2)
cargo test -p w420 security_ai # тесты AI-движка (3/3)
```

Единственный известный проваленный тест: `sysops::tests::gitleaks_finds_the_planted_secret` (требует /tmp/scanme и gitleaks — существующая проблема до начала работы над Фазами 2-4).
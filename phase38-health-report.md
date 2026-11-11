# Phase 38 — Финал паритета DameWare: hosts_health dashboard

Коммит в `main` PerfectFriend/Torquemada-AGI-OS-420 · тесты: 188 passed / 0 failed (lib), +11 bin, +20 doctests · `cargo build --release` exit 0 · `node --check health.js` OK.

## Сделано
- **`health.rs`** (новый модуль):
  - `hosts_health(host_id)` — метрики хоста по SSH (best-effort: `uptime`, `free -m`, `df -P /`, `systemctl --failed`) + локальные события SIEM (за 1ч по src_ip) и EDR по IP хоста → интегральный **score 0..100** с грейдом HEALTHY / OK / DEGRADED / CRITICAL / OFFLINE + вердикт Матери (свой пакет — accept, чужой — DROP по allowlist `madre.json`).
  - `hosts_health_all()` — сводная таблица по всему инвентарю + разбивка по грейдам.
  - Чистые функции парсинга/score вынесены отдельно и покрыты тестами.
- **UI**: `health.js` + карточка «ЗДОРОВЬЕ ХОСТОВ» в v-net: «ОБНОВИТЬ ВСЕ», «ПРОВЕРИТЬ ОДИН», автообновление 30с, цветные грейды, вердикт Матери рядом.
- **План**: `DAMEWARE_PARITY_PLAN.md` — Этап 38 отмечен ✅ DONE 2026-11-11.

## Тесты (+6)
parse_load1 / parse_mem_pct / parse_disk_root_pct / parse_failed_services на реальных форматах вывода; health_score: offline→0, healthy→≥95 HEALTHY, degraded/critical <50, монотонность штрафов.

## Что осталось (не блокеры)
- ISO-сборка — по запросу (тяжёлая), .deb/.rpm пересобрать в конце.
- Live-проверка `hosts_health` против реального SSH-хоста — `#[ignore]`-сценарий, когда будет стенд.

# W420 — Фазы 8–9 + интеграция VibeVoice (2026-11-05)

## Фаза 8: firewall.rs (брандмауэр/сегментация) — ГОТОВО, работает в ядре
- Таблица `inet w420_fw`, профили: office / guest / dmz / isolated (чистая функция `build_profile_rules`, юнит-тесты).
- Команды: `fw_profile_apply/status/rules_list/rule_add/rule_remove/isolate_host/logs` + журнал `~/.w420/firewall.db`.
- **Live-тест пройден**: профиль `guest` реально применён в ядро nft от пользователя (cap_net_admin) и снят (`live_apply_revert_profile ... ok`).
- UI: карточка «БРАНДМАУЭР · СЕГМЕНТАЦИЯ» во вкладке СЕТЬ (`fw.js`).

## Фаза 9 (ядро): siem.rs — ГОТОВО
- `~/.w420/siem.db`: инкрементальный ingest из traffic.db (IDS-алерты), threats.db (CVE), net_scan.db (новые хосты), firewall.db; курсоры в `meta`.
- Корреляция: ≥2 события с одного src_ip за час или critical → инцидент (без дублей). Команды: `siem_ingest/correlate/events/search/dashboard/ai_summary`.
- **Live end-to-end пройден**: `cargo test live_siem -- --ignored` — ingest реальных БД + AI-сводка через NVIDIA (ротация 11 ключей, AES-256-GCM) вернула осмысленную русскую сводку SOC за 32 с.
- UI: карточка «SIEM · СОБЫТИЯ · ИНЦИДЕНТЫ» (`fw.js`).

Тесты: новые 8/8, весь lib 55 passed / 1 известный fail (gitleaks, окружение). Release-сборка чистая (47.6 МБ).

## VibeVoice (microsoft/VibeVoice) — изучен и интегрирован как опциональный движок
- В оригинальном репо длинный TTS-код удалён; живёт **VibeVoice-Realtime-0.5B** (потоковый, ~200–300 мс до первого звука, 24 кГц, голос = cached prompt `.pt`).
- Модель скачана (2.0 ГБ, `~/.w420/tts-server/models/`), пакет `vibevoice` из git, пресет голоса `en-Carter_man.pt`.
- Интеграция в голосовой сервер: ленивая загрузка, bf16/CPU/sdpa, `/speak` с `engine: vibevoice|espeak|auto`, fallback на espeak, заголовки `X-W420-Engine/X-W420-Gen-Sec`.
- **Честный вердикт по этому железу**: 15.7 ГБ RAM, ~4 ГБ free, CPU без CUDA — модель 0.5B дважды уходила в OOM (SIGKILL) при загрузке/генерации. Поэтому `tts_engine: "espeak"` в проде; vibevoice включается на машине с ≥8 ГБ free или GPU (или GGUF q4_k 699 МБ через llama.cpp — `cstr/vibevoice-realtime-0.5b-GGUF`).
- RU-клона оператора в Realtime нет среди пресетов (de/en/fr/it/jp/kr/nl/pl/pt/sp) — для клона по WAV: форк с VibeVoice-1.5B (voice_samples) либо сборка своего `.pt` из сэмпла. STT-альтернатива под CPU: **VibeVoice-ASR-BitNet** (1.58 ГБ, RTF<1, без GPU).
- Сервер сейчас: espeak-ng, `/health` → engine espeak-ng, `/speak` → 200 OK WAV 106 КБ. STT faster-whisper без изменений.

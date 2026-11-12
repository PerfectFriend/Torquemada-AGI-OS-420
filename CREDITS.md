# CREDITS

Torquemada 228 AGI (W420) stands on the shoulders of open-source giants:

## Core stack
- **Tauri v2** (MIT/Apache-2.0) — desktop shell (WebKitGTK on Linux)
- **Rust** (MIT/Apache-2.0) — all backend modules
- **tokio, serde, sqlx** — async runtime, serialization, SQLite
- **reqwest** — HTTP client for AI providers / feeds

## Security & network
- **sing-box** (GPL-3.0) — sidecar VPN/proxy engine (managed from Rust, not bundled)
- **nftables** (GPL-2.0) — default-deny firewall (system component)
- **trivy** (Apache-2.0) — CVE scanner sidecar (optional download)
- **gitleaks** (MIT) — secret scanner sidecar (optional download)

## AI / voice
- **Mistral Large 4** via NVIDIA NIM endpoint — default LLM
- **Whisper / Piper / XTTS** — STT/TTS pipeline (voice module)

## Frontend
- Vanilla HTML/CSS/JS thin client, fonts: **Orbitron** (OFL), **Caveat** (OFL) — bundled locally in `app/dist/`

## Artwork
- Hero/feature banners generated with Grok (prompts in `BANNER-PROMPTS.md`), vector versions hand-authored as SVG.

See `THIRD_PARTY_NOTICES.md` for full license texts.

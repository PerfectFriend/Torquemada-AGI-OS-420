# RC1 — Plan of Development (Open-Source Installer + i18n)

Commit: RC1 plan · status: **PLANNED** (executes after this document)

---

## Vision of RC1
Torquemada 228 AGI becomes a **one-command open-source install** from the GitHub repository, with **autostart on boot**, **transparent dependency provisioning**, and **global i18n (RU/EN/ES)** swappable from the Settings menu — without building any ISO.

## Architecture principles for RC1
- **No ISO**: GitHub repo is the single source of truth. Users run one script that clones + installs everything.
- **Autostart**: Linux desktop entry (`~/.local/share/applications/torquemada-228-desktop-agi.desktop`) + `systemd --user` service (or `rc.local` fallback). No sudo needed for the desktop client itself; privileged steps (`root_setup.sh`) opt in interactively.
- **Transparent resource provisioning**: the installer checks for missing binaries (Rust/Cargo, Node, sing-box, trivy, gitleaks, `git`, `sudo`) and either downloads the right sidecar or gives a clear `apt/dnf` hint. No secrets shipped.
- **i18n first**: JSON locales for RU/EN/ES keyed on `t.` names, a small `t(lang)` runtime in JS bridge, `settings lang` persist + hot-switch. UI strings stay in HTML/js; backend keeps English identifiers.
- **Keep existing**: all Rust modules, Tauri v2, `madre.rs`, `health.rs`, firewall, RDP/VNC/RAT/AD/netutil remain unchanged unless wiring i18n.

---

## Phase A — Repository polish & one-command installer

1. **`README.md`** rewrite: headline, badges, architecture diagram, one-line install, features table, screenshots placeholders, i18n note, contributing + license (MIT), roadmap link. 2 banner prompts (Grok) prepared separately.
2. **`SETUP.sh`** (idempotent root-capable):
   - check `git`, `sudo`, `jq`, `curl`;
   - detect OS (`/etc/os-release`) → package hint if Rust/Node missing;
   - `cargo build --release` (or fetch release binary from GitHub Releases);
   - copy `.desktop` + systemd-user unit + icons to `~/.local`;
   - run `root_setup.sh` (nftables base + NOPASSWD sudo rule) **only if user accepts**;
   - register autostart entry (`@desktop file` via XDG autostart).
3. **`scripts/root_setup.sh`**: nftables base, user sudo rule narrow, `~/.w420` dirs, exit 0 if already configured.
4. **`packaging/deb`**: keep `build_deb.sh`; add release workflow: `scripts/release.sh` → bump nothing, `cargo build --release`, `./build_deb.sh`, `gh release` draft with the `.deb` attached (uses existing GitHub token/CI).
5. **`.github/workflows/build_and_release.yml`**: Ubuntu job → `cargo build --release`, `./scripts/build_deb.sh`, test, upload `.deb` as release asset.

## Phase B — Global i18n (RU/EN/ES)

1. **Locales**: `app/i18n/ru.json`, `app/i18n/en.json`, `app/i18n/es.json` — keys `t.<page>.<id>`, includes menu, headers, panels (fw, siem, soc, ai, rat, netutil, ad, voice, settings, madre, health, emergency, did, bridge).
2. **JS runtime** (`app/i18n/bridge.js` already exists — extend it): `t(k, lang)`, default `ru`, load-on-demand per tab, `settings lang` change triggers re-render of all `data-i18n` labels.
3. **HTML wiring**: add `data-i18n="t.<...>"` attributes to every static text node; keep `id` for logic.
4. **Settings panel**: language dropdown (RU/EN/ES) → `settings_set({"lang":"en"})` → hot reload.
5. **Voice TTS**: pass `lang` into `voice_say` from settings (already parameterised).
6. **Tests**: i18n completeness check (`data-i18n` count vs locale key count per page) + `node --check` on bridge.

## Phase C — Autostart & service hardening

1. **Desktop entry** (`torquemada-228-desktop-agi.desktop`): Name/Comment/i18n, `Exec=%U`, `StartupWMClass=Torquemada228AGI`, Categories=Security; icon 128x128 + 512x512 PNGs in repo (`app/icons/`).
2. **systemd --user** unit (`torquemada-228-agi@user.service`): runs the binary as user, restart=always, logs to journal.
3. **XDG autostart** fallback for DEs without systemd: symlink desktop file to `~/.config/autostart/`.
4. **Verify** after install: `systemctl --user is-enabled` + `killall + restart` smoke test.

## Phase D — Release packaging & GitHub

1. `release.sh` builds `.deb`, tags nothing, creates a `v0.1.0-rc1` draft release via `gh` CLI with `w420_1.0.0_amd64.deb` attached.
2. **`.gitignore`** review: confirm no secrets, no `target/`, no `.deb`/`.rpm`/`.iso` (keep only `packaging/` staging + scripts).
3. **Licenses**: MIT `LICENSE`, `THIRD_PARTY_NOTICES.md` updated (sing-box, trivy, gitleaks licenses), `CREDITS.md`.
4. Docs to update: `README.md`, `SYSADMIN_GUIDE.md` → renamed/merged into `SETUP.md`, `W420_TECH_SPEC.md` mention RC1 scope (no ISO).

## Phase E — Documentation & assets

1. **Diagrams** (drawn as SVG → embedded into README):
   - `arch-rc1.svg`: repo → installer → install paths → services;
   - `install-flow.svg`: user command → checks → build → autostart → first boot;
   - `i18n-flow.svg`: settings lang → bridge → render;
   - `security-model.svg`: default-deny / Madre / sudo boundaries.
2. **Screenshots**: launch, settings i18n switch, health panel, madre panel — placeholders + `REPO_SCREENSHOTS.md` with naming convention.
3. **Grok banner prompts** (2):
   - `Banner 1 (hero, 1200×260, dark cyberpunk): Torquemada 228 AGI — open-source security operating system, cyberpunk city at night, neon circuit lines, terminal glow, text space at top-left "Torquemada 228 AGI", subtitle "Autonomous Cybersecurity OS — MIT licensed — install from GitHub with one command";`
   - `Banner 2 (feature strip, 1200×300): four panels: a) firewall shield icon + "Default-deny firewall"; b) hooded lady silhouette with scales + "Madre Torquemada AGI helm"; c) health meter with green checkmarks + "Host health dashboard score"; d) globe with three flags (RU/EN/ES) + "Full i18n"; flat vector, dark blue background, white text labels.`

## Verification gates (each phase)
- `cargo test --workspace` green, `cargo build --release` exit 0, `node --check` all JS, `.desktop` valid via `desktop-file-validate` if present, `grep` no `PASSWORD` in committed files, balance HTML (id ↔ data-i18n sanity), **report → topic 252 (media)**, push to `main` with commit message `rc1: <phase>` (e.g. `rc1: phase B i18n RU/EN/ES + settings switch`).

---

## What I will do next (sequence I expect, ask if wrong)
**Phase A first** — rewrite README + write `SETUP.sh` + `root_setup.sh` hardening + release workflow + CI. Then **Phase B** i18n (largest). Then C/D/E. Confirm and I start Phase A.

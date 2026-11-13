# Security Policy

## Reporting a vulnerability

If you find a security issue in Torquemada-AGI-OS-420, please **do not open a public issue**.
Report it privately to the repository owner via GitHub (DM / private contact listed in the profile)
or by email. Include a reproducer if possible. We aim to acknowledge within 72 hours.

## Scope notes

- This is a **personal / research-grade** desktop tool (RC1). It is not a hardened enterprise product.
- The app intentionally runs **local privileged helpers** (nftables firewall, sysctl hardening, ssh config)
  via narrow `NOPASSWD` sudoers entries created by `scripts/root_setup.sh`. Review that script before running it.
- API keys of LLM providers are stored **only** encrypted (AES-256-GCM) in `~/.w420/ai_providers.db`;
  the UI receives only masks (`…abcd`). The Hermes key pool (`~/.hermes/auth.json`) is read at startup
  to seed keys and is never sent anywhere except the provider's own endpoint.
- Secrets scan of full git history is clean at audit time (2026-11-13): only fake test keys
  (`nvapi-aaaa…`, `nvapi-abcdef…SECRET`) appear in unit tests.

## Supported versions

Only the latest commit on `main` is supported. There are no release branches yet (RC1 stage).

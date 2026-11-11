# Grok — промпты для баннеров README (Torquemada 228 AGI)

Все баннеры — горизонтальные, темный киберпанк, неоновые акценты (#00f0ff, #00e676, #d896ff), читаемый воздух в верхнем левом углу под текст.

---

## Баннер 1 — главный (hero), 1200×260, для top README.md

**Prompt (English, best for Grok/DALL-E/Midjourney):**

```
Hero banner for a cybersecurity open-source OS called "Torquemada 228 AGI".
Cyberpunk cityscape at night, deep dark blue-black background (#0a0e14), neon circuit-board
lines in cyan (#00f0ff) and magenta (#d896ff) running across the frame. In the center-left,
a hooded female silhouette (Mother Torquemada) glowing faintly, with a holographic firewall
shield made of data packets floating in front of her. Bottom-right: a glowing green health
meter and a three-language globe (RU/EN/ES flags subtle). Leave the top-left area mostly
clean for overlaid text. No visible text in the image. Ultra-detailed vector art style,
8k, cinematic lighting, dark mood.
```

**Prompt (короткий вариант):**

```
Cyberpunk hero banner 1200x260: hooded Mother Torquemada AI silhouette, neon cyan firewall
shield made of packets, dark blue city night, magenta circuit lines, glowing green health meter,
three-language globe (RU/EN/ES), plenty of clean space top-left for text overlay, vector style.
```

---

## Баннер 2 — полоса «4 фичи», 1200×300, под разделом возможностей (4 карточки в ряд)

**Prompt (English):**

```
Wide feature strip banner 1200x300 on dark blue background (#111824). Four equal panels in a row,
flat vector illustration style with thin cyan borders:

Panel 1 — left half of a glowing shield icon, label: "Default-deny firewall" (all packets from
foreign networks are dropped).
Panel 2 — silhouette of a hooded lady with scales of justice, label: "Madre Torquemada AI helm".
Panel 3 — circular health score meter at 100 with green checkmarks, label: "Host health dashboard".
Panel 4 — globe icon with three small flags (RU / EN / ES), label: "Full i18n in 3 languages".

Each label is placed at the bottom of its panel in white sans-serif. Clean, modern, minimal,
no photorealism, consistent icon style across all panels.
```

**Prompt (короткий вариант):**

```
Banner 1200x300, 4 panels: a) firewall shield "Default-deny firewall"; b) hooded lady "Madre
Torquemada AI helm"; c) green health meter "Host health dashboard"; d) globe with RU/EN/ES
flags "Full i18n". Dark blue bg, vector, clean white labels.
```

---

## Баннер 3 — установочный (для SETUP.md / RC1-PLAN.md), 1200×260

**Prompt (English):**

```
Wide banner 1200x260 for an installation guide of an open-source cybersecurity OS.
Left side: a glowing terminal window showing "bash SETUP.sh" typing with green output
lines, a running cargo build progress bar, and a checkmark next to "install complete".
Right side: a stylized Linux desktop with a "Torquemada 228 AGI" app icon launching from
the application menu, plus a systemd user-service badge. Dark background with cyan accent
lines connecting terminal to desktop. No visible text except the terminal screen. Clean
vector style, flat design, 8k.
```

**Prompt (короткий вариант):**

```
Banner 1200x260: glowing terminal typing "bash SETUP.sh" with green output + checkmarks,
connected by cyan circuit lines to a Linux desktop menu launching "Torquemada 228 AGI" icon.
Dark bg, vector, no text except terminal.
```

---

## Советы по генерации

- Указывайте размеры явно — Grok/Copilot DALL·E понимает `1200x260` / `1200x300`.
- Если появляется текст внутри картинки — добавьте `no visible text in the image, no lettering`.
- Сохраняйте PNG с прозрачным или темным фоном для интеграции в README.

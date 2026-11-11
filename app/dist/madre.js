// madre.js — панель «АРСЕНАЛ МАТЕРИ ТОРКВЕМАДЫ» (Torquemada 228 AGI).
// Философия: доверяем только своим пакетам — чужие все дропаем, для них нет хостов.
// Тонкий клиент: вся логика в Rust (madre.rs), здесь только invoke + рендер. Нативный режим только.
(() => {
  const $ = (id) => document.getElementById(id);
  const inv = window.__TAURI__?.invoke;
  if (!inv) return;

  const out = $("madre-out"), stat = $("madre-stat");
  const show = (t) => { out.textContent = String(t).slice(0, 6000); };

  async function refresh() {
    try {
      const s = await inv("madre_status");
      const c = s.config;
      stat.textContent = `режим: ${c.mode} · honeypot: ${s.honeypot_running ? "ON" : "off"} · watchdog: ${s.watchdog_running ? "ON" : "off"} · allow: ${c.allow.length} записей`;
      const ev = (s.events || []).slice(0, 8).map(e => `[${e.ts}] ${e.kind} ${e.src} — ${e.detail}`).join("\n");
      show(`ALLOWLIST (свои):\n  ${c.allow.join("\n  ")}\n\nСОБЫТИЯ:\n${ev || "пока пусто"}`);
    } catch (e) { stat.textContent = "err: " + e; }
  }

  $("madre-refresh").onclick = refresh;
  $("madre-mode").onclick = async () => {
    const cur = (await inv("madre_status")).config.mode;
    const next = cur === "enforce" ? "observe" : "enforce";
    await inv("madre_mode_set", { mode: next });
    stat.textContent = "режим → " + next + (next === "enforce" ? " (чужие пакеты дропаем)" : " (только логируем)");
    refresh();
  };
  $("madre-apply").onclick = async () => {
    const r = await inv("madre_apply", { clear: false });
    stat.textContent = r.applied ? "default-deny ПРИМЕНЁН в ядре (w420_madre)" : (r.needs_root ? "нужен root (root_setup.sh)" : "ошибка: " + r.error);
    refresh();
  };
  $("madre-clear").onclick = async () => {
    await inv("madre_apply", { clear: true });
    stat.textContent = "таблица w420_madre снята";
    refresh();
  };
  $("madre-allow-add").onclick = async () => {
    const v = $("madre-allow-in").value.trim();
    if (!v) return;
    await inv("madre_allow_add", { entry: v });
    $("madre-allow-in").value = "";
    refresh();
  };
  $("madre-verdict").onclick = async () => {
    const v = $("madre-dst-in").value.trim();
    if (!v) return;
    const r = await inv("madre_verdict", { dst: v });
    show(`Вердикт Матери для ${r.dst}: ${r.verdict.toUpperCase()} ${r.own ? "(свой пакет — accept)" : "(чужой пакет — DROP, для него нет хостов)"}`);
  };
  $("madre-hp").onclick = async () => {
    const s = await inv("madre_status");
    const r = s.honeypot_running ? await inv("madre_honeypot_stop") : await inv("madre_honeypot_start");
    stat.textContent = "honeypot: " + JSON.stringify(r);
    refresh();
  };
  $("madre-wd").onclick = async () => {
    const s = await inv("madre_status");
    const r = s.watchdog_running ? await inv("madre_watchdog_stop") : await inv("madre_watchdog_start");
    stat.textContent = "watchdog: " + JSON.stringify(r);
    refresh();
  };
  $("madre-helm").onclick = async () => {
    const h = await inv("madre_helm");
    show(`ШТУРВАЛ AGI — Madre Torquemada\n\n${h.system_prompt}\n\nрежим: ${h.mode} · honeypot: ${h.honeypot_on} · watchdog: ${h.watchdog_on}\nallowlist: ${h.allow.join(", ")}\nфилософия: ${h.philosophy}\n\nсвежие события:\n` +
      (h.recent_events || []).map(e => `[${e.ts}] ${e.kind} ${e.src} — ${e.detail}`).join("\n"));
  };

  refresh();
  setInterval(() => { if ($("v-net").classList.contains("on")) refresh(); }, 15000);
})();

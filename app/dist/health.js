// health.js — Этап 38: дашборд здоровья хостов (hosts_health / hosts_health_all).
// Тонкий клиент: сбор метрик и score — в Rust (health.rs), здесь только invoke + рендер.
(() => {
  const $ = (id) => document.getElementById(id);
  const inv = window.__TAURI__?.invoke;
  if (!inv) return;

  const out = $("hl-out"), stat = $("hl-stat");
  const gradeColor = (g) =>
    g === "HEALTHY" ? "#39ff6a" : g === "OK" ? "#a8ff60" : g === "DEGRADED" ? "#ffd23f" : g === "CRITICAL" ? "#ff5555" : "#888";

  async function refresh() {
    try {
      const r = await inv("hosts_health_all");
      stat.textContent = `хостов: ${r.total} · ${Object.entries(r.by_grade).map(([g, n]) => `${g}:${n}`).join(" ") || "—"}`;
      const rows = (r.reports || []).map((h) => {
        const m = h.metrics;
        return `<div style="border-bottom:1px solid #1f5c2e;padding:4px 0">
          <b>${h.host_id}</b> (${h.ip}) — <span style="color:${gradeColor(h.grade)}">${h.grade} ${h.score}/100</span>
          · Madre: ${h.madre_verdict === "accept" ? "свой (accept)" : "чужой (DROP)"}<br>
          <span style="opacity:.8">load ${m.load1?.toFixed(2) ?? "-"} · mem ${m.mem_used_pct?.toFixed(0) ?? "-"}% · disk / ${m.disk_root_pct?.toFixed(0) ?? "-"}% · failed svc ${m.failed_services ?? 0} · siem 1h ${m.siem_events_1h ?? 0} · edr ${m.edr_alerts_open ?? 0} · ${m.online ? "online" : "OFFLINE"}</span>
        </div>`;
      }).join("");
      out.innerHTML = rows || "инвентарь пуст — добавь хосты выше";
    } catch (e) { stat.textContent = "err: " + e; }
  }

  $("hl-refresh").onclick = refresh;
  $("hl-one").onclick = async () => {
    const id = $("hl-id-in").value.trim();
    if (!id) return;
    try {
      const h = await inv("hosts_health", { hostId: id });
      out.innerHTML = `<div><b>${h.host_id}</b> (${h.ip}) — <span style="color:${gradeColor(h.grade)}">${h.grade} ${h.score}/100</span> · Madre: ${h.madre_verdict}</div>`;
    } catch (e) { stat.textContent = "err: " + e; }
  };

  refresh();
  setInterval(() => { if ($("v-net").classList.contains("on")) refresh(); }, 30000);
})();

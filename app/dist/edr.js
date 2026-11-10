// edr.js — EDR карточка: процессы, соединения, baseline/diff, watch, kill/isolate, события
(() => {
  const $ = (id) => document.getElementById(id);
  const inv = window.__TAURI__?.invoke;
  if (!inv) return;
  const out = $("edr-out"), stat = $("edr-stat");
  const show = (t) => { out.textContent = String(t).slice(0, 6000); };

  $("edr-scan").onclick = async () => {
    try {
      const ps = await inv("edr_scan_processes");
      ps.sort((a, b) => b.cpu - a.cpu);
      stat.textContent = `процессов: ${ps.length}`;
      show("ТОП по CPU:\n" + ps.slice(0, 15).map(p => `${p.pid}  ${p.cpu.toFixed(1)}%  ${p.mem_kb >> 10} МБ  ${p.name}  ${p.exe}`).join("\n"));
    } catch (e) { show("err: " + e); }
  };
  $("edr-conns").onclick = async () => {
    try {
      const cs = await inv("edr_connections");
      stat.textContent = `соединений: ${cs.length}`;
      show(cs.slice(0, 40).map(c => `${c.proto} ${c.state} ${c.local} -> ${c.remote}  [${c.pid} ${c.process}]`).join("\n"));
    } catch (e) { show("err: " + e); }
  };
  $("edr-base").onclick = async () => { stat.textContent = "baseline: " + await inv("edr_baseline_set") + " записей"; };
  $("edr-diff").onclick = async () => { stat.textContent = "новых процессов: " + await inv("edr_diff"); };
  $("edr-watch").onclick = async () => {
    const on = await inv("edr_watch_status");
    const r = on ? await inv("edr_watch_stop") : await inv("edr_watch_start", { intervalSecs: 60 });
    $("edr-watch").textContent = r ? "WATCH ВКЛ" : "WATCH ВЫКЛ";
    stat.textContent = "watch: " + (r ? "on" : "off");
  };
  $("edr-kill").onclick = async () => {
    const pid = parseInt($("edr-pid").value, 10);
    if (!pid) return;
    try { show(await inv("edr_kill_pid", { pid })); } catch (e) { show("err: " + e); }
  };
  $("edr-isolate").onclick = async () => {
    const ip = $("edr-ip").value.trim();
    if (!ip) return;
    try { show(await inv("edr_respond", { action: "isolate_ip", target: ip })); } catch (e) { show("err: " + e); }
  };
  $("edr-events").onclick = async () => {
    try {
      const ev = await inv("edr_events", { limit: 50 });
      show(ev.map(e => `${e.ts} [${e.severity}] ${e.category} pid=${e.pid} ${e.process} — ${e.detail}`).join("\n") || "событий нет");
    } catch (e) { show("err: " + e); }
  };
})();

// fw.js — брандмауэр (профили/правила/изоляция) + SIEM (ingest/дашборд/поиск/AI-сводка)
// Тонкий клиент: вся логика в Rust, здесь только invoke + рендер.
(() => {
  const $ = (id) => document.getElementById(id);
  const inv = window.__TAURI__?.invoke;
  if (!inv) return;

  const fwOut = $("fw-out"), fwStat = $("fw-stat");
  const siemOut = $("siem-out"), siemStat = $("siem-stat");

  const showFw = (txt) => { fwOut.textContent = String(txt).slice(0, 4000); };
  const showSiem = (txt) => { siemOut.textContent = String(txt).slice(0, 6000); };

  async function fwRefresh() {
    try {
      const s = await inv("fw_status");
      fwStat.textContent = `профиль: ${s.profile} · таблица в ядре: ${s.table_present ? "да" : "нет"}`;
    } catch (e) { fwStat.textContent = "err: " + e; }
  }

  $("fw-apply").onclick = async () => {
    const p = $("fw-profile").value;
    const r = await inv("fw_profile_apply", { profile: p });
    fwStat.textContent = `профиль ${p}: сохранён=${r.saved} применён=${r.applied}${r.needs_root ? " (нужен root)" : ""}`;
    showFw(r.detail + "\n---\n" + r.rules);
    fwRefresh();
  };

  $("fw-rules").onclick = async () => {
    try {
      const rules = await inv("fw_rules_list");
      showFw(rules.map(r => `[${r.chain}] #${r.handle} ${r.rule}`).join("\n") || "таблица пуста/отсутствует");
    } catch (e) { showFw("err: " + e); }
  };

  $("fw-isolate").onclick = async () => {
    const ip = $("fw-ip").value.trim();
    if (!ip) return;
    try { showFw(await inv("fw_isolate_host", { ip })); }
    catch (e) { showFw("err: " + e); }
  };

  $("fw-logs").onclick = async () => {
    try {
      const logs = await inv("fw_logs", { limit: 50 });
      showFw(logs.map(l => `${l.ts}  ${l.action}  ${l.ip || "-"}  ${l.rule}`).join("\n") || "журнал пуст");
    } catch (e) { showFw("err: " + e); }
  };

  $("siem-ingest").onclick = async () => {
    const added = await inv("siem_ingest");
    const corr = await inv("siem_correlate");
    siemStat.textContent = `+${added} событий, новых инцидентов: ${corr}`;
  };

  $("siem-dash").onclick = async () => {
    try {
      const d = await inv("siem_dashboard");
      const sev = (d.by_severity || []).map(([k, v]) => `${k}:${v}`).join(" ");
      const src = (d.by_source || []).map(([k, v]) => `${k}:${v}`).join(" ");
      const inc = (d.open_incidents || []).map(i => `#${i.id} ${i.severity} ${i.src_ip} — ${i.title}`).join("\n");
      showSiem(`всего событий: ${d.total_events}\nпо severity: ${sev}\nпо источникам: ${src}\nинциденты:\n${inc || "нет"}`);
    } catch (e) { showSiem("err: " + e); }
  };

  $("siem-search").onclick = async () => {
    const q = $("siem-q").value.trim();
    if (!q) return;
    try {
      const ev = await inv("siem_search", { query: q, limit: 50 });
      showSiem(ev.map(e => `${e.ts} [${e.severity}] ${e.source}/${e.category} ${e.src_ip} ${e.message}`).join("\n") || "ничего не найдено");
    } catch (e) { showSiem("err: " + e); }
  };

  $("siem-ai").onclick = async () => {
    siemStat.textContent = "AI думает…";
    try {
      const s = await inv("siem_ai_summary");
      siemStat.textContent = "AI-сводка готова";
      showSiem(s);
    } catch (e) { siemStat.textContent = "err: " + e; showSiem(String(e)); }
  };

  // --- Правила корреляции и инциденты (Этап 18) ---
  $("siem-rules").onclick = async () => {
    try {
      const rules = await inv("siem_rules_list");
      showSiem(rules.map(r => `#${r.id} [${r.enabled ? "ON" : "OFF"}] ${r.name} — min=${r.min_events} окно=${r.window_minutes}м sev≥${r.min_severity}\n    шаблон: ${r.title}\n    ${r.description}`).join("\n") || "правил нет");
      siemStat.textContent = `правил: ${rules.length}`;
    } catch (e) { showSiem("err: " + e); }
  };
  $("siem-radd").onclick = async () => {
    try {
      const r = await inv("siem_rule_add", {
        name: $("siem-rname").value.trim(),
        description: null,
        minEvents: parseInt($("siem-rmin").value, 10) || null,
        windowMinutes: parseInt($("siem-rwin").value, 10) || null,
        minSeverity: $("siem-rsev").value,
        title: $("siem-rtitle").value.trim() || null,
      });
      siemStat.textContent = `добавлено правило #${r.id} ${r.name}`;
      $("siem-rname").value = ""; $("siem-rtitle").value = "";
      $("siem-rules").onclick();
    } catch (e) { showSiem("err: " + e); }
  };
  $("siem-rtoggle").onclick = async () => {
    const id = parseInt(prompt("id правила и новый статус (вкл=1/выкл=0):\nнапример: 3 0"), 10);
    if (!id) return;
    const parts = (prompt("введите: id статус") || "").trim().split(/\s+/);
    try {
      const r = await inv("siem_rule_toggle", { id: parseInt(parts[0], 10), enabled: parts[1] === "1" });
      siemStat.textContent = r; $("siem-rules").onclick();
    } catch (e) { showSiem("err: " + e); }
  };
  $("siem-rdel").onclick = async () => {
    const id = parseInt(prompt("id правила для удаления:"), 10);
    if (!id) return;
    try { const r = await inv("siem_rule_remove", { id }); siemStat.textContent = r; $("siem-rules").onclick(); }
    catch (e) { showSiem("err: " + e); }
  };
  $("siem-incidents").onclick = async () => {
    try {
      const st = prompt("статус-фильтр (open/in_progress/resolved/false_positive, пусто = все):", "open") ?? "";
      const inc = await inv("siem_incidents_list", { status: st.trim() || null });
      showSiem(inc.map(i => `#${i.id} [${i.status}] ${i.severity} src=${i.src_ip}\n  ${i.title}\n  ${i.created_at}`).join("\n") || "инцидентов нет");
      siemStat.textContent = `инцидентов (${st || "все"}): ${inc.length}`;
    } catch (e) { showSiem("err: " + e); }
  };
  $("siem-iclose").onclick = async () => {
    const parts = (prompt("id инцидента и новый статус:\nнапример: 5 resolved") || "").trim().split(/\s+/);
    if (!parts[0]) return;
    try {
      const r = await inv("siem_incident_set_status", { id: parseInt(parts[0], 10), status: parts[1] || "resolved" });
      siemStat.textContent = r;
    } catch (e) { showSiem("err: " + e); }
  };

  fwRefresh();
  setInterval(fwRefresh, 15000);
})();

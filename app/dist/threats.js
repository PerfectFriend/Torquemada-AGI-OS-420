// threats.js — карточка THREAT MONITOR: скан системы, база CVE, алерты, источники
(() => {
  const $ = (id) => document.getElementById(id);
  const inv = window.__TAURI__?.invoke;
  if (!inv) return;
  const out = $("th-out"), stat = $("th-stat");
  if (!out) return;
  const show = (t) => { out.textContent = String(t).slice(0, 8000); };
  const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;");

  // Скан системы: пакеты vs база уязвимостей → findings + алерты в БД
  $("th-scan").onclick = async () => {
    stat.textContent = "сканирую пакеты…";
    try {
      const r = await inv("threats_scan");
      stat.textContent = `скан ${r.scan_id.slice(0, 8)}: пакетов ${r.packages_checked}, уязвимостей ${r.vulnerabilities_found} (critical ${r.critical_count}, high ${r.high_count})`;
      show("Последний скан: " + r.scan_time + "\n" +
        r.findings.slice(0, 40).map(f => `${f.severity.toUpperCase()} ${f.cve_id} — ${f.package_name} ${f.installed_version}` +
          (f.fixed_version ? ` → fix ${f.fixed_version}` : " (нет фикса)") +
          (f.cvss_score != null ? ` cvss=${f.cvss_score}` : "")).join("\n"));
    } catch (e) { stat.textContent = "err"; show("err: " + e); }
  };

  // Синхронизация базы CVE из внешних источников (NVD и др.)
  $("th-sync").onclick = async () => {
    stat.textContent = "sync…";
    try {
      const n = await inv("threats_sync");
      stat.textContent = `синхронизировано записей: ${n}`;
      show("База уязвимостей обновлена из внешних источников: " + n + " записей.");
    } catch (e) { stat.textContent = "err"; show("err: " + e); }
  };

  // Список уязвимостей с фильтром severity
  $("th-vulns").onclick = async () => {
    try {
      const sev = $("th-sev").value || null;
      const list = await inv("threats_list", { severity: sev, limit: 200 });
      stat.textContent = `уязвимостей (${sev || "все"}): ${list.length}`;
      show(list.map(v => `${v.severity.toUpperCase()} ${v.cve_id} cvss=${v.cvss_v3_score ?? "?"} — ${v.product} ${v.version || ""}\n  ${esc(v.description).slice(0, 160)}`).join("\n"));
    } catch (e) { show("err: " + e); }
  };

  // Алерты (новые угрозы по результатам сканов)
  $("th-alerts").onclick = async () => {
    try {
      const a = await inv("threats_alerts");
      const open = a.filter(x => !x.acknowledged);
      stat.textContent = `алертов: ${a.length} (непрочитанных ${open.length})`;
      show(a.slice(0, 40).map(x => `${x.acknowledged ? "✓" : "●"} [${x.severity}] ${x.cve_id} ${x.title}\n   id=${x.alert_id} ${x.created_at}\n   ${esc(x.description).slice(0, 140)}`).join("\n"));
    } catch (e) { show("err: " + e); }
  };

  // Пометить алерт прочитанным по id
  $("th-ack").onclick = async () => {
    const id = prompt("alert_id для отметки прочитанным:");
    if (!id) return;
    try { await inv("threats_acknowledge_alert", { alertId: id.trim() }); stat.textContent = "алерт " + id.trim() + " прочитан"; $("th-alerts").onclick(); }
    catch (e) { show("err: " + e); }
  };

  // Источники угроз (NVD, OSV и т.п.)
  $("th-src").onclick = async () => {
    try {
      const s = await inv("threats_sources");
      stat.textContent = `источников: ${s.length}`;
      show(s.map(x => `${x.enabled ? "ON " : "OFF"} ${x.name} — ${x.url}\n   интервал ${x.sync_interval_hours}ч, последний sync: ${x.last_sync || "—"}`).join("\n"));
    } catch (e) { show("err: " + e); }
  };

  // При загрузке — последний скан, если был
  inv("threats_last_scan").then(r => {
    if (r) stat.textContent = `последний скан: уязвимостей ${r.vulnerabilities_found} (critical ${r.critical_count})`;
  }).catch(() => {});
})();

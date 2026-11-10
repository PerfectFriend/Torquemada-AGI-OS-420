// ops.js — патч-менеджмент + WireGuard сервер (тонкий клиент над Tauri invoke)
(() => {
  const $ = (id) => document.getElementById(id);
  const inv = window.__TAURI__?.invoke;
  if (!inv) return;
  const pOut = $("p-out"), pStat = $("p-stat"), vOut = $("v-out"), vStat = $("v-stat");
  const showP = (t) => { pOut.textContent = String(t).slice(0, 5000); };
  const showV = (t) => { vOut.textContent = String(t).slice(0, 5000); };

  $("p-scan").onclick = async () => {
    try { const r = await inv("patch_scan_all"); pStat.textContent = r.map(([h, t, s]) => `${h}:${t}/${s}sec`).join(" "); }
    catch (e) { showP("err: " + e); }
  };
  $("p-list").onclick = async () => {
    try { const l = await inv("patch_list_updates", { securityOnly: false }); showP(l.map(p => `${p.host}  ${p.package} ${p.current} -> ${p.candidate}  [${p.origin}]`).join("\n") || "нет обновлений"); }
    catch (e) { showP("err: " + e); }
  };
  $("p-sec").onclick = async () => {
    try { const l = await inv("patch_list_updates", { securityOnly: true }); pStat.textContent = `security: ${l.length}`; showP(l.map(p => `${p.host}  ${p.package} ${p.current} -> ${p.candidate}`).join("\n") || "security-обновлений нет"); }
    catch (e) { showP("err: " + e); }
  };
  $("p-deploy").onclick = async () => {
    try { const r = await inv("patch_deploy", { securityOnly: true }); pStat.textContent = `ok=${r.ok} needs_root=${r.needs_root} count=${r.count}`; showP(r.detail + (r.needs_root ? "\nКоманда для ручного запуска:\n" + r.command : "")); }
    catch (e) { showP("err: " + e); }
  };
  $("p-rollback").onclick = async () => {
    try { showP((await inv("patch_rollback_plan", { transactions: 1 })).join("\n") || "нет транзакций"); }
    catch (e) { showP("err: " + e); }
  };
  $("p-ai").onclick = async () => {
    pStat.textContent = "AI думает…";
    try { showP(await inv("patch_ai_assess")); pStat.textContent = "AI-оценка готова"; }
    catch (e) { pStat.textContent = "err"; showP(String(e)); }
  };

  $("v-init").onclick = async () => {
    try { const r = await inv("vpn_server_init", {}); vStat.textContent = `init: порт ${r.port}, pubkey ${String(r.server_pubkey).slice(0, 12)}…`; showV(JSON.stringify(r, null, 1).slice(0, 800)); }
    catch (e) { showV("err: " + e); }
  };
  $("v-add").onclick = async () => {
    const name = $("v-peer").value.trim();
    if (!name) return;
    try { const r = await inv("vpn_peer_add", { name }); vStat.textContent = `peer ${name}: ${r.allowed_ip}`; showV(r.client_conf); }
    catch (e) { showV("err: " + e); }
  };
  $("v-list").onclick = async () => {
    try { const l = await inv("vpn_peer_list"); showV(l.map(p => `${p.name} ${p.allowed_ip} ${p.revoked ? "REVOKED" : "active"} ${p.pubkey.slice(0, 12)}…`).join("\n") || "peer'ов нет"); }
    catch (e) { showV("err: " + e); }
  };
  $("v-up").onclick = async () => {
    try { const r = await inv("vpn_server_start"); vStat.textContent = `up=${r.up}${r.needs_root ? " needs_root (перезапусти root_setup.sh)" : ""}`; showV(r.detail || ""); }
    catch (e) { showV("err: " + e); }
  };
  $("v-down").onclick = async () => { try { vStat.textContent = "down: " + JSON.stringify(await inv("vpn_server_stop")); } catch (e) { showV("err: " + e); } };
  $("v-status").onclick = async () => {
    try {
      const s = await inv("vpn_status");
      vStat.textContent = `peers online: ${s.length}`;
      showV(s.map(p => `${p.interface} peer=${p.peer.slice(0, 12)}… ep=${p.endpoint} rx=${(p.transfer_rx / 1048576).toFixed(2)}MB tx=${(p.transfer_tx / 1048576).toFixed(2)}MB hs=${p.latest_handshake}`).join("\n") || "интерфейс не поднят");
    } catch (e) { showV("err: " + e); }
  };
  $("v-traffic").onclick = async () => {
    try {
      const t = await inv("vpn_traffic");
      vStat.textContent = `peers: ${t.peers_count} · всего rx=${(t.total_rx / 1048576).toFixed(2)}MB tx=${(t.total_tx / 1048576).toFixed(2)}MB`;
      showV(t.peers.map(p => `${p.peer.slice(0, 12)}… rx=${(p.rx / 1048576).toFixed(2)}MB tx=${(p.tx / 1048576).toFixed(2)}MB hs=${p.latest_handshake}`).join("\n") +
        `\nИТОГО: rx=${(t.total_rx / 1048576).toFixed(2)}MB tx=${(t.total_tx / 1048576).toFixed(2)}MB` +
        (t.top_talker && t.top_talker.peer ? `\ntop-talker: ${t.top_talker.peer.slice(0, 12)}… (${((t.top_talker.total || 0) / 1048576).toFixed(2)}MB)` : "") || "интерфейс не поднят");
    } catch (e) { showV("err: " + e); }
  };

  // --- веб-сканер ---
  const wOut = $("w-out"), wStat = $("w-stat");
  const showW = (t) => { wOut.textContent = String(t).slice(0, 6000); };
  $("w-net").onclick = async () => {
    try { const r = await inv("web_scan_net", { target: $("w-target").value.trim() }); wStat.textContent = `up=${r.hosts_up} new=${r.new_hosts.length}`; showW("hosts: " + r.hosts.join(", ") + "\nnew: " + r.new_hosts.join(", ")); }
    catch (e) { showW("err: " + e); }
  };
  $("w-vuln").onclick = async () => {
    wStat.textContent = "nmap сканирует (может занять минуты)…";
    try {
      const r = await inv("web_scan_targets", { targets: $("w-target").value.trim(), ports: $("w-ports").value.trim() || null, script: "vuln" });
      wStat.textContent = `vulns=${r.vulns_total}`;
      showW(r.hosts.map(h => `${h.ip} open=${h.ports_open} ` + h.ports.map(p => `${p.port}/${p.service} ${p.version} vulns=${p.vulns}`).join("; ")).join("\n"));
    } catch (e) { wStat.textContent = "err"; showW(String(e)); }
  };
  $("w-vlist").onclick = async () => {
    try { const l = await inv("web_vulns_list", { host: null, minSev: "low" }); wStat.textContent = `vulns: ${l.length}`; showW(l.map(v => `[${v.severity}] ${v.host}:${v.port} ${v.title}`).join("\n") || "уязвимостей нет"); }
    catch (e) { showW("err: " + e); }
  };
  $("w-hosts").onclick = async () => {
    try { const l = await inv("web_scan_results"); showW(l.slice(0, 50).map(h => `${h.scanned_at} ${h.ip} ${h.is_known ? "known" : "NEW"}`).join("\n")); }
    catch (e) { showW("err: " + e); }
  };
  $("w-ai").onclick = async () => {
    wStat.textContent = "AI думает…";
    try { showW(await inv("web_ai_report")); wStat.textContent = "AI-отчёт готов"; }
    catch (e) { wStat.textContent = "err"; showW(String(e)); }
  };
  $("w-status").onclick = async () => {
    try {
      const s = await inv("web_scan_status");
      wStat.textContent = `хостов: ${s.hosts_distinct} (новых ${s.hosts_new}) · уязвимостей: ${s.vulns_total}`;
      showW(JSON.stringify(s, null, 1));
    } catch (e) { showW("err: " + e); }
  };
  $("w-report").onclick = async () => {
    try { showW(await inv("web_scan_report")); wStat.textContent = "md-отчёт готов (ниже)"; }
    catch (e) { showW("err: " + e); }
  };

  // --- PKI ---
  const kOut = $("k-out"), kStat = $("k-stat");
  const showK = (t) => { kOut.textContent = String(t).slice(0, 5000); };
  $("k-init").onclick = async () => {
    try { const r = await inv("pki_ca_init", { cn: null, days: 3650 }); kStat.textContent = `CA: ${r.cn}`; showK(JSON.stringify(r, null, 1)); }
    catch (e) { showK("err: " + e); }
  };
  $("k-issue").onclick = async () => {
    const cn = $("k-cn").value.trim();
    if (!cn) return;
    const sans = $("k-sans").value.split(",").map(s => s.trim()).filter(Boolean);
    try { const r = await inv("pki_issue", { cn, sans, days: 825 }); kStat.textContent = `issued: ${cn}`; showK(JSON.stringify(r, null, 1)); }
    catch (e) { showK("err: " + e); }
  };
  $("k-list").onclick = async () => {
    try { const l = await inv("pki_list"); showK(l.map(c => `${c.cn} serial=${c.serial.slice(0, 12)}… ${c.revoked ? "REVOKED" : "ok"} до ${c.not_after}`).join("\n") || "сертификатов нет"); }
    catch (e) { showK("err: " + e); }
  };
  $("k-revoke").onclick = async () => {
    const cn = $("k-cn").value.trim();
    if (!cn) return;
    try { const r = await inv("pki_revoke", { cn }); kStat.textContent = "revoked + CRL"; showK(JSON.stringify(r, null, 1)); }
    catch (e) { showK("err: " + e); }
  };
  $("k-crl").onclick = async () => {
    try { kStat.textContent = "CRL: " + (await inv("pki_crl")); }
    catch (e) { showK("err: " + e); }
  };
  $("k-renew").onclick = async () => {
    try {
      const r = await inv("pki_cert_renew", { days: 30 });
      kStat.textContent = `продлено: ${r.renewed_ok} из ${r.expiring.length} истекающих`;
      showK(JSON.stringify(r, null, 1).slice(0, 4000));
    } catch (e) { showK("err: " + e); }
  };

  // === AI SOC (Фаза 15) ===
  const sStat = $("s-stat"), showS = t => $("s-out").textContent = t;
  $("s-status").onclick = async () => {
    try { const r = await inv("soc_status"); sStat.textContent = `open=${r.incidents_open} cyc=${r.cycles_run}`; showS(JSON.stringify(r, null, 1)); }
    catch (e) { showS("err: " + e); }
  };
  $("s-cycle").onclick = async () => {
    sStat.textContent = "цикл…";
    try { const r = await inv("soc_autonomous_cycle"); sStat.textContent = `+inc=${r.incidents_new} act=${r.actions_taken}`; showS(JSON.stringify(r, null, 1)); }
    catch (e) { showS("err: " + e); sStat.textContent = "err"; }
  };
  $("s-inc").onclick = async () => {
    try { const l = await inv("soc_incidents", { status: "open", severity: null, limit: 50 }); showS(l.map(i => `#${i.id} [${i.severity}] ${i.src_ip} — ${i.title} (${i.matched_playbook || "-"}) → ${i.actions_taken || "нет действий"}`).join("\n") || "открытых нет"); }
    catch (e) { showS("err: " + e); }
  };
  $("s-ai").onclick = async () => {
    sStat.textContent = "AI думает…";
    try { showS(await inv("soc_ai_cycle_report")); sStat.textContent = "сводка готова"; }
    catch (e) { showS("err: " + e); sStat.textContent = "err"; }
  };
  $("s-forecast").onclick = async () => {
    sStat.textContent = "прогноз…";
    try { showS(await inv("soc_forecast")); sStat.textContent = "прогноз готов"; }
    catch (e) { showS("err: " + e); sStat.textContent = "err"; }
  };
  $("s-chat").onclick = async () => {
    const q = $("s-q").value.trim();
    if (!q) return;
    sStat.textContent = "AI думает…";
    try { showS(await inv("soc_chat", { question: q })); sStat.textContent = "ответ получен"; }
    catch (e) { showS("err: " + e); sStat.textContent = "err"; }
  };
})();

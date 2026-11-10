// rat.js — Этап 29 (DameWare Parity): RAT-команды поверх SSH. Только нативный режим.
(function () {
  if (!(window.__TAURI__ && window.__TAURI__.core)) return;
  const invoke = window.__TAURI__.core.invoke;
  const $ = (s, r) => (r || document).querySelector(s);
  const el = (t, c, txt) => { const e = document.createElement(t); if (c) e.className = c; if (txt != null) e.textContent = txt; return e; };

  // панель RAT в разделе СЕТЬ
  let panel = null;
  function ensurePanel() {
    if (panel) return;
    const net = $('#v-net'); if (!net) return;
    panel = el('div', 'card'); panel.id = 'rat-panel';
    panel.appendChild(el('h3', null, 'RAT (этап 29) — действия над хостом'));
    const row = el('div', 'row');
    const sel = el('select'); sel.id = 'rat-host';
    const bRefr = el('button', 'btn', '↻ хосты'); bRefr.onclick = loadHosts;
    row.appendChild(sel); row.appendChild(bRefr);
    panel.appendChild(row);
    const acts = el('div', 'row');
    const mk = (label, fn) => { const b = el('button', 'btn', label); b.onclick = () => fn(sel.value); acts.appendChild(b); };
    mk('⏻ reboot', (h) => power(h, 'reboot'));
    mk('⏹ shutdown', (h) => power(h, 'shutdown'));
    mk('🔒 lock', (h) => power(h, 'lock'));
    mk('🚪 logoff', (h) => power(h, 'logoff'));
    mk('🔧 сервисы', (h) => showOut('Сервисы', invoke('rat_services_list', { hostId: h }).then(r => r.services)));
    mk('📜 логи', (h) => showOut('Журнал (200 строк)', invoke('rat_log_view', { hostId: h, unit: null, since: null, limit: 200 }).then(r => r.log)));
    mk('🧹 чистить логи', (h) => { if (confirm('Очистить journal на хосту (rotate+vacuum)?')) showOut('Чистка логов', invoke('rat_log_clear', { hostId: h })); });
    mk('💽 диски', (h) => showOut('Диски', invoke('rat_disk', { hostId: h }).then(r => r.disks)));
    mk('📦 пакеты', (h) => showOut('Пакеты', invoke('rat_pkgs', { hostId: h }).then(r => r.pkgs)));
    mk('📤 экспорт CSV', (h) => exportInfo(h, 'csv'));
    mk('📤 экспорт XML', (h) => exportInfo(h, 'xml'));
    panel.appendChild(acts);
    const wolRow = el('div', 'row');
    const macIn = el('input'); macIn.placeholder = 'MAC для WoL (aa:bb:cc:dd:ee:ff)'; macIn.id = 'rat-mac';
    const bWol = el('button', 'btn', '⚡ Wake-on-LAN'); bWol.onclick = async () => {
      try { const r = await invoke('rat_wake', { hostId: sel.value, mac: macIn.value }); out.textContent = 'WoL отправлен: ' + r.mac + ' (' + r.sent_bytes + ' байт)'; }
      catch (e) { out.textContent = 'ошибка: ' + e; }
    };
    wolRow.appendChild(macIn); wolRow.appendChild(bWol); panel.appendChild(wolRow);
    // управление сервисом
    const svcRow = el('div', 'row');
    const unitIn = el('input'); unitIn.placeholder = 'unit (напр. sshd.service)'; unitIn.id = 'rat-unit';
    const actSel = el('select'); actSel.id = 'rat-svc-act';
    ['start', 'stop', 'restart', 'status'].forEach(a => { const o = el('option'); o.value = a; o.textContent = a; actSel.appendChild(o); });
    const bSvc = el('button', 'btn', '▶ сервис'); bSvc.onclick = async () => {
      try { const r = await invoke('rat_service_control', { hostId: sel.value, unit: unitIn.value, action: actSel.value }); out.textContent = r.output; }
      catch (e) { out.textContent = 'ошибка: ' + e; }
    };
    svcRow.appendChild(unitIn); svcRow.appendChild(actSel); svcRow.appendChild(bSvc); panel.appendChild(svcRow);
    var out = el('pre'); out.id = 'rat-out'; out.style.cssText = 'background:#000;padding:6px;max-height:40vh;overflow:auto;white-space:pre-wrap';
    panel.appendChild(out);
    net.appendChild(panel);
    loadHosts();
  }

  async function loadHosts() {
    const sel = $('#rat-host'); if (!sel) return;
    try {
      const r = await invoke('hosts_list');
      const hosts = r.hosts || r;
      sel.innerHTML = '';
      for (const h of hosts) { const o = el('option'); o.value = h.id; o.textContent = `${h.name} (${h.ip})`; sel.appendChild(o); }
    } catch (e) {}
  }

  async function power(h, action) {
    if (!h) return;
    if (!confirm(`Действительно ${action} на хосте ${h}?`)) return;
    try { const r = await invoke('rat_power', { hostId: h, action }); out.textContent = `${action}: exit=${r.exit_code} (${r.note})`; }
    catch (e) { out.textContent = 'ошибка: ' + e; }
  }

  async function showOut(title, p) {
    try { out.textContent = title + '\n' + (await p); } catch (e) { out.textContent = title + '\nошибка: ' + e; }
  }

  async function exportInfo(h, format) {
    if (!h) return;
    try {
      const p = (window.__W420_HOME__ || '/tmp') + `/.w420/info-${h}.${format}`;
      const r = await invoke('rat_info_export', { hostId: h, format, outPath: p });
      out.textContent = `Экспорт ${format}: ${r.path} (hostname=${r.hostname}, os=${r.os})`;
    } catch (e) { out.textContent = 'ошибка: ' + e; }
  }

  document.addEventListener('DOMContentLoaded', ensurePanel);
})();

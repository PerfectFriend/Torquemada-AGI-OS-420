// evtlog.js — Этап 35: журнал событий (локальный sqlite + удалённый Windows Event Log). Нативный режим.
(() => {
  if (!(window.__TAURI__ && window.__TAURI__.core)) return;
  const { invoke } = window.__TAURI__.core;

  function el(tag, cls, txt) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt !== undefined) e.textContent = txt;
    return e;
  }

  const LEVEL_COLORS = { debug: '#888', info: '#4af', warn: '#fa0', error: '#f44', critical: '#f0f' };

  async function refreshStats() {
    const s = await invoke('evt_stats');
    const box = document.querySelector('#evt-stats');
    box.innerHTML = `Всего: <b>${s.total}</b> · ` + s.by_level.map(l =>
      `<span style="color:${LEVEL_COLORS[l.level] || '#fff'}">${l.level}: ${l.count}</span>`).join(' · ');
  }

  async function queryLocal() {
    const level = document.querySelector('#evt-level').value || null;
    const search = document.querySelector('#evt-search').value.trim() || null;
    const limit = parseInt(document.querySelector('#evt-limit').value || '100', 10);
    const r = await invoke('evt_query', { level, search, limit });
    const tbody = document.querySelector('#evt-table tbody');
    tbody.innerHTML = '';
    for (const e of r.events) {
      const tr = el('tr');
      const tdTs = el('td', '', new Date(e.ts * 1000).toLocaleString());
      const tdLvl = el('td', '', e.level);
      tdLvl.style.color = LEVEL_COLORS[e.level] || '#fff';
      tr.append(tdTs, tdLvl, el('td', '', e.source), el('td', '', e.message.slice(0, 200)));
      tbody.appendChild(tr);
    }
    document.querySelector('#evt-count').textContent = String(r.count);
    refreshStats();
  }

  async function logLocal() {
    const level = document.querySelector('#evt-new-level').value;
    const source = document.querySelector('#evt-new-src').value.trim() || 'ui';
    const message = document.querySelector('#evt-new-msg').value;
    if (!message.trim()) return;
    await invoke('evt_log', { level, source, message, tags: 'ui' });
    document.querySelector('#evt-new-msg').value = '';
    queryLocal();
  }

  async function remoteLogs() {
    const hostId = document.querySelector('#evt-host').value.trim();
    if (!hostId) return;
    const r = await invoke('evt_remote_logs', { hostId });
    const sel = document.querySelector('#evt-rlog');
    sel.innerHTML = '';
    for (const l of r.logs) sel.appendChild(el('option', '', l));
  }

  async function remoteQuery() {
    const hostId = document.querySelector('#evt-host').value.trim();
    const log = document.querySelector('#evt-rlog').value || 'Application';
    const errsOnly = document.querySelector('#evt-errs').checked;
    const count = parseInt(document.querySelector('#evt-rcount').value || '50', 10);
    const xpath = errsOnly ? '*[System/Level<=2]' : null;
    const out = document.querySelector('#evt-rout');
    try {
      const r = await invoke('evt_remote_query', { hostId, log, xpath, count });
      out.textContent = r.events.map(e =>
        `${e.time || ''} L${e.level ?? '?'} ${e.provider || ''} #${e.event_id ?? '?'} — ${e.message || ''}`
      ).join('\n') || r.stderr || '(пусто)';
    } catch (e) { out.textContent = 'Ошибка: ' + e; }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const host = document.querySelector('#v-net .panel') || document.body;
    const panel = el('div', 'panel');
    panel.appendChild(el('h3', '', '📋 Журнал событий'));
    panel.appendChild(el('div', '', '')).id = '';
    const stats = el('div'); stats.id = 'evt-stats';
    panel.appendChild(stats);

    const row = el('div', 'row');
    const lvl = el('select'); lvl.id = 'evt-level';
    lvl.appendChild(el('option', '', '(все)')).value = '';
    for (const l of ['debug', 'info', 'warn', 'error', 'critical']) {
      const o = el('option', '', l); o.value = l; lvl.appendChild(o);
    }
    const search = el('input'); search.id = 'evt-search'; search.placeholder = 'поиск по тексту';
    const limit = el('input'); limit.id = 'evt-limit'; limit.value = '100'; limit.style.width = '60px';
    const bQ = el('button', 'btn', 'Запрос'); bQ.onclick = queryLocal;
    const bS = el('button', 'btn', 'Статистика'); bS.onclick = refreshStats;
    row.append(lvl, search, limit, bQ, bS);
    panel.appendChild(row);
    panel.appendChild(el('span', '', 'Найдено: ')).appendChild(Object.assign(el('b'), { id: 'evt-count', textContent: '0' }));
    const table = el('table'); table.id = 'evt-table';
    table.innerHTML = '<thead><tr><th>Время</th><th>Уровень</th><th>Источник</th><th>Сообщение</th></tr></thead><tbody></tbody>';
    panel.appendChild(table);

    const rowN = el('div', 'row');
    const nl = el('select'); nl.id = 'evt-new-level';
    for (const l of ['info', 'warn', 'error', 'critical']) { const o = el('option', '', l); o.value = l; nl.appendChild(o); }
    const ns = el('input'); ns.id = 'evt-new-src'; ns.placeholder = 'источник'; ns.style.width = '100px';
    const nm = el('input'); nm.id = 'evt-new-msg'; nm.placeholder = 'сообщение'; nm.style.width = '260px';
    const bL = el('button', 'btn', 'Записать'); bL.onclick = logLocal;
    rowN.append(nl, ns, nm, bL);
    panel.appendChild(rowN);

    panel.appendChild(el('h4', '', 'Удалённый Event Log (Windows host)'));
    const rowR = el('div', 'row');
    const rh = el('input'); rh.id = 'evt-host'; rh.placeholder = 'host_id';
    const bLogs = el('button', 'btn', 'Каналы'); bLogs.onclick = remoteLogs;
    const rl = el('select'); rl.id = 'evt-rlog'; rl.style.width = '200px';
    const rc = el('input'); rc.id = 'evt-rcount'; rc.value = '50'; rc.style.width = '50px';
    const errs = el('label'); const cb = el('input'); cb.type = 'checkbox'; cb.id = 'evt-errs'; cb.checked = true;
    errs.append(cb, ' только ошибки (Level≤2)');
    const bRQ = el('button', 'btn', 'Query'); bRQ.onclick = remoteQuery;
    rowR.append(rh, bLogs, rl, rc, errs, bRQ);
    panel.appendChild(rowR);
    const out = el('pre'); out.id = 'evt-rout';
    out.style.cssText = 'max-height:220px;overflow:auto;background:#111;color:#eee;padding:8px;font-size:12px;';
    panel.appendChild(out);
    host.appendChild(panel);
    queryLocal();
  });
})();

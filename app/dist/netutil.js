// netutil.js — Этап 30: сетевые утилиты (ping/traceroute/DNS/port check). Только нативный режим.
(function () {
  if (!(window.__TAURI__ && window.__TAURI__.core)) return;
  const invoke = window.__TAURI__.core.invoke;
  const $ = (s, r) => (r || document).querySelector(s);
  const el = (t, c, txt) => { const e = document.createElement(t); if (c) e.className = c; if (txt != null) e.textContent = txt; return e; };

  function ensure() {
    if ($('#netutil-panel')) return;
    const net = $('#v-net'); if (!net) return;
    const p = el('div', 'card'); p.id = 'netutil-panel';
    p.appendChild(el('h3', null, 'СЕТЕВЫЕ УТИЛИТЫ (этап 30)'));
    const row = el('div', 'row');
    const host = el('input'); host.placeholder = 'host (напр. 8.8.8.8 или ya.ru)'; host.style.flex = '1'; host.id = 'nu-host';
    row.appendChild(host); p.appendChild(row);
    const row2 = el('div', 'row');
    const mk = (label, fn) => { const b = el('button', 'btn', label); b.onclick = () => fn(host.value.trim()); row2.appendChild(b); };
    mk('🏓 ping', (h) => run(h, () => invoke('net_ping', { host: h, count: 4 }).then(r => `ok=${r.ok}\n${JSON.stringify(r.result)}`)));
    mk('🗺 traceroute', (h) => run(h, () => invoke('net_traceroute', { host: h, maxHops: 15 }).then(r => r.hops.map(x => `${x.hop}. ${x.addr || '*'}  ${x.rtt_ms.join(' ')} ms`).join('\n'))));
    mk('🔌 порт', (h) => {
      const port = parseInt(prompt('Порт?', '22'), 10);
      if (!port) return;
      run(h, () => invoke('net_port_check', { host: h, port, timeoutMs: 2000 }).then(r => `${h}:${port} — ${r.open ? 'ОТКРЫТ' : 'закрыт'}`));
    });
    mk('🔎 DNS', (h) => {
      const rec = prompt('Тип записи (A/AAAA/MX/TXT)?', 'A') || 'A';
      run(h, () => invoke('net_dns_lookup', { name: h, record: rec }).then(r => r.answers.join('\n') || 'нет ответов'));
    });
    p.appendChild(row2);
    var out = el('pre'); out.id = 'nu-out'; out.style.cssText = 'background:#000;padding:6px;max-height:30vh;overflow:auto;white-space:pre-wrap';
    p.appendChild(out);
    net.appendChild(p);

    function run(h, fn) {
      if (!h) { out.textContent = 'введите хост'; return; }
      out.textContent = 'выполняю…';
      fn().then(t => { out.textContent = t; }).catch(e => { out.textContent = 'ошибка: ' + e; });
    }
  }
  document.addEventListener('DOMContentLoaded', ensure);
})();

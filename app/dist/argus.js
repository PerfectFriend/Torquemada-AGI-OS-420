// argus.js — панель «ДИСПЕТЧЕР» (в духе Argus @github.com/Ray-lea/Argus): процессы+ресурсы,
// графики истории, порты, «кто держит файл». Только нативный режим.
(function () {
  if (!(window.__TAURI__ && window.__TAURI__.core)) return;
  const invoke = window.__TAURI__.core.invoke;
  const $ = (s, r) => (r || document).querySelector(s);
  const el = (t, c, txt) => { const e = document.createElement(t); if (c) e.className = c; if (txt != null) e.textContent = txt; return e; };

  let panel, tabs, body, chartTimer = null;

  function ensurePanel() {
    if (panel) return;
    const stat = $('#v-stat'); if (!stat) return;
    panel = el('div', 'card'); panel.id = 'argus-panel';
    panel.appendChild(el('h3', null, 'ДИСПЕТЧЕР (Argus-стиль)'));
    tabs = el('div', 'row');
    const names = [['procs', '🧮 Процессы'], ['perf', '📈 Графики'], ['ports', '🌐 Порты'], ['files', '🔍 Файлы']];
    let cur = 'procs';
    for (const [id, label] of names) {
      const b = el('button', 'btn' + (id === cur ? ' active' : ''), label);
      b.onclick = () => { cur = id; [...tabs.children].forEach(x => x.classList.remove('active')); b.classList.add('active'); render(); };
      tabs.appendChild(b);
    }
    panel.appendChild(tabs);
    body = el('div'); body.id = 'argus-body'; panel.appendChild(body);
    stat.appendChild(panel);
    invoke('argus_metrics_start').catch(() => {});
    render();
  }

  async function render() {
    if (chartTimer) { clearInterval(chartTimer); chartTimer = null; }
    if (cur === 'procs') return renderProcs();
    if (cur === 'perf') return renderPerf();
    if (cur === 'ports') return renderPorts();
    if (cur === 'files') return renderFiles();
  }

  async function renderProcs() {
    body.innerHTML = '';
    const row = el('div', 'row');
    const f = el('input'); f.placeholder = 'фильтр по имени/cmd/pid…'; f.style.flex = '1';
    const s = el('select');
    [['cpu', 'по CPU'], ['mem', 'по RAM'], ['name', 'по имени'], ['pid', 'по PID']].forEach(([v, t]) => { const o = el('option'); o.value = v; o.textContent = t; s.appendChild(o); });
    const b = el('button', 'btn', '↻'); 
    const load = async () => {
      try {
        const r = await invoke('argus_procs', { sort: s.value, filter: f.value || null });
        tbl.innerHTML = '';
        const head = el('tr');
        ['PID', 'Имя', 'Юзер', 'CPU%', 'RAM MB', 'Команда', ''].forEach(h => head.appendChild(el('th', null, h)));
        tbl.appendChild(head);
        for (const p of r.procs.slice(0, 300)) {
          const tr = el('tr');
          [p.pid, p.name, p.user, p.cpu_pct.toFixed(1), p.mem_mb, p.cmd].forEach(c => tr.appendChild(el('td', null, String(c))));
          const td = el('td');
          const k = el('button', 'btn danger', '✕'); k.onclick = async () => { if (confirm(`Убить ${p.name} (pid ${p.pid})?`)) { try { await invoke('argus_kill', { pid: p.pid }); load(); } catch (e) { alert(e); } } };
          td.appendChild(k); tr.appendChild(td);
          tbl.appendChild(tr);
        }
        body.appendChild(el('div', 'dim', `всего процессов: ${r.total}, показано: ${Math.min(300, r.total)}`));
      } catch (e) { body.appendChild(el('div', 'err', String(e))); }
    };
    b.onclick = load; f.oninput = () => load();
    row.appendChild(f); row.appendChild(s); row.appendChild(b); body.appendChild(row);
    const tbl = el('table'); tbl.style.cssText = 'width:100%;font:11px monospace;border-collapse:collapse';
    body.appendChild(tbl);
    load();
  }

  function drawChart(cv, pts) {
    const ctx = cv.getContext('2d');
    const W = cv.width = cv.clientWidth || 600, H = cv.height = 160;
    ctx.fillStyle = '#0a0a0a'; ctx.fillRect(0, 0, W, H);
    if (!pts.length) { ctx.fillStyle = '#888'; ctx.fillText('нет данных — семплер пишет раз в секунду', 10, 20); return; }
    const line = (get, max, color) => {
      ctx.strokeStyle = color; ctx.beginPath();
      pts.forEach((p, i) => {
        const x = (i / Math.max(1, pts.length - 1)) * W;
        const y = H - 4 - (get(p) / max) * (H - 12);
        i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
      });
      ctx.stroke();
    };
    line(p => p.cpu_pct, 100, '#4af');
    const memMax = Math.max(1, ...pts.map(p => p.mem_total_mb));
    line(p => p.mem_used_mb, memMax, '#fa4');
    ctx.fillStyle = '#4af'; ctx.fillText('CPU %', 6, 12);
    ctx.fillStyle = '#fa4'; ctx.fillText('RAM', 60, 12);
    const last = pts[pts.length - 1];
    ctx.fillStyle = '#8f8'; ctx.fillText(`CPU ${last.cpu_pct.toFixed(1)}%  RAM ${last.mem_used_mb}/${last.mem_total_mb} MB  точек: ${pts.length}`, 6, H - 6);
  }

  async function renderPerf() {
    body.innerHTML = '';
    const cv = el('canvas'); cv.style.cssText = 'width:100%;height:160px;background:#000';
    body.appendChild(cv);
    const upd = async () => { try { const r = await invoke('argus_metrics_history'); drawChart(cv, r.points || []); } catch (e) {} };
    upd();
    chartTimer = setInterval(upd, 1000);
  }

  async function renderPorts() {
    body.innerHTML = '';
    const b = el('button', 'btn', '↻ обновить'); body.appendChild(b);
    const tbl = el('table'); tbl.style.cssText = 'width:100%;font:11px monospace;border-collapse:collapse';
    body.appendChild(tbl);
    b.onclick = async () => {
      try {
        const r = await invoke('argus_ports');
        tbl.innerHTML = '';
        const head = el('tr'); ['Протокол', 'Локальный', 'Удалённый', 'Состояние', 'PID', 'Процесс'].forEach(h => head.appendChild(el('th', null, h)));
        tbl.appendChild(head);
        for (const c of (r.conns || []).slice(0, 500)) {
          const tr = el('tr');
          [c.proto, c.local, c.remote, c.state, c.pid ?? '', c.proc].forEach(v => tr.appendChild(el('td', null, String(v))));
          tbl.appendChild(tr);
        }
        body.appendChild(el('div', 'dim', `соединений: ${r.count}`));
      } catch (e) { body.appendChild(el('div', 'err', String(e))); }
    };
    b.click();
  }

  function renderFiles() {
    body.innerHTML = '';
    const row = el('div', 'row');
    const inp = el('input'); inp.placeholder = 'путь к файлу/директории (напр. /var/log/syslog)'; inp.style.flex = '1';
    const b = el('button', 'btn', '🔍 кто держит'); 
    const out = el('pre'); out.style.cssText = 'background:#000;padding:6px;max-height:30vh;overflow:auto';
    b.onclick = async () => {
      try {
        const r = await invoke('argus_file_users', { path: inp.value });
        out.textContent = r.count ? r.users.map(([pid, name]) => `pid ${pid} — ${name}`).join('\n') : 'файл никем не занят';
      } catch (e) { out.textContent = 'ошибка: ' + e; }
    };
    row.appendChild(inp); row.appendChild(b); body.appendChild(row); body.appendChild(out);
  }

  document.addEventListener('DOMContentLoaded', ensurePanel);
})();

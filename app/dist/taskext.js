// taskext.js — Этап 36: расширенный Task Manager. Нативный режим.
(() => {
  if (!(window.__TAURI__ && window.__TAURI__.core)) return;
  const { invoke } = window.__TAURI__.core;

  function el(tag, cls, txt) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt !== undefined) e.textContent = txt;
    return e;
  }

  async function refreshLocal() {
    const t = await invoke('taskext_tree');
    const tbody = document.querySelector('#tk-local tbody');
    tbody.innerHTML = '';
    const q = (document.querySelector('#tk-q').value || '').toLowerCase();
    for (const p of t.processes) {
      if (q && !p.name.toLowerCase().includes(q) && !String(p.pid).includes(q)) continue;
      const tr = el('tr');
      tr.appendChild(el('td', '', String(p.pid)));
      tr.appendChild(el('td', '', p.ppid ?? '—'));
      tr.appendChild(el('td', '', p.name));
      tr.appendChild(el('td', '', (p.cpu || 0).toFixed(1)));
      tr.appendChild(el('td', '', (p.mem / 1024 / 1024).toFixed(1) + ' МБ'));
      const td = el('td');
      const bInfo = el('button', 'btn', 'Инфо');
      bInfo.onclick = async () => {
        const i = await invoke('taskext_proc_info', { pid: p.pid });
        document.querySelector('#tk-out').textContent = JSON.stringify(i, null, 1);
      };
      const bKill = el('button', 'btn', 'Kill');
      bKill.onclick = async () => {
        if (!confirm(`Завершить ${p.name} (pid ${p.pid}) SIGTERM?`)) return;
        await invoke('taskext_kill', { pid: p.pid, force: false });
        refreshLocal();
      };
      const bK9 = el('button', 'btn', 'KILL');
      bK9.onclick = async () => {
        if (!confirm(`Жёстко убить ${p.name} (pid ${p.pid}) SIGKILL?`)) return;
        await invoke('taskext_kill', { pid: p.pid, force: true });
        refreshLocal();
      };
      td.append(bInfo, bKill, bK9);
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
    document.querySelector('#tk-count').textContent = String(t.count);
  }

  async function refreshAutostart() {
    const r = await invoke('taskext_autostart_list');
    const ul = document.querySelector('#tk-auto');
    ul.innerHTML = '';
    for (const u of r.units) ul.appendChild(el('li', '', `⚙ systemd: ${u.name}`));
    for (const d of r.desktops) ul.appendChild(el('li', '', `🖥 ${d.file.split('/').pop()} — ${d.exec || d.name}${d.hidden ? ' (Hidden)' : ''}`));
  }

  async function remoteProcs() {
    const hostId = document.querySelector('#tk-host').value.trim();
    if (!hostId) return;
    const r = await invoke('taskext_remote_procs', { hostId });
    const tbody = document.querySelector('#tk-remote tbody');
    tbody.innerHTML = '';
    for (const p of r.processes) {
      const tr = el('tr');
      tr.appendChild(el('td', '', p.image));
      tr.appendChild(el('td', '', String(p.pid)));
      tr.appendChild(el('td', '', p.user));
      tr.appendChild(el('td', '', p.mem_kb));
      const td = el('td');
      const bK = el('button', 'btn', 'Kill /F');
      bK.onclick = async () => {
        if (!confirm(`taskkill /PID ${p.pid} /F на ${hostId}?`)) return;
        const k = await invoke('taskext_remote_kill', { hostId, pid: p.pid, image: null, force: true });
        document.querySelector('#tk-out').textContent = (k.ok ? 'OK' : 'FAIL') + ' ' + (k.stdout || k.stderr);
      };
      td.appendChild(bK);
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
  }

  async function remoteTasks() {
    const hostId = document.querySelector('#tk-host').value.trim();
    if (!hostId) return;
    const r = await invoke('taskext_remote_tasks', { hostId, task: null });
    document.querySelector('#tk-out').textContent = r.raw || r.stderr;
  }

  async function remoteAuto() {
    const hostId = document.querySelector('#tk-host').value.trim();
    if (!hostId) return;
    const r = await invoke('taskext_remote_autostart', { hostId });
    document.querySelector('#tk-out').textContent = r.entries.map(e => `${e.hive}\\${e.name} = ${e.command}`).join('\n') || '(пусто)';
  }

  document.addEventListener('DOMContentLoaded', () => {
    const host = document.querySelector('#v-net .panel') || document.body;
    const panel = el('div', 'panel');
    panel.appendChild(el('h3', '', '🧩 Task Manager (расширенный)'));
    const row = el('div', 'row');
    const q = el('input'); q.id = 'tk-q'; q.placeholder = 'фильтр по имени/pid';
    const bR = el('button', 'btn', '↻ Локальные процессы'); bR.onclick = refreshLocal;
    const bA = el('button', 'btn', 'Автозапуск (локально)'); bA.onclick = refreshAutostart;
    row.append(q, bR, bA);
    panel.appendChild(row);
    panel.appendChild(el('span', '', 'Процессов: ')).appendChild(Object.assign(el('b'), { id: 'tk-count', textContent: '0' }));
    const table = el('table'); table.id = 'tk-local';
    table.innerHTML = '<thead><tr><th>PID</th><th>PPID</th><th>Имя</th><th>CPU%</th><th>RAM</th><th></th></tr></thead><tbody></tbody>';
    panel.appendChild(table);
    panel.appendChild(el('ul')).id = 'tk-auto';

    panel.appendChild(el('h4', '', 'Windows host через SSH'));
    const rowR = el('div', 'row');
    const rh = el('input'); rh.id = 'tk-host'; rh.placeholder = 'host_id';
    const bP = el('button', 'btn', 'Процессы'); bP.onclick = remoteProcs;
    const bT = el('button', 'btn', 'Scheduled Tasks'); bT.onclick = remoteTasks;
    const bAu = el('button', 'btn', 'Автозапуск (Run keys)'); bAu.onclick = remoteAuto;
    rowR.append(rh, bP, bT, bAu);
    panel.appendChild(rowR);
    const tableR = el('table'); tableR.id = 'tk-remote';
    tableR.innerHTML = '<thead><tr><th>Образ</th><th>PID</th><th>Пользователь</th><th>RAM</th><th></th></tr></thead><tbody></tbody>';
    panel.appendChild(tableR);
    const out = el('pre'); out.id = 'tk-out';
    out.style.cssText = 'max-height:200px;overflow:auto;background:#111;color:#eee;padding:8px;font-size:12px;';
    panel.appendChild(out);
    host.appendChild(panel);
    refreshLocal();
  });
})();

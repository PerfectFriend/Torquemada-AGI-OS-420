// fmgr.js — Этап 37: файловый менеджер (локально + удалённо через SSH). Нативный режим.
(() => {
  if (!(window.__TAURI__ && window.__TAURI__.core)) return;
  const { invoke } = window.__TAURI__.core;

  function el(tag, cls, txt) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt !== undefined) e.textContent = txt;
    return e;
  }

  let curPath = '';

  async function listLocal(rel) {
    curPath = rel || '';
    const r = await invoke('fmgr_list', { root: null, rel: curPath || null });
    document.querySelector('#fmgr-path').textContent = r.path;
    const tbody = document.querySelector('#fmgr-local tbody');
    tbody.innerHTML = '';
    for (const e of r.entries) {
      const tr = el('tr');
      const nameTd = el('td', '', (e.is_dir ? '📁 ' : '📄 ') + e.name);
      if (e.is_dir) {
        nameTd.style.cursor = 'pointer';
        nameTd.onclick = () => listLocal((curPath ? curPath + '/' : '') + e.name);
      } else {
        nameTd.style.cursor = 'pointer';
        nameTd.onclick = async () => {
          const rd = await invoke('fmgr_read', { root: null, rel: (curPath ? curPath + '/' : '') + e.name, limit: null });
          document.querySelector('#fmgr-view').textContent =
            (rd.text ?? ('[бинарный] hex: ' + (rd.preview_hex || ''))) + (rd.truncated ? `\n… обрезано (всего ${rd.total_bytes} байт)` : '');
        };
      }
      tr.appendChild(nameTd);
      tr.appendChild(el('td', '', e.is_dir ? 'dir' : (e.size / 1024).toFixed(1) + ' КБ'));
      tr.appendChild(el('td', '', e.mode));
      tr.appendChild(el('td', '', new Date(e.mtime * 1000).toLocaleString()));
      tbody.appendChild(tr);
    }
    document.querySelector('#fmgr-count').textContent = String(r.count);
  }

  async function searchLocal() {
    const q = document.querySelector('#fmgr-q').value.trim();
    if (q.length < 2) return;
    const r = await invoke('fmgr_search', { root: null, rel: curPath || null, query: q, maxResults: null });
    const out = document.querySelector('#fmgr-view');
    out.textContent = r.results.map(x => `${x.is_dir ? '📁' : '📄'} ${x.path} (${x.size} Б)`).join('\n') || 'ничего не найдено';
  }

  async function writeLocal() {
    const name = document.querySelector('#fmgr-newname').value.trim();
    const content = document.querySelector('#fmgr-newcontent').value;
    if (!name) return;
    await invoke('fmgr_write', { root: null, rel: (curPath ? curPath + '/' : '') + name, content });
    listLocal(curPath);
  }

  async function remoteList() {
    const hostId = document.querySelector('#fmgr-host').value.trim();
    const dir = document.querySelector('#fmgr-rdir').value.trim() || '/home';
    if (!hostId) return;
    const r = await invoke('fmgr_remote_list', { hostId, dir });
    const tbody = document.querySelector('#fmgr-remote tbody');
    tbody.innerHTML = '';
    for (const e of r.entries) {
      const tr = el('tr');
      tr.appendChild(el('td', '', (e.is_dir ? '📁 ' : '📄 ') + e.name));
      tr.appendChild(el('td', '', e.is_dir ? 'dir' : e.size));
      tr.appendChild(el('td', '', e.mode));
      tbody.appendChild(tr);
    }
  }

  async function remoteSearch() {
    const hostId = document.querySelector('#fmgr-host').value.trim();
    const dir = document.querySelector('#fmgr-rdir').value.trim() || '/home';
    const q = document.querySelector('#fmgr-q').value.trim();
    if (!hostId || q.length < 2) return;
    const r = await invoke('fmgr_remote_search', { hostId, dir, pattern: q });
    document.querySelector('#fmgr-view').textContent = r.results.map(x => `${x.type} ${x.size} ${x.path}`).join('\n') || 'ничего';
  }

  document.addEventListener('DOMContentLoaded', () => {
    const host = document.querySelector('#v-net .panel') || document.body;
    const panel = el('div', 'panel');
    panel.appendChild(el('h3', '', '📂 Файловый менеджер'));
    const row = el('div', 'row');
    const bUp = el('button', 'btn', '⬆ Вверх'); bUp.onclick = () => listLocal(curPath.split('/').slice(0, -1).join('/'));
    const bRef = el('button', 'btn', '↻'); bRef.onclick = () => listLocal(curPath);
    const path = el('b'); path.id = 'fmgr-path';
    const q = el('input'); q.id = 'fmgr-q'; q.placeholder = 'поиск (≥2 симв.)';
    const bS = el('button', 'btn', '🔍 Локально'); bS.onclick = searchLocal;
    row.append(bUp, bRef, path, q, bS);
    panel.appendChild(row);
    panel.appendChild(el('span', '', 'Записей: ')).appendChild(Object.assign(el('b'), { id: 'fmgr-count', textContent: '0' }));
    const table = el('table'); table.id = 'fmgr-local';
    table.innerHTML = '<thead><tr><th>Имя</th><th>Размер</th><th>Права</th><th>Изменён</th></tr></thead><tbody></tbody>';
    panel.appendChild(table);
    const rowW = el('div', 'row');
    const nn = el('input'); nn.id = 'fmgr-newname'; nn.placeholder = 'новый файл';
    const nc = el('input'); nc.id = 'fmgr-newcontent'; nc.placeholder = 'содержимое'; nc.style.width = '220px';
    const bW = el('button', 'btn', '✍ Записать'); bW.onclick = writeLocal;
    rowW.append(nn, nc, bW);
    panel.appendChild(rowW);
    panel.appendChild(el('pre', '', '')).id = '';
    const view = el('pre'); view.id = 'fmgr-view';
    view.style.cssText = 'max-height:180px;overflow:auto;background:#111;color:#eee;padding:8px;font-size:12px;';
    panel.appendChild(view);

    panel.appendChild(el('h4', '', 'Удалённый хост (SSH)'));
    const rowR = el('div', 'row');
    const rh = el('input'); rh.id = 'fmgr-host'; rh.placeholder = 'host_id';
    const rd = el('input'); rd.id = 'fmgr-rdir'; rd.placeholder = '/home'; rd.style.width = '140px';
    const bL = el('button', 'btn', 'Листинг'); bL.onclick = remoteList;
    const bSR = el('button', 'btn', '🔍 Поиск'); bSR.onclick = remoteSearch;
    rowR.append(rh, rd, bL, bSR);
    panel.appendChild(rowR);
    const tableR = el('table'); tableR.id = 'fmgr-remote';
    tableR.innerHTML = '<thead><tr><th>Имя</th><th>Размер</th><th>Права</th></tr></thead><tbody></tbody>';
    panel.appendChild(tableR);
    host.appendChild(panel);
    listLocal('');
  });
})();

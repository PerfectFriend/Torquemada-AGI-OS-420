// reg.js — Этап 34: реестр (локальный w420 kv + удалённый Windows reg.exe через SSH). Нативный режим.
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
    const r = await invoke('reg_local_list');
    const tbody = document.querySelector('#reg-local-table tbody');
    tbody.innerHTML = '';
    for (const k of r.keys) {
      const tr = el('tr');
      tr.appendChild(el('td', '', k.key));
      tr.appendChild(el('td', '', new Date(k.ts * 1000).toLocaleString()));
      const td = el('td');
      const bHist = el('button', 'btn', 'История');
      bHist.onclick = async () => {
        const h = await invoke('reg_local_history', { key: k.key });
        const out = document.querySelector('#reg-out');
        out.textContent = h.history.map(x => `${new Date(x.ts * 1000).toLocaleString()}  ${x.value}`).join('\n') || 'пусто';
      };
      const bGet = el('button', 'btn', 'Get');
      bGet.onclick = async () => {
        const g = await invoke('reg_local_get', { key: k.key });
        document.querySelector('#reg-out').textContent = g.found ? g.value : '(нет)';
      };
      td.append(bGet, bHist);
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
    document.querySelector('#reg-local-count').textContent = String(r.count);
  }

  async function localSet() {
    const key = document.querySelector('#reg-lkey').value.trim();
    const value = document.querySelector('#reg-lval').value;
    if (!key) return;
    await invoke('reg_local_set', { key, value });
    refreshLocal();
  }

  async function remote(op) {
    const hostId = document.querySelector('#reg-host').value.trim();
    const path = document.querySelector('#reg-path').value.trim();
    const out = document.querySelector('#reg-out');
    if (!hostId || !path) return;
    try {
      if (op === 'query') {
        const v = document.querySelector('#reg-name').value.trim() || null;
        const r = await invoke('reg_remote_query', { hostId, path, value: v });
        out.textContent = r.entries.map(e => `${e.name} = ${e.value}`).join('\n') || r.raw || '(пусто)';
      } else if (op === 'set') {
        const name = document.querySelector('#reg-name').value.trim();
        const value = document.querySelector('#reg-val').value;
        const rtype = document.querySelector('#reg-type').value;
        const r = await invoke('reg_remote_set', { hostId, path, name, value, rtype });
        out.textContent = r.ok ? 'OK' : 'FAIL: ' + r.stderr;
      } else if (op === 'del') {
        const name = document.querySelector('#reg-name').value.trim();
        if (!confirm(`Удалить ${path}\\${name} на хосте ${hostId}?`)) return;
        const r = await invoke('reg_remote_delete', { hostId, path, name });
        out.textContent = r.ok ? 'OK' : 'FAIL: ' + r.stderr;
      }
    } catch (e) { out.textContent = 'Ошибка: ' + e; }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const host = document.querySelector('#v-net .panel') || document.body;
    const panel = el('div', 'panel');
    panel.appendChild(el('h3', '', '🗄 Реестр'));
    panel.appendChild(el('h4', '', 'Локальный реестр w420 (kv + история)'));
    const rowL = el('div', 'row');
    const lk = el('input'); lk.id = 'reg-lkey'; lk.placeholder = 'ключ';
    const lv = el('input'); lv.id = 'reg-lval'; lv.placeholder = 'значение';
    const bSet = el('button', 'btn', 'Set'); bSet.onclick = localSet;
    rowL.append(lk, lv, bSet);
    panel.appendChild(rowL);
    panel.appendChild(el('span', '', 'Кlucей: ')).appendChild(Object.assign(el('b'), { id: 'reg-local-count', textContent: '0' }));
    const table = el('table'); table.id = 'reg-local-table';
    table.innerHTML = '<thead><tr><th>Ключ</th><th>Обновлён</th><th></th></tr></thead><tbody></tbody>';
    panel.appendChild(table);

    panel.appendChild(el('h4', '', 'Удалённый реестр (Windows host через SSH)'));
    const rowR = el('div', 'row');
    const rh = el('input'); rh.id = 'reg-host'; rh.placeholder = 'host_id';
    const rp = el('input'); rp.id = 'reg-path'; rp.placeholder = 'HKLM\\SOFTWARE\\...'; rp.style.width = '220px';
    const rn = el('input'); rn.id = 'reg-name'; rn.placeholder = 'имя параметра (для query опц.)';
    const rv = el('input'); rv.id = 'reg-val'; rv.placeholder = 'значение (для set)';
    const rt = el('select'); rt.id = 'reg-type';
    for (const t of ['REG_SZ', 'REG_DWORD', 'REG_EXPAND_SZ', 'REG_QWORD']) rt.appendChild(el('option', '', t));
    const bQ = el('button', 'btn', 'Query'); bQ.onclick = () => remote('query');
    const bS = el('button', 'btn', 'Add'); bS.onclick = () => remote('set');
    const bD = el('button', 'btn', 'Delete'); bD.onclick = () => remote('del');
    rowR.append(rh, rp, rn, rv, rt, bQ, bS, bD);
    panel.appendChild(rowR);
    const out = el('pre'); out.id = 'reg-out';
    out.style.cssText = 'max-height:200px;overflow:auto;background:#111;color:#eee;padding:8px;font-size:12px;';
    panel.appendChild(out);
    host.appendChild(panel);
    refreshLocal();
  });
})();

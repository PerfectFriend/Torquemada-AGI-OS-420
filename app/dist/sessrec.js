// sessrec.js — Этап 32: запись сессий (.cast/typescript) + аудит-цепочка. Нативный режим только.
(() => {
  if (!(window.__TAURI__ && window.__TAURI__.core)) return;
  const { invoke } = window.__TAURI__.core;

  let activeId = null;
  let timer = null;

  function el(tag, cls, txt) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt !== undefined) e.textContent = txt;
    return e;
  }

  async function refresh() {
    try {
      const r = await invoke('sessrec_list');
      const tbody = document.querySelector('#sessrec-table tbody');
      tbody.innerHTML = '';
      for (const rec of r.recordings) {
        const tr = el('tr');
        const name = rec.path.split('/').pop();
        tr.appendChild(el('td', '', name));
        tr.appendChild(el('td', '', rec.format));
        tr.appendChild(el('td', '', (rec.size / 1024).toFixed(1) + ' КБ'));
        const td = el('td');
        const bView = el('button', 'btn', 'Просмотр');
        bView.onclick = () => view(rec.path, rec.format);
        const bMp4 = el('button', 'btn', 'MP4');
        bMp4.onclick = () => renderMp4(rec.path);
        td.append(bView, bMp4);
        tr.appendChild(td);
        tbody.appendChild(tr);
      }
      document.querySelector('#sessrec-count').textContent = String(r.count);
      const v = await invoke('sessrec_verify_chain');
      const vc = document.querySelector('#sessrec-chain');
      vc.textContent = v.ok ? `OK — проверено ${v.checked} записей` : `ПОВРЕЖДЕНА на строке ${v.bad_line}`;
      vc.style.color = v.ok ? 'var(--ok, #4caf50)' : 'var(--bad, #f44336)';
    } catch (e) { console.error('sessrec refresh', e); }
  }

  async function start() {
    const label = document.querySelector('#sessrec-label').value.trim() || undefined;
    const cmd = document.querySelector('#sessrec-cmd').value.trim() || undefined;
    const r = await invoke('sessrec_start', { label, cmd });
    activeId = r.id;
    document.querySelector('#sessrec-active').textContent = `Запись #${r.id} → ${r.path}`;
    if (timer) clearInterval(timer);
    timer = setInterval(refresh, 2000);
  }

  async function stop() {
    if (activeId == null) return;
    await invoke('sessrec_stop', { id: activeId });
    document.querySelector('#sessrec-active').textContent = '—';
    activeId = null;
    if (timer) { clearInterval(timer); timer = null; }
    refresh();
  }

  async function view(path, format) {
    const out = document.querySelector('#sessrec-view');
    if (format === 'cast') {
      const r = await invoke('sessrec_read_cast', { path });
      let text = '';
      for (const ev of r.events) if (ev[1] === 'o') text += ev[2];
      out.textContent = text.replace(/\r/g, '');
    } else {
      out.textContent = '(формат typescript — откройте файл в терминале через `less -R`)\n' + path;
    }
  }

  async function renderMp4(path) {
    const out = path.replace(/\.(cast|typescript)$/, '.mp4');
    try {
      await invoke('sessrec_render_mp4', { path, outMp4: out });
      alert('Готово: ' + out);
    } catch (e) { alert('Рендер: ' + e); }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const host = document.querySelector('#v-net .panel') || document.body;
    const panel = el('div', 'panel');
    panel.id = 'sessrec-panel';
    panel.appendChild(el('h3', '', '🎥 Запись сессий'));
    const row = el('div', 'row');
    row.appendChild(el('input', '', '')).id = '';
    const labelIn = el('input'); labelIn.id = 'sessrec-label'; labelIn.placeholder = 'Метка (опц.)';
    const cmdIn = el('input'); cmdIn.id = 'sessrec-cmd'; cmdIn.placeholder = 'Команда (по умолч. bash)';
    const bStart = el('button', 'btn', '▶ Начать'); bStart.onclick = start;
    const bStop = el('button', 'btn', '⏹ Стоп'); bStop.onclick = stop;
    row.append(labelIn, cmdIn, bStart, bStop);
    panel.appendChild(row);
    panel.appendChild(el('div', '', '')).id = '';
    const st = el('div', '', 'Активная запись: '); st.appendChild(el('b', '', '—')).id = '';
    const act = el('b'); act.id = 'sessrec-active'; act.textContent = '—';
    st.innerHTML = 'Активная запись: '; st.appendChild(act);
    panel.appendChild(st);
    const info = el('div', '', '');
    const cnt = el('b'); cnt.id = 'sessrec-count'; cnt.textContent = '0';
    const chain = el('span'); chain.id = 'sessrec-chain'; chain.textContent = 'цепочка: …';
    info.append('Записей: ', cnt, ' · ', chain);
    panel.appendChild(info);
    const table = el('table'); table.id = 'sessrec-table';
    table.innerHTML = '<thead><tr><th>Файл</th><th>Формат</th><th>Размер</th><th></th></tr></thead><tbody></tbody>';
    panel.appendChild(table);
    panel.appendChild(el('h4', '', 'Просмотр'));
    const viewBox = el('pre'); viewBox.id = 'sessrec-view';
    viewBox.style.cssText = 'max-height:240px;overflow:auto;background:#111;color:#eee;padding:8px;font-size:12px;';
    panel.appendChild(viewBox);
    host.appendChild(panel);
    refresh();
  });
})();

// rdesk.js — Этап 27 (DameWare Parity): Remote Desktop core. Только нативный режим.
(function () {
  if (!(window.__TAURI__ && window.__TAURI__.core)) return;
  const invoke = window.__TAURI__.core.invoke;
  const $ = (s, r) => (r || document).querySelector(s);
  const el = (t, c, txt) => { const e = document.createElement(t); if (c) e.className = c; if (txt != null) e.textContent = txt; return e; };

  // ---------- минимальный RFB-over-WebSocket клиент (Raw encoding) ----------
  class RfbWs {
    constructor(url, canvas) {
      this.canvas = canvas; this.ws = null; this.state = 'idle';
      this.url = url; this._buf = new Uint8Array(0);
    }
    connect() {
      this.state = 'connecting';
      this.ws = new WebSocket(this.url, 'binary'); // websockify отдаёт бинарный поток
      this.ws.binaryType = 'arraybuffer';
      this.ws.onopen = () => { this.state = 'handshake'; this._sendStr('RFB 003.008\n'); };
      this.ws.onmessage = (ev) => this._feed(new Uint8Array(ev.data));
      this.ws.onclose = () => { this.state = 'closed'; };
      this.ws.onerror = () => { this.state = 'error'; };
    }
    _sendStr(s) { const b = new TextEncoder().encode(s); this.ws.send(b); }
    _send(b) { this.ws.send(b); }
    _feed(d) {
      const nb = new Uint8Array(this._buf.length + d.length);
      nb.set(this._buf, 0); nb.set(d, this._buf.length); this._buf = nb;
      try { this._parse(); } catch (e) { this.state = 'error'; console.error('rfb parse', e); }
    }
    _take(n) {
      if (this._buf.length < n) return null;
      const out = this._buf.slice(0, n); this._buf = this._buf.slice(n); return out;
    }
    _u8() { const b = this._take(1); return b ? b[0] : null; }
    _u16() { const b = this._take(2); return b ? (b[0] << 8) | b[1] : null; }
    _u32() { const b = this._take(4); return b ? ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0 : null; }
    _parse() {
      if (this.state === 'handshake') {
        const v = this._take(12); if (!v) return;
        // security types
        const n = this._u8(); if (n === null) return;
        const types = this._take(n); if (!types) return;
        if (!types.includes(1)) throw new Error('сервер не даёт security None');
        this._send(new Uint8Array([1]));
        this.state = 'secresult';
      } else if (this.state === 'secresult') {
        const r = this._u32(); if (r === null) return;
        if (r !== 0) throw new Error('security handshake отклонён');
        this._send(new Uint8Array([1])); // ClientInit shared
        this.state = 'serverinit';
      } else if (this.state === 'serverinit') {
        const hdr = this._take(24); if (!hdr) return;
        this.w = (hdr[0] << 8) | hdr[1]; this.h = (hdr[2] << 8) | hdr[3];
        const nameLen = (hdr[20] << 24) | (hdr[21] << 16) | (hdr[22] << 8) | hdr[23];
        const name = this._take(nameLen); if (!name) return;
        this.canvas.width = this.w; this.canvas.height = this.h;
        // SetPixelFormat 32bpp LE truecolor R16 G8 B0
        const spf = new Uint8Array(20);
        spf[4] = 32; spf[5] = 24; spf[6] = 0; spf[7] = 1;
        spf[8] = 0; spf[9] = 255; spf[10] = 0; spf[11] = 255; spf[12] = 0; spf[13] = 255;
        spf[14] = 16; spf[15] = 8; spf[16] = 0;
        this._send(spf);
        // SetEncodings: Raw
        const se = new Uint8Array(8); se[0] = 2;
        se[2] = 0; se[3] = 1; // 1 encoding
        this._send(se);
        this._reqFbu();
        this.state = 'live';
      } else if (this.state === 'live') {
        const hdr = this._take(4); if (!hdr) return;
        const type = hdr[0], nrects = (hdr[2] << 8) | hdr[3];
        if (type !== 0) { this._reqFbu(); return; } // Bell/CutText — игнор, запросим кадр снова
        const ctx = this.canvas.getContext('2d');
        const img = ctx.createImageData(this.w, this.h);
        this._rectsLeft = nrects; this._img = img; this._ctx = ctx;
        this.state = 'rects';
      } else if (this.state === 'rects') {
        const rh = this._take(12); if (!rh) return;
        const x = (rh[0] << 8) | rh[1], y = (rh[2] << 8) | rh[3];
        const w = (rh[4] << 8) | rh[5], h = (rh[6] << 8) | rh[7];
        const enc = (rh[8] << 24) | (rh[9] << 16) | (rh[10] << 8) | rh[11];
        if (enc !== 0) throw new Error('не Raw: ' + enc);
        const px = this._take(w * h * 4); if (!px) { this._pendingRect = { x, y, w, h }; this.state = 'rectpx'; return; }
        this._drawRect(x, y, w, h, px);
        this._rectsLeft--;
        if (this._rectsLeft <= 0) { this._ctx.putImageData(this._img, 0, 0); this._reqFbu(); this.state = 'live'; }
      } else if (this.state === 'rectpx') {
        const r = this._pendingRect;
        const px = this._take(r.w * r.h * 4); if (!px) return;
        this._drawRect(r.x, r.y, r.w, r.h, px);
        this._rectsLeft--;
        if (this._rectsLeft <= 0) { this._ctx.putImageData(this._img, 0, 0); this._reqFbu(); this.state = 'live'; }
        else this.state = 'rects';
      }
    }
    _drawRect(x, y, w, h, px) {
      for (let row = 0; row < h; row++) for (let col = 0; col < w; col++) {
        const si = (row * w + col) * 4, di = ((y + row) * this.w + (x + col)) * 4;
        this._img.data[di] = px[si + 2]; this._img.data[di + 1] = px[si + 1];
        this._img.data[di + 2] = px[si]; this._img.data[di + 3] = 255;
      }
    }
    _reqFbu() {
      const b = new Uint8Array(10); b[0] = 3; b[1] = 1; // incremental
      b[6] = this.w >> 8; b[7] = this.w & 255; b[8] = this.h >> 8; b[9] = this.h & 255;
      this._send(b);
    }
    close() { try { this.ws && this.ws.close(); } catch (e) {} this.state = 'closed'; }
  }

  // ---------- UI: панель сессий в разделе СЕТЬ ----------
  let panel = null, sessRows = null, viewerMap = {};

  function ensurePanel() {
    if (panel) return panel;
    const net = $('#v-net'); if (!net) return null;
    panel = el('div', 'card'); panel.id = 'rdesk-panel';
    panel.appendChild(el('h3', null, 'REMOTE DESKTOP (этап 27)'));
    const btns = el('div', 'row');
    const bRefresh = el('button', 'btn', '↻ сессии'); bRefresh.onclick = refreshSessions;
    btns.appendChild(bRefresh); panel.appendChild(btns);
    sessRows = el('div'); sessRows.id = 'rdesk-sessions'; panel.appendChild(sessRows);
    net.appendChild(panel);
    refreshSessions();
    return panel;
  }

  async function refreshSessions() {
    if (!sessRows) return;
    sessRows.innerHTML = '';
    let data; try { data = await invoke('rdesk_sessions'); } catch (e) { sessRows.appendChild(el('div', 'dim', 'ошибка: ' + e)); return; }
    if (!data.sessions.length) { sessRows.appendChild(el('div', 'dim', 'активных сессий нет — подключитесь к хосту кнопками VNC/RDP в списке выше')); return; }
    for (const s of data.sessions) {
      const row = el('div', 'row');
      row.appendChild(el('b', null, `#${s.id} ${s.proto.toUpperCase()} ${s.host_name || ''} (${s.host}:${s.port})`));
      row.appendChild(el('span', 'dim', ` ${s.state}${s.ws_port ? ' ws:' + s.ws_port : ''} viewers:${s.viewers}${s.locked ? ' 🔒' : ''}${s.blanked ? ' ⬛' : ''}`));
      if (s.proto === 'vnc' && s.ws_port) {
        const bView = el('button', 'btn', 'Смотреть'); bView.onclick = () => openViewer(s); row.appendChild(bView);
        const bShot = el('button', 'btn', '📷 скриншот'); bShot.onclick = async () => {
          try {
            const out = await invoke('rdesk_screenshot', { host: s.host, port: s.port, outPath: (window.__W420_HOME__ || '') + '/.w420/rdesk-' + s.id + '.png' });
            row.appendChild(el('span', 'ok', ` сохранён ${out.width}x${out.height}`));
          } catch (e) { row.appendChild(el('span', 'err', ' ' + e)); }
        };
        row.appendChild(bShot);
      }
      const bLock = el('button', 'btn', s.locked ? '🔓 input' : '🔒 input'); bLock.onclick = async () => { await invoke('rdesk_lock_input', { id: s.id, locked: !s.locked }); refreshSessions(); };
      const bBlank = el('button', 'btn', s.blanked ? '⬜ screen' : '⬛ screen'); bBlank.onclick = async () => { await invoke('rdesk_blank_screen', { id: s.id, blanked: !s.blanked }); refreshSessions(); };
      const bRole = el('button', 'btn', s.role === 'controller' ? '🎮 controller' : '👁 viewer');
      bRole.onclick = async () => { await invoke('rdesk_set_role', { id: s.id, role: s.role === 'controller' ? 'viewer' : 'controller' }); refreshSessions(); };
      const bXfer = el('button', 'btn', '📁 файлы'); bXfer.onclick = () => openXfer(s);
      const bClose = el('button', 'btn danger', '✕ закрыть'); bClose.onclick = async () => { closeViewer(s.id); await invoke('rdesk_disconnect', { id: s.id }); refreshSessions(); };
      row.appendChild(bLock); row.appendChild(bBlank); row.appendChild(bRole); row.appendChild(bXfer); row.appendChild(bClose);
      sessRows.appendChild(row);
    }
  }

  function openViewer(s) {
    closeViewer(s.id);
    const dlg = el('div', 'card'); dlg.id = 'rdesk-view-' + s.id;
    dlg.style.cssText = 'position:fixed;inset:4% 4%;z-index:9999;background:#000;overflow:auto';
    const bar = el('div', 'row');
    bar.appendChild(el('b', null, `Сессия #${s.id} — ${s.host_name} (${s.host})`));
    const bClose = el('button', 'btn danger', '✕'); bClose.onclick = () => { closeViewer(s.id); invoke('rdesk_viewer_join', { id: s.id, delta: -1 }); refreshSessions(); };
    bar.appendChild(bClose); dlg.appendChild(bar);
    const cv = el('canvas'); cv.style.cssText = 'max-width:100%;image-rendering:pixelated;background:#111'; dlg.appendChild(cv);
    // Этап 28: in-session чат (polling по offset)
    const chatBox = el('div'); chatBox.style.cssText = 'height:120px;overflow:auto;background:#0a0a0a;border:1px solid #333;padding:4px;font:12px monospace';
    dlg.appendChild(chatBox);
    const chatRow = el('div', 'row');
    const chatIn = el('input'); chatIn.placeholder = 'сообщение в сессию…'; chatIn.style.flex = '1';
    const chatBtn = el('button', 'btn', '➤');
    let chatOff = 0;
    const pollChat = async () => {
      try {
        const r = await invoke('rdesk_chat_recv', { id: s.id, since: chatOff });
        for (const m of r.messages) {
          chatBox.appendChild(el('div', null, `[${new Date(m.ts * 1000).toLocaleTimeString()}] ${m.author}: ${m.text}`));
          chatOff++;
        }
        chatBox.scrollTop = chatBox.scrollHeight;
      } catch (e) {}
    };
    chatBtn.onclick = async () => { const t = chatIn.value.trim(); if (!t) return; chatIn.value = ''; try { await invoke('rdesk_chat_send', { id: s.id, author: 'thomas', text: t }); } catch (e) { alert(e); } pollChat(); };
    chatRow.appendChild(chatIn); chatRow.appendChild(chatBtn); dlg.appendChild(chatRow);
    const chatTimer = setInterval(() => { if (!viewerMap[s.id]) { clearInterval(chatTimer); return; } pollChat(); }, 2000);
    pollChat();
    document.body.appendChild(dlg);
    const rfb = new RfbWs('ws://127.0.0.1:' + s.ws_port, cv);
    rfb.connect();
    viewerMap[s.id] = rfb;
    invoke('rdesk_viewer_join', { id: s.id, delta: 1 });
  }
  function closeViewer(id) { const v = viewerMap[id]; if (v) { v.close(); delete viewerMap[id]; } const d = $('#rdesk-view-' + id); if (d) d.remove(); }

  // Этап 28: file transfer поверх SSH (список/скачать/залить)
  function openXfer(s) {
    const dlg = el('div', 'card'); dlg.id = 'rdesk-xfer-' + s.id;
    dlg.style.cssText = 'position:fixed;inset:10% 20%;z-index:9998;background:#111;overflow:auto';
    dlg.appendChild(el('h3', null, `Файлы — ${s.host_name} (${s.host})`));
    const pathIn = el('input'); pathIn.value = '/home/' + (s.host_name || ''); pathIn.style.width = '60%';
    const bList = el('button', 'btn', '📂 список'); const out = el('pre'); out.style.cssText = 'background:#000;padding:6px;max-height:40vh;overflow:auto';
    bList.onclick = async () => { try { const r = await invoke('rdesk_xfer_list', { hostId: hostIdOf(s), remotePath: pathIn.value }); out.textContent = r.listing; } catch (e) { out.textContent = 'ошибка: ' + e; } };
    const row = el('div', 'row'); row.appendChild(pathIn); row.appendChild(bList); dlg.appendChild(row); dlg.appendChild(out);
    const upRow = el('div', 'row');
    const upLocal = el('input'); upLocal.placeholder = 'локальный файл'; upLocal.style.flex = '1';
    const upBtn = el('button', 'btn', '⬆ залить'); upBtn.onclick = async () => {
      try { const r = await invoke('rdesk_xfer_up', { hostId: hostIdOf(s), localPath: upLocal.value, remotePath: pathIn.value + '/' + upLocal.value.split('/').pop() }); out.textContent = JSON.stringify(r); } catch (e) { out.textContent = 'ошибка: ' + e; }
    };
    upRow.appendChild(upLocal); upRow.appendChild(upBtn); dlg.appendChild(upRow);
    const dnRow = el('div', 'row');
    const dnRemote = el('input'); dnRemote.placeholder = 'удалённый файл (напр. /var/log/syslog)'; dnRemote.style.flex = '1';
    const dnBtn = el('button', 'btn', '⬇ скачать'); dnBtn.onclick = async () => {
      try { const r = await invoke('rdesk_xfer_down', { hostId: hostIdOf(s), remotePath: dnRemote.value, localPath: (window.__W420_HOME__ || '/tmp') + '/.w420/dl-' + dnRemote.value.split('/').pop() }); out.textContent = JSON.stringify(r); } catch (e) { out.textContent = 'ошибка: ' + e; }
    };
    dnRow.appendChild(dnRemote); dnRow.appendChild(dnBtn); dlg.appendChild(dnRow);
    const bClose = el('button', 'btn danger', '✕'); bClose.onclick = () => dlg.remove();
    dlg.appendChild(bClose);
    document.body.appendChild(dlg);
    bList.click();
  }
  // узнаём host_id сессии из списка (нужен для xfer-команд)
  async function hostIdOf(s) {
    try { const d = await invoke('rdesk_sessions'); const cur = d.sessions.find((x) => x.id === s.id); if (cur && cur.hostId) return cur.hostId; } catch (e) {}
    // фолбэк: ищем в инвентаре по IP
    try { const h = await invoke('hosts_list'); const hh = (h.hosts || h).find((x) => x.ip === s.host); if (hh) return hh.id; } catch (e) {}
    return s.host;
  }

  // Кнопки VNC/RDP на карточках хостов (делегирование — карточки рисуются hosts.js)
  document.addEventListener('click', async (ev) => {
    const b = ev.target.closest('button'); if (!b) return;
    const act = b.dataset.rdesk; if (!act) return;
    const card = b.closest('[data-host-id]'); const hid = card && card.dataset.hostId;
    if (!hid) return;
    try {
      const s = await invoke('rdesk_connect', { hostId: hid, proto: act, port: null });
      if (s.proto === 'vnc') openViewer(s);
      refreshSessions();
    } catch (e) { alert('rdesk: ' + e); }
  });

  // подмешиваем кнопки в карточки хостов при отрисовке
  const mo = new MutationObserver(() => {
    document.querySelectorAll('#v-net [data-host-id], #v-net .host-card').forEach((card) => {
      if (card.querySelector('[data-rdesk]')) return;
      const hid = card.dataset.hostId || (card.querySelector('[data-id]') || {}).dataset?.id;
      if (!hid || card.dataset.rdeskDone) return;
      card.dataset.rdeskDone = '1'; card.dataset.hostId = hid;
      const row = el('div', 'row');
      const v = el('button', 'btn', '🖥 VNC'); v.dataset.rdesk = 'vnc';
      const r = el('button', 'btn', '🪟 RDP'); r.dataset.rdesk = 'rdp';
      row.appendChild(v); row.appendChild(r); card.appendChild(row);
    });
  });
  document.addEventListener('DOMContentLoaded', () => { ensurePanel(); mo.observe($('#v-net') || document.body, { childList: true, subtree: true }); });
})();

// smartcard.js — Этап 33: Smart-Card (PKCS#11/OpenSC). Нативный режим только.
(() => {
  if (!(window.__TAURI__ && window.__TAURI__.core)) return;
  const { invoke } = window.__TAURI__.core;

  function el(tag, cls, txt) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt !== undefined) e.textContent = txt;
    return e;
  }

  async function refresh() {
    const st = await invoke('sc_status');
    const badge = document.querySelector('#sc-badge');
    badge.textContent = st.tool ? `pkcs11-tool OK, модуль: ${st.module}` : 'pkcs11-tool НЕ установлен (apt install opensc)';
    badge.style.color = st.tool ? 'var(--ok,#4caf50)' : 'var(--bad,#f44336)';
    if (!st.tool) return;
    try {
      const tokens = await invoke('sc_tokens');
      const tl = document.querySelector('#sc-tokens');
      tl.innerHTML = '';
      for (const t of tokens.tokens) tl.appendChild(el('li', '', `Слот ${t.slot}: ${t.label} (серийник ${t.serial_number || '—'})`));
      if (!tokens.tokens.length) tl.appendChild(el('li', '', 'Токенов не найдено — вставьте карту'));
      const certs = await invoke('sc_certs');
      const cl = document.querySelector('#sc-certs');
      cl.innerHTML = '';
      for (const c of certs.certs) {
        const li = el('li', '', `${c.label || 'сертификат'} (ID ${c.id || '—'})`);
        cl.appendChild(li);
      }
      const objs = await invoke('sc_objects');
      const sel = document.querySelector('#sc-keyid');
      sel.innerHTML = '';
      for (const o of objs.objects) {
        if (o.type === 'private_key') {
          const opt = el('option', '', `${o.label || 'key'} (ID ${o.id || '?'})`);
          opt.value = o.id || '';
          sel.appendChild(opt);
        }
      }
    } catch (e) { console.error('sc refresh', e); }
  }

  async function sign() {
    const keyId = document.querySelector('#sc-keyid').value;
    const data = document.querySelector('#sc-data').value.trim();
    const pin = document.querySelector('#sc-pin').value;
    if (!keyId) return alert('Нет приватного ключа на карте');
    if (!/^[0-9a-fA-F]*$/.test(data) || data.length % 2) return alert('Данные — hex чётной длины (или оставьте пустым?) нет: введите hex');
    const hexData = data || Buffer_hex('w420');
    if (!confirm(`Подписать ${hexData.length / 2} байт ключом ID=${keyId}? PIN уйдёт на карту, в логи не попадёт.`)) return;
    try {
      const r = await invoke('sc_sign', { keyId, dataHex: hexData, pin });
      document.querySelector('#sc-sig').textContent = `Подпись (${r.sig_len} байт): ${r.signature_hex.slice(0, 96)}…`;
    } catch (e) {
      alert('Ошибка подписи: ' + e);
    } finally {
      document.querySelector('#sc-pin').value = '';
    }
  }

  function Buffer_hex(s) { // текст → hex
    return Array.from(new TextEncoder().encode(s)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  document.addEventListener('DOMContentLoaded', () => {
    const host = document.querySelector('#v-net .panel') || document.body;
    const panel = el('div', 'panel');
    panel.appendChild(el('h3', '', '💳 Smart-Card (PKCS#11)'));
    const badge = el('div', '', ''); badge.id = 'sc-badge';
    panel.appendChild(badge);
    panel.appendChild(el('h4', '', 'Токены'));
    const tl = el('ul'); tl.id = 'sc-tokens';
    panel.appendChild(tl);
    panel.appendChild(el('h4', '', 'Сертификаты'));
    const cl = el('ul'); cl.id = 'sc-certs';
    panel.appendChild(cl);
    const row = el('div', 'row');
    const sel = el('select'); sel.id = 'sc-keyid';
    const dataIn = el('input'); dataIn.id = 'sc-data'; dataIn.placeholder = 'Данные (hex)';
    const pinIn = el('input'); pinIn.id = 'sc-pin'; pinIn.type = 'password'; pinIn.placeholder = 'PIN (не логируется)';
    const bSign = el('button', 'btn', '✍ Подписать'); bSign.onclick = sign;
    const bRef = el('button', 'btn', '↻ Обновить'); bRef.onclick = refresh;
    row.append(sel, dataIn, pinIn, bSign, bRef);
    panel.appendChild(row);
    panel.appendChild(el('div', '', '')).id = '';
    const sig = el('div'); sig.id = 'sc-sig'; sig.style.cssText = 'word-break:break-all;font-size:12px;';
    panel.appendChild(sig);
    host.appendChild(panel);
    refresh();
  });
})();

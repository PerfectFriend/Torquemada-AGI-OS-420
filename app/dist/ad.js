// ad.js — Этап 31: Active Directory (LDAP). Только нативный режим.
// Пароль bind вводится один раз и уходит в зашифрованный ~/.w420/ad.json; в UI — только маска.
(function () {
  if (!(window.__TAURI__ && window.__TAURI__.core)) return;
  const invoke = window.__TAURI__.core.invoke;
  const $ = (s, r) => (r || document).querySelector(s);
  const el = (t, c, txt) => { const e = document.createElement(t); if (c) e.className = c; if (txt != null) e.textContent = txt; return e; };

  let panel, out;
  function ensure() {
    if ($('#ad-panel')) return;
    const net = $('#v-net'); if (!net) return;
    panel = el('div', 'card'); panel.id = 'ad-panel';
    panel.appendChild(el('h3', null, 'ACTIVE DIRECTORY (этап 31, LDAP)'));
    // настройка
    const cfgRow = el('div', 'row');
    const server = el('input'); server.placeholder = 'dc.corp.local'; server.id = 'ad-server';
    const bindDn = el('input'); bindDn.placeholder = 'CORP\\svc-w420'; bindDn.id = 'ad-binddn';
    const baseDn = el('input'); baseDn.placeholder = 'DC=corp,DC=local'; baseDn.id = 'ad-basedn';
    const pw = el('input'); pw.type = 'password'; pw.placeholder = 'bind-пароль (хранится зашифрованно)'; pw.id = 'ad-pw';
    const bCfg = el('button', 'btn', '💾 сохранить конфиг');
    bCfg.onclick = async () => {
      try {
        const r = await invoke('ad_config_set', { server: server.value, port: null, bindDn: bindDn.value, bindPassword: pw.value, baseDn: baseDn.value, useTls: true });
        show(`Конфиг сохранён: ${r.server}:${r.port} bind=${r.bind_dn} пароль=${r.password_mask}`);
        pw.value = '';
      } catch (e) { show('ошибка: ' + e); }
    };
    const bPing = el('button', 'btn', '🏓 ping AD'); bPing.onclick = async () => { try { show(JSON.stringify(await invoke('ad_ping'))); } catch (e) { show('ошибка: ' + e); } };
    cfgRow.appendChild(server); cfgRow.appendChild(bindDn); cfgRow.appendChild(baseDn); cfgRow.appendChild(pw); cfgRow.appendChild(bCfg); cfgRow.appendChild(bPing);
    panel.appendChild(cfgRow);
    // действия
    const row = el('div', 'row');
    const mk = (label, fn) => { const b = el('button', 'btn', label); b.onclick = fn; row.appendChild(b); };
    mk('🌳 OU tree', async () => { try { const r = await invoke('ad_tree'); show(r.ous.map(o => `${o.ou}  ${o.dn}`).join('\n') || 'нет OU'); } catch (e) { show('ошибка: ' + e); } });
    mk('👥 users', async () => {
      const f = prompt('Фильтр (пусто = все):', '');
      try { const r = await invoke('ad_users_search', { filter: f || null }); show(r.users.map(u => `${u.login}  ${u.cn}  ${u.locked ? '🔒' : ''}  ${u.dn}`).join('\n').slice(0, 8000)); window.__adUsers = r.users; } catch (e) { show('ошибка: ' + e); }
    });
    mk('👪 groups', async () => { try { const r = await invoke('ad_groups'); show(r.groups.map(g => `${g.cn} (${g.members_count})  ${g.dn}`).join('\n').slice(0, 8000)); } catch (e) { show('ошибка: ' + e); } });
    mk('📜 GPO', async () => { try { const r = await invoke('ad_gpo_list'); show(r.gpos.map(g => `${g.name}  ${g.dn}`).join('\n') || 'нет GPO'); } catch (e) { show('ошибка: ' + e); } });
    mk('🔓 unlock user', async () => {
      const dn = prompt('DN пользователя:'); if (!dn) return;
      if (!confirm(`Разблокировать ${dn}?`)) return;
      try { show(JSON.stringify(await invoke('ad_user_unlock', { userDn: dn }))); } catch (e) { show('ошибка: ' + e); }
    });
    mk('🔑 reset password', async () => {
      const dn = prompt('DN пользователя:'); if (!dn) return;
      const np = prompt('Новый пароль (мин. 8 символов):'); if (!np) return;
      if (!confirm(`СБРОСИТЬ пароль у ${dn}? Действие необратимо.`)) return;
      try { show(JSON.stringify(await invoke('ad_user_reset_password', { userDn: dn, newPassword: np, mustChange: true }))); } catch (e) { show('ошибка: ' + e); }
    });
    mk('➕ в группу', async () => {
      const g = prompt('DN группы:'); const m = prompt('DN участника:');
      if (!g || !m || !confirm(`Добавить ${m} в ${g}?`)) return;
      try { show(JSON.stringify(await invoke('ad_group_add_member', { groupDn: g, memberDn: m }))); } catch (e) { show('ошибка: ' + e); }
    });
    mk('➖ из группы', async () => {
      const g = prompt('DN группы:'); const m = prompt('DN участника:');
      if (!g || !m || !confirm(`Удалить ${m} из ${g}?`)) return;
      try { show(JSON.stringify(await invoke('ad_group_remove_member', { groupDn: g, memberDn: m }))); } catch (e) { show('ошибка: ' + e); }
    });
    mk('📤 экспорт CSV', () => exportAd('users', 'csv'));
    mk('📤 экспорт XML', () => exportAd('groups', 'xml'));
    panel.appendChild(row);
    out = el('pre'); out.style.cssText = 'background:#000;padding:6px;max-height:35vh;overflow:auto;white-space:pre-wrap';
    panel.appendChild(out);
    net.appendChild(panel);
    invoke('ad_config_get').then(r => { server.value = r.server || ''; bindDn.value = r.bind_dn || ''; baseDn.value = r.base_dn || ''; show('AD настроен: ' + r.server + ' (пароль ' + r.password_mask + ')'); }).catch(() => show('AD не настроен — заполните поля выше'));
  }
  async function exportAd(what, format) {
    try {
      const p = (window.__W420_HOME__ || '/tmp') + `/.w420/ad-${what}.${format}`;
      const r = await invoke('ad_export', { what, format, outPath: p });
      show(`Экспорт: ${r.path} (объектов: ${r.objects})`);
    } catch (e) { show('ошибка: ' + e); }
  }
  function show(t) { out.textContent = String(t); }
  document.addEventListener('DOMContentLoaded', ensure);
})();

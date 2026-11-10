/* W420 SYSOPS UI (native shell): scope approval, Trivy/gitleaks scans, file integrity monitor. Read-only tools. */
(function () {
  if (typeof window === 'undefined' || !window.__TAURI__) return;
  var inv = window.__TAURI__.core.invoke, Q = function (s) { return document.querySelector(s); };
  var aud = function (a, d) { try { if (typeof audit === 'function') audit('sysops', a + (d ? ': ' + d : '')); } catch (e) {} };
  var note = function (t, bad) { var e = Q('#sostat'); if (e) { e.textContent = t; e.style.color = bad ? 'var(--wip)' : ''; } };
  var SEV = { critical: 'var(--sim)', high: 'var(--sim)', medium: 'var(--wip)', low: 'var(--live)', info: 'var(--live)' };
  var lastReport = [];
  var lastUpdates = [];

  function renderScope(list) {
    var box = Q('#soscope'); box.innerHTML = '';
    if (!list.length) { box.textContent = 'Область пуста: добавьте папку, чтобы включить сканирование.'; return; }
    list.forEach(function (p) { var d = document.createElement('div'); d.className = 'item'; d.innerHTML = '<span></span>'; d.firstChild.textContent = p; box.appendChild(d); });
  }
  async function refreshScope() { try { renderScope(await inv('sysops_get_scope')); } catch (e) {} }
  async function addScope() {
    var p = Q('#sopath').value.trim(); if (!p) return;
    try {
      var cur = await inv('sysops_get_scope'); var next = cur.concat([p]);
      var got = await inv('sysops_set_scope', { paths: next }); renderScope(got); Q('#sopath').value = '';
      note('Область обновлена.'); aud('scope set', got.join(' ; '));
    } catch (e) { note(String(e && e.message || e), true); }
  }
  async function clearScope() { try { var got = await inv('sysops_set_scope', { paths: [] }); renderScope(got); note('Область очищена.'); aud('scope cleared'); } catch (e) { note(String(e), true); } }

  function renderFindings(findings) {
    lastReport = findings;
    var box = Q('#solist'); box.innerHTML = '';
    if (!findings.length) { box.textContent = 'Находок нет.'; return; }
    var order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    findings.slice().sort(function (a, b) { var oa = a.severity in order ? order[a.severity] : 9, ob = b.severity in order ? order[b.severity] : 9; return oa - ob; }).forEach(function (f) {
      var d = document.createElement('div'); d.className = 'item'; d.style.flexWrap = 'wrap'; d.style.alignItems = 'flex-start';
      var sev = document.createElement('span'); sev.className = 'b'; sev.style.setProperty('--c', SEV[f.severity] || 'var(--wip)'); sev.textContent = f.severity.toUpperCase();
      var main = document.createElement('span'); main.style.flex = '1'; main.textContent = '[' + f.tool + '] ' + f.title + ' — ' + f.location + (f.detail ? ' (' + f.detail + ')' : '');
      d.append(sev, main); box.appendChild(d);
    });
    var counts = {}; findings.forEach(function (f) { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    note('Находок: ' + findings.length + ' (' + Object.keys(counts).map(function (k) { return k + ':' + counts[k]; }).join(', ') + ')', findings.length > 0);
  }
  async function runScan(cmd, args, toolLabel) {
    note('Сканирую (' + toolLabel + ')…'); Q('#solist').textContent = '';
    try { var r = await inv(cmd, args); renderFindings(r.findings); aud(toolLabel + ' scan', r.raw_summary); }
    catch (e) { note(String(e && e.message || e), true); aud(toolLabel + ' scan failed', String(e && e.message || e)); }
  }
  async function exportVault() {
    if (!lastReport.length) return note('Сначала сделайте скан.', true);
    var pw = Q('#sopw').value; if (!pw) return note('Введите пароль vault.', true);
    try {
      Q('#vn').value = 'sysops-report-' + new Date().toISOString().slice(0, 16);
      Q('#vt').value = JSON.stringify(lastReport, null, 1); Q('#vp').value = pw; Q('#vput').click(); Q('#vp').value = ''; Q('#sopw').value = '';
      note('Отчёт сохранён в QFS Vault.'); aud('report exported to vault', String(lastReport.length));
    } catch (e) { note(String(e), true); }
  }
  async function aiTriage() {
    if (!lastReport.length) return note('Сначала сделайте скан.', true);
    if (typeof goAI !== 'function') return note('ИИ недоступен: подключите его на вкладке AI CORE.', true);
    var top = lastReport.slice(0, 20).map(function (f) { return f.severity + ' [' + f.tool + '] ' + f.title + ' — ' + f.location; }).join('\n');
    goAI('Вот находки сканирования (Trivy/gitleaks), не придумывай новых и не меняй версии/CVE — используй только этот список. Расставь приоритеты по риску (учти критичность и доступность из сети, если это видно по описанию), для каждого пункта дай короткую рекомендацию по устранению. Будь краток.\n\n' + top);
  }

  // file integrity monitor
  async function fimBaseline() { var p = Q('#sofim').value.trim(); if (!p) return; try { var n = await inv('sysops_fim_baseline', { path: p }); note('Снимок сохранён: файлов ' + n); aud('fim baseline', p + ' files=' + n); } catch (e) { note(String(e && e.message || e), true); } }
  async function fimCheck() {
    var p = Q('#sofim').value.trim(); if (!p) return;
    try {
      var d = await inv('sysops_fim_check', { path: p });
      if (!d.has_baseline) { note('Снимка ещё нет: сначала «Сохранить снимок».', true); return; }
      var box = Q('#sofimres'); box.innerHTML = '';
      var line = function (label, arr, color) { arr.forEach(function (f) { var el = document.createElement('div'); el.style.color = color; el.textContent = label + ': ' + f; box.appendChild(el); }); };
      line('добавлен', d.added, 'var(--wip)'); line('изменён', d.changed, 'var(--sim)'); line('удалён', d.removed, 'var(--wip)');
      var total = d.added.length + d.changed.length + d.removed.length;
      note(total ? ('Изменений: ' + total) : 'Изменений нет.', total > 0);
      if (total) aud('fim changes', p + ' +' + d.added.length + ' ~' + d.changed.length + ' -' + d.removed.length);
    } catch (e) { note(String(e && e.message || e), true); }
  }


  var UPD_CMD = { apt: 'sudo apt upgrade', dnf: 'sudo dnf upgrade', brew: 'brew upgrade', winget: 'winget upgrade --all' };
  function renderUpdates(reports) {
    var box = Q('#soupdlist'); box.innerHTML = '';
    var total = 0, sec = 0, lines = [];
    reports.forEach(function (r) {
      if (!r.ok) { var e = document.createElement('div'); e.style.color = 'var(--wip)'; e.textContent = '[' + r.manager + '] ' + r.note; box.appendChild(e); return; }
      if (r.note) { var n = document.createElement('div'); n.style.opacity = '.7'; n.textContent = '[' + r.manager + '] ' + r.note; box.appendChild(n); }
      r.packages.forEach(function (p) {
        total++; if (p.security) sec++;
        var d = document.createElement('div'); d.className = 'item';
        var badge = document.createElement('span'); badge.className = 'b'; badge.style.setProperty('--c', p.security ? 'var(--sim)' : 'var(--live)'); badge.textContent = p.security ? 'SECURITY' : r.manager.toUpperCase();
        var main = document.createElement('span'); main.style.flex = '1';
        main.textContent = p.name + ': ' + (p.installed || '?') + ' → ' + p.available + (p.source ? ' (' + p.source + ')' : '');
        d.append(badge, main); box.appendChild(d);
        lines.push(p.security ? 'security' : 'update', '[' + r.manager + '] ' + p.name + ' ' + (p.installed || '?') + ' -> ' + p.available);
      });
      if (r.packages.length) { var c = document.createElement('div'); c.className = 'mono'; c.style.opacity = '.7'; c.style.marginTop = '4px'; c.textContent = 'Установить всё из ' + r.manager + ': ' + (UPD_CMD[r.manager] || '?'); box.appendChild(c); }
    });
    if (!total) box.textContent = box.textContent || 'Устаревших пакетов не найдено (или ни один менеджер не обнаружен).';
    lastUpdates = reports;
    note('Обновлений: ' + total + (sec ? ' (из них безопасности: ' + sec + ')' : ''), sec > 0);
    aud('updates checked', 'total=' + total + ' security=' + sec);
  }
  async function checkUpdates() {
    note('Проверяю обновления…'); Q('#soupdlist').textContent = '';
    try { renderUpdates(await inv('updates_check')); } catch (e) { note(String(e && e.message || e), true); }
  }
  async function updatesAiTriage() {
    if (!lastUpdates.length) return note('Сначала проверьте обновления.', true);
    if (typeof goAI !== 'function') return note('ИИ недоступен: подключите его на вкладке AI CORE.', true);
    var sec = []; lastUpdates.forEach(function (r) { r.packages.forEach(function (p) { if (p.security) sec.push('[' + r.manager + '] ' + p.name + ' ' + (p.installed || '?') + ' -> ' + p.available); }); });
    if (!sec.length) return note('Обновлений безопасности не найдено.');
    goAI('Вот пакеты с обновлениями безопасности (не придумывай новые, не меняй версии — только этот список): ' + sec.slice(0, 30).join('; ') + '. Кратко объясни риск на простом языке и порекомендуй порядок обновления.');
  }


  var hstat = function (t, bad) { var e = Q('#hstat'); if (e) { e.textContent = t; e.style.color = bad ? 'var(--wip)' : ''; } };
  function hCard(kind, title, bodyHtml, onApprove) {
    var d = document.createElement('div'); d.className = 'card';
    var h = document.createElement('div'); h.className = 'k'; h.textContent = 'ПОДТВЕРДИТЕ: ' + title;
    var body = document.createElement('div'); body.className = 'mono'; body.innerHTML = bodyHtml;
    var row = document.createElement('div'); row.className = 'row';
    var ok = document.createElement('button'); ok.className = 'a'; ok.textContent = 'APPROVE — ПРИМЕНИТЬ';
    var no = document.createElement('button'); no.className = 'a'; no.textContent = 'REJECT'; no.style.setProperty('--c', 'var(--sim)');
    var done = function (s) { row.remove(); body.innerHTML += '<div style="margin-top:6px">' + s + '</div>'; };
    ok.onclick = function () { ok.disabled = true; no.disabled = true; onApprove().then(function (s) { done(s); aud(kind + ' approved', s.slice(0, 160)); }).catch(function (e) { done('Ошибка: ' + (e && e.message || e)); aud(kind + ' apply failed', String(e && e.message || e)); }); };
    no.onclick = function () { done('отклонено'); aud(kind + ' rejected'); };
    row.append(ok, no); d.append(h, body, row); return d;
  }

  var sysctlPlan = null;
  async function sysctlShowPlan() {
    hstat('Читаю текущие параметры…');
    try { sysctlPlan = await inv('harden_sysctl_plan'); } catch (e) { return hstat(String(e && e.message || e), true); }
    var box = Q('#hsyslist'); box.innerHTML = '';
    if (!sysctlPlan.items.length) { box.textContent = 'Все рекомендованные параметры уже установлены.'; hstat(''); return; }
    var rows = sysctlPlan.items.map(function (it) { return it.key + ': ' + it.current + ' → <b>' + it.recommended + '</b> — ' + it.reason; }).join('<br>');
    box.appendChild(hCard('sysctl', 'применить ' + sysctlPlan.items.length + ' параметр(ов) ядра', rows + '<br><br>Файл: ' + sysctlPlan.drop_in_path, function () { return inv('harden_sysctl_apply'); }));
    hstat('');
  }
  async function sysctlRevert() { try { hstat(await inv('harden_sysctl_revert')); aud('sysctl reverted'); } catch (e) { hstat(String(e && e.message || e), true); } }

  var sshPlan = null;
  async function sshShowPlan() {
    hstat('Читаю sshd_config…');
    try { sshPlan = await inv('harden_ssh_plan'); } catch (e) { return hstat(String(e && e.message || e), true); }
    var box = Q('#hsshlist'); box.innerHTML = '';
    var real = sshPlan.changes.filter(function (c) { return !c.skipped_reason; });
    var skipped = sshPlan.changes.filter(function (c) { return c.skipped_reason; });
    var parts = [];
    if (!real.length) parts.push('Изменений не требуется.');
    else parts.push(real.map(function (c) { return c.directive + ': ' + c.current + ' → <b>' + c.recommended + '</b> — ' + c.reason; }).join('<br>'));
    skipped.forEach(function (c) { parts.push('<span style="color:var(--wip)">пропущено: ' + c.directive + ' — ' + c.skipped_reason + '</span>'); });
    parts.push('<br><pre style="white-space:pre-wrap;margin:4px 0">' + sshPlan.diff.replace(/</g, '&lt;') + '</pre>');
    if (real.length) box.appendChild(hCard('ssh', 'записать ' + sshPlan.config_path + ' (служба не перезапускается сама)', parts.join('<br>'), function () { return inv('harden_ssh_apply'); }));
    else { var d = document.createElement('div'); d.className = 'mono'; d.innerHTML = parts.join('<br>'); box.appendChild(d); }
    hstat('');
  }
  async function sshRevert() { try { hstat(await inv('harden_ssh_revert')); aud('ssh reverted'); } catch (e) { hstat(String(e && e.message || e), true); } }

  function build() {
    if (Q('#v-sysops') || !Q('#v-radio') || !Q('nav')) return;
    var sec = document.createElement('section'); sec.className = 'view live'; sec.id = 'v-sysops';
    sec.innerHTML =
      '<h2>SYSOPS <span class="b live">LIVE</span></h2>' +
      '<div class="mono" style="opacity:.8">Только чтение: уязвимости, секреты и целостность файлов — в папках, которые вы явно разрешили. Ничего не исправляется само.</div>' +
      '<div class="card"><div class="k">ОБЛАСТЬ ПРОВЕРКИ</div><div id="soscope" class="mono"></div>' +
      '<div class="row" style="margin-top:6px"><input id="sopath" placeholder="путь к папке, например /home/user/project"><button class="a" id="soaddpath">ДОБАВИТЬ</button><button class="a" id="soclear">ОЧИСТИТЬ</button></div></div>' +
      '<div class="card"><div class="k">СКАНЫ</div><div class="row">' +
      '<button class="a" id="sotrivy">TRIVY: УЯЗВИМОСТИ + СЕКРЕТЫ</button><button class="a" id="sogl">GITLEAKS: СЕКРЕТЫ</button><label class="mono"><input type="checkbox" id="soglhist" style="width:auto"> вкл. историю git</label></div>' +
      '<div class="row" style="margin-top:6px"><button class="a" id="soai">РАЗБОР ИИ (без новых CVE)</button><input id="sopw" type="password" placeholder="пароль vault"><button class="a" id="soexport">СОХРАНИТЬ ОТЧЁТ В VAULT</button></div>' +
      '<div class="mono" id="sostat">—</div><div id="solist" class="mono" style="max-height:220px;overflow:auto"></div></div>' +
      '<div class="card"><div class="k">ОБНОВЛЕНИЯ СИСТЕМЫ (только чтение, ничего не ставит)</div>' +
      '<div class="mono" style="opacity:.8">Опрашивает ваш менеджер пакетов (apt/dnf/brew/winget). Установка — вручную, командой, которую вы видите ниже.</div>' +
      '<div class="row"><button class="a" id="soupd">ПРОВЕРИТЬ ОБНОВЛЕНИЯ</button><button class="a" id="soupdai">РАЗБОР ИИ (безопасность)</button></div>' +
      '<div class="mono" id="soupdstat">—</div><div id="soupdlist" class="mono" style="max-height:200px;overflow:auto"></div></div>' +
      
      '<div class="card"><div class="k">УСИЛЕНИЕ ЗАЩИТЫ (sysctl, SSH) <span class="b wip">ТРЕБУЕТ ПОДТВЕРЖДЕНИЯ</span></div>' +
      '<div class="mono" style="opacity:.8">Ничего не применяется без явного одобрения ниже. Перед записью — резервная копия; sysctl можно откатить кнопкой, SSH — из резервной копии. Изменения sshd_config НЕ перезапускают службу сами: это нужно сделать вручную, после проверки.</div>' +
      '<div class="row"><button class="a" id="hsysplan">SYSCTL: ПОКАЗАТЬ РЕКОМЕНДАЦИИ</button><button class="a" id="hsysrevert">SYSCTL: ОТКАТИТЬ</button></div>' +
      '<div id="hsyslist" class="mono" style="margin:6px 0"></div>' +
      '<div class="row"><button class="a" id="hsshplan">SSH: ПОКАЗАТЬ РЕКОМЕНДАЦИИ</button><button class="a" id="hsshrevert">SSH: ОТКАТИТЬ ИЗ КОПИИ</button></div>' +
      '<div id="hsshlist" class="mono" style="margin:6px 0"></div>' +
      '<div class="mono" id="hstat">—</div></div>'
 +
      '<div class="card"><div class="k">ЦЕЛОСТНОСТЬ ФАЙЛОВ (SHA-256)</div>' +
      '<div class="row"><input id="sofim" placeholder="папка для снимка (внутри области)"><button class="a" id="sofimbase">СОХРАНИТЬ СНИМОК</button><button class="a" id="sofimcheck">ПРОВЕРИТЬ ИЗМЕНЕНИЯ</button></div>' +
      '<div id="sofimres" class="mono" style="margin-top:6px"></div></div>';
    Q('#v-radio').parentNode.appendChild(sec);
    var btn = document.createElement('button'); btn.className = 'live'; btn.textContent = 'SYSOPS'; btn.dataset.id = 'sysops'; btn.onclick = function () { show('sysops'); }; Q('nav').appendChild(btn);
    Q('#soaddpath').onclick = addScope; Q('#soclear').onclick = clearScope;
    Q('#sotrivy').onclick = function () { var p = Q('#sopath').value.trim() || (Q('#soscope').firstChild && Q('#soscope').firstChild.textContent); if (!p) return note('Укажите путь (поле выше) или добавьте его в область.', true); runScan('sysops_scan_trivy', { path: p }, 'trivy'); };
    Q('#sogl').onclick = function () { var p = Q('#sopath').value.trim() || (Q('#soscope').firstChild && Q('#soscope').firstChild.textContent); if (!p) return note('Укажите путь (поле выше) или добавьте его в область.', true); runScan('sysops_scan_gitleaks', { path: p, includeGitHistory: Q('#soglhist').checked }, 'gitleaks'); };
    Q('#soai').onclick = aiTriage; Q('#soexport').onclick = exportVault;
    Q('#sofimbase').onclick = fimBaseline; Q('#sofimcheck').onclick = fimCheck;
    Q('#soupd').onclick = checkUpdates; Q('#soupdai').onclick = updatesAiTriage;
    Q('#hsysplan').onclick = sysctlShowPlan; Q('#hsysrevert').onclick = sysctlRevert;
    Q('#hsshplan').onclick = sshShowPlan; Q('#hsshrevert').onclick = sshRevert;
    refreshScope();
  }
  build();
  window.W420SysOps = { build: build, lastReport: function () { return lastReport; } };
})();

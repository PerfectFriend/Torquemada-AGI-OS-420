/* W420 BRIDGE UI (native shell): profiles (encrypted at rest), modes, connect/disconnect, status, exit check. */
(function () {
  if (typeof window === 'undefined' || !window.__TAURI__ || !window.W420BridgeConfig) return;
  var inv = window.__TAURI__.core.invoke, CFG = window.W420BridgeConfig, Q = function (s) { return document.querySelector(s); };
  var LS = { get: function (k, d) { try { var v = localStorage.getItem(k); return v == null ? d : v; } catch (e) { return d; } }, set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) {} } };
  var P = [], statusTimer = 0, connected = false, mode = 'proxy', port = 2080;
  var aud = function (a, d) { try { if (typeof audit === 'function') audit('bridge', a + (d ? ': ' + d : '')); } catch (e) {} };
  var note = function (t, bad) { var e = Q('#brstat'); if (e) { e.textContent = t; e.style.color = bad ? 'var(--wip)' : ''; } };
  var uid = function () { return Math.random().toString(36).slice(2, 10); };

  function render() {
    var box = Q('#brlist'); box.innerHTML = '';
    if (!P.length) { box.textContent = 'Профилей нет: вставьте ссылки, WireGuard или OpenVPN ниже.'; return; }
    P.forEach(function (p) {
      var row = document.createElement('div'); row.className = 'item';
      var cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = p.enabled; cb.style.width = 'auto'; cb.onchange = function () { p.enabled = cb.checked; };
      var nm = document.createElement('span'); nm.textContent = p.name + ' · ' + p.singbox.type + (p.needsAuth ? ' · нужен логин' : '');
      var del = document.createElement('button'); del.className = 'a'; del.textContent = '✕'; del.onclick = function () { P = P.filter(function (x) { return x !== p; }); render(); };
      row.append(cb, nm, del); box.appendChild(row);
    });
  }
  function importText(text, fname) {
    var added = 0, bad = [];
    try {
      if (/\[Interface\]/i.test(text)) { var w = CFG.parseWireGuardConf(text, fname || 'WireGuard'); P.push(Object.assign(w, { id: uid(), enabled: true })); added++; }
      else if (/^\s*remote\s+\S+/m.test(text) && /<ca>|^\s*client\s*$/m.test(text)) {
        var o = CFG.parseOvpn(text, fname || 'OpenVPN', { username: Q('#bruser').value.trim(), password: Q('#brpass').value });
        if (o.needsAuth) { note('Этому .ovpn нужны логин и пароль: введите их выше и импортируйте снова.', true); return; }
        P.push(Object.assign(o, { id: uid(), enabled: true })); added++;
      } else { var r = CFG.parseProfiles(text); r.ok.forEach(function (x) { P.push(Object.assign(x, { id: uid(), enabled: true })); added++; }); bad = r.bad; }
    } catch (e) { note(e.message, true); return; }
    render(); note('Добавлено профилей: ' + added + (bad.length ? ' · не распознано: ' + bad.length + ' (' + bad[0].error + ')' : ''), !added);
    if (added) aud('profiles imported', String(added));
  }
  async function saveEnc() {
    var pw = Q('#brpw').value; if (!pw) return note('Введите пароль для шифрования.', true);
    var blob = await window.W420Crypto.encryptSecret(JSON.stringify(P), pw, window.crypto); LS.set('w420.bridge.enc', JSON.stringify(blob)); Q('#brpw').value = '';
    note('Профили сохранены зашифрованно (AES-256-GCM, ключ из пароля).');
  }
  async function unlock() {
    var pw = Q('#brpw').value, raw = LS.get('w420.bridge.enc', ''); if (!raw) return note('Сохранённых профилей нет.', true); if (!pw) return note('Введите пароль.', true);
    try { P = JSON.parse(await window.W420Crypto.decryptSecret(JSON.parse(raw), pw, window.crypto)); Q('#brpw').value = ''; render(); note('Профилей загружено: ' + P.length); }
    catch (e) { note('Неверный пароль.', true); }
  }
  function opts() {
    return { mode: Q('#brmode').value, via: Q('#brvia').value, failover: Q('#brfail').value, port: parseInt(Q('#brport').value, 10) || 2080, torPort: 9150,
      bypassPrivate: Q('#brlan').checked, strict: Q('#brstrict').checked, bootstrap: Q('#brboot').value.trim() || '1.1.1.1', remoteDns: Q('#brdns').value.trim() || '1.1.1.1', logLevel: 'info' };
  }
  async function connect() {
    var o = opts(), prof = P.filter(function (p) { return p.enabled; });
    if (o.via === 'torOnly') { o.via = 'tor'; prof = []; }
    try {
      if (o.via !== 'direct') {
        try { await inv('tor_start', { socksPort: o.torPort, bridges: [] }); } catch (e) { return note('Tor-движок недоступен в этой сборке (' + (e && e.message || e) + ').', true); }
        var ready = false;
        for (var i = 0; i < 180 && !ready; i++) {
          var t = await inv('tor_status');
          if (t.state === 'error') return note('Tor: ' + t.message, true);
          if (t.state === 'ready') { ready = true; break; }
          note('Tor: ' + Math.round((t.progress || 0) * 100) + '% ' + (t.message || '')); await new Promise(function (r) { setTimeout(r, 1000); });
        }
        if (!ready) { try { await inv('tor_stop'); } catch (e) {} return note('Tor не успел подключиться за 3 минуты. Возможно, он заблокирован в вашей сети: подключайтесь к Tor через VPN-профиль.', true); }
      }
      var cfg = CFG.buildConfig(prof, o);
      note('Проверяю и запускаю…'); var info = await inv('bridge_start', { configJson: JSON.stringify(cfg), tun: o.mode === 'tun' });
      mode = o.mode; port = o.port; connected = true; aud('bridge connected', o.mode + '/' + o.via + ' profiles=' + prof.length); paint(info);
      window.W420Proxy = (Q('#brself').checked && o.mode === 'proxy') ? 'socks5h://127.0.0.1:' + o.port : '';
    } catch (e) { note(String(e && e.message || e), true); }
  }
  async function disconnect() { try { var i = await inv('bridge_stop'); try { await inv('tor_stop'); } catch (e) {} window.W420Proxy = ''; connected = false; aud('bridge disconnected'); paint(i); note('Отключено.'); } catch (e) { note(String(e), true); } }
  function paint(i) {
    var b = Q('#brbadge'); if (!b) return;
    b.textContent = i.running ? 'LIVE · ' + mode.toUpperCase() : 'OFF'; b.className = 'b ' + (i.running ? 'live' : 'wip');
    Q('#brinfo').textContent = (i.running ? 'работает ' + i.uptime_s + ' с · pid ' + i.pid : 'остановлен') + ' · движок: ' + (i.sidecar ? 'встроен' : 'НЕ НАЙДЕН') + ' · права для TUN: ' + (i.elevated ? 'есть' : 'нет');
    Q('#brlog').textContent = (i.log_tail || []).join('\n'); Q('#brlog').scrollTop = 1e9;
    if (connected && !i.running) { connected = false; note('Мост остановился неожиданно: смотрите журнал ниже. Системный режим со строгой маршрутизацией не пропускает трафик мимо моста.', true); }
  }
  async function poll() { try { paint(await inv('bridge_status')); } catch (e) {} }
  async function exitCheck() {
    var http = window.__TAURI__.http && window.__TAURI__.http.fetch; if (!http) return note('HTTP-плагин недоступен.', true);
    Q('#brip').textContent = 'проверяю…';
    try {
      var init = (connected && mode === 'proxy') ? { proxy: { all: 'socks5h://127.0.0.1:' + port } } : {};
      var r = await http('https://check.torproject.org/api/ip', init), j = await r.json();
      Q('#brip').textContent = 'Сайты видят адрес ' + j.IP + (j.IsTor ? ' · это выход Tor' : ' · это не Tor') + (connected && mode === 'proxy' ? ' (проверка шла через мост)' : ' (проверка шла напрямую из приложения: в режиме «Прокси» сначала подключитесь)');
    } catch (e) { Q('#brip').textContent = 'Не удалось проверить: ' + (e && e.message || e); }
  }

  function build() {
    if (Q('#v-bridge') || !Q('#v-radio') || !Q('nav')) return;
    var sec = document.createElement('section'); sec.className = 'view live'; sec.id = 'v-bridge';
    sec.innerHTML =
      '<h2>BRIDGE · VPN + TOR <span class="b wip" id="brbadge">OFF</span></h2>' +
      '<div class="mono" id="brinfo">—</div>' +
      '<div class="card"><div class="k">ПРОФИЛИ</div><div id="brlist" class="mono"></div>' +
      '<textarea id="brtext" rows="4" placeholder="Вставьте: ссылки vless:// vmess:// trojan:// ss:// hysteria2:// tuic:// anytls:// socks5://, подписку (base64), содержимое WireGuard .conf или OpenVPN .ovpn"></textarea>' +
      '<div class="row" style="margin-top:6px"><input type="file" id="brfile" accept=".conf,.ovpn,.txt"><input id="bruser" placeholder="логин OpenVPN (если нужен)"><input id="brpass" type="password" placeholder="пароль OpenVPN"></div>' +
      '<div class="row" style="margin-top:6px"><button class="a" id="bradd">ДОБАВИТЬ</button><input id="brpw" type="password" placeholder="пароль для хранения профилей"><button class="a" id="brsave">СОХРАНИТЬ ЗАШИФРОВАННО</button><button class="a" id="brunlock">РАЗБЛОКИРОВАТЬ</button></div></div>' +
      '<div class="card"><div class="k">РЕЖИМ</div><div class="row">' +
      '<select id="brmode" style="width:auto"><option value="proxy">Прокси 127.0.0.1 (приложения настраиваются вручную)</option><option value="tun">Системный VPN (TUN, весь трафик, нужны права)</option></select>' +
      '<select id="brvia" style="width:auto"><option value="direct">Профили напрямую</option><option value="tor">Профили поверх Tor (VPN over Tor)</option><option value="torOnly">Только Tor</option></select>' +
      '<select id="brfail" style="width:auto"><option value="urltest">Автовыбор рабочего</option><option value="selector">Первый в списке</option></select></div>' +
      '<div class="row" style="margin-top:6px"><span class="mono">порт</span><input id="brport" value="2080" style="max-width:80px"><label class="mono"><input type="checkbox" id="brlan" checked style="width:auto"> локальную сеть не трогать</label><label class="mono"><input type="checkbox" id="brstrict" checked style="width:auto"> строгий kill-switch (TUN)</label></div>' +
      '<div class="row" style="margin-top:6px"><span class="mono">DNS: начальный</span><input id="brboot" value="1.1.1.1" style="max-width:120px"><span class="mono">удалённый (DoH)</span><input id="brdns" value="1.1.1.1" style="max-width:120px"></div>' +
      '<label class="mono"><input type="checkbox" id="brself" style="width:auto"> запросы самого W420 к облачному ИИ тоже пускать через мост (аккаунт API всё равно вас идентифицирует)</label>' +
      '<div class="row" style="margin-top:6px"><button class="a" id="brgo">ПОДКЛЮЧИТЬ</button><button class="a" id="broff">ОТКЛЮЧИТЬ</button><button class="a" id="brcheck">ПРОВЕРИТЬ ВЫХОД</button></div>' +
      '<div class="mono" id="brstat">—</div><div class="mono" id="brip"></div></div>' +
      '<div class="card"><div class="k">ЖУРНАЛ ДВИЖКА</div><pre id="brlog" class="mono" style="max-height:180px;overflow:auto;margin:0;white-space:pre-wrap"></pre></div>' +
      '<div class="card"><div class="k">ЧТО ЭТО ДАЁТ И ЧЕГО НЕТ</div><div class="mono" style="opacity:.85">Мост шифрует и маскирует трафик до вашего сервера или Tor и помогает обходить блокировки. Он не делает вас анонимным «полностью»: сайты узнают вас по входам в аккаунты, cookie и отпечатку браузера; обычный VPN-провайдер видит ваш трафик; Tor защищает лучше, но медленнее и его самого блокируют (нужны мосты). Режим «поверх Tor» скрывает ваш IP от VPN-сервера, но не от Tor-входа.</div></div>';
    Q('#v-radio').parentNode.appendChild(sec);
    var btn = document.createElement('button'); btn.className = 'live'; btn.textContent = 'BRIDGE'; btn.dataset.id = 'bridge'; btn.onclick = function () { show('bridge'); poll(); }; Q('nav').appendChild(btn);
    Q('#bradd').onclick = function () { importText(Q('#brtext').value); Q('#brtext').value = ''; };
    Q('#brfile').onchange = function (e) { var f = e.target.files[0]; if (!f) return; var r = new FileReader(); r.onload = function () { importText(String(r.result), f.name.replace(/\.[^.]+$/, '')); }; r.readAsText(f); e.target.value = ''; };
    Q('#brsave').onclick = saveEnc; Q('#brunlock').onclick = unlock; Q('#brgo').onclick = connect;
    Q('#broff').onclick = disconnect; Q('#brcheck').onclick = exitCheck;
    render(); poll(); statusTimer = setInterval(function () { if (Q('#v-bridge').classList.contains('on')) poll(); }, 2000);
  }
  build();
  window.W420Bridge = { profiles: function () { return P; }, importText: importText, build: build };
})();

/* W420 NET: обнаружение хостов в доступных сетях (живой список при сканировании),
   добавление в инвентарь, подключение по SSH, блокировка IP через IPS.
   Вся логика — в Rust-командах net_scan_* / hosts_* / traffic_block_ip. */
(function () {
  if (!window.__TAURI__ || !__TAURI__.invoke) return;
  var inv = __TAURI__.invoke;
  var $ = function (s) { return document.querySelector(s); };
  var pollTimer = 0;

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }

  async function scan() {
    var cidr = $('#n-cidr').value.trim();
    $('#n-stat').textContent = 'сканирую ' + cidr + '…';
    try {
      var ports = await inv('net_default_ports');
      var p = inv('net_scan_subnet', { cidr: cidr, ports: ports, concurrency: 500, timeoutMs: 1200 });
      // живое обновление списка каждые 2 с, пока скан идёт
      clearInterval(pollTimer);
      pollTimer = setInterval(renderLast, 2000);
      var res = await p;
      clearInterval(pollTimer);
      render(res);
      $('#n-stat').textContent = 'найдено хостов: ' + res.hosts_up + '/' + res.hosts_total +
        (res.new_hosts.length ? ' · новых: ' + res.new_hosts.join(', ') : '');
      renderInventory();
    } catch (e) {
      clearInterval(pollTimer);
      $('#n-stat').textContent = 'ошибка: ' + e.message;
    }
  }

  async function renderLast() {
    try {
      var res = await inv('net_scan_last');
      if (res) render(res);
    } catch (e) {}
  }

  function render(res) {
    var box = $('#n-hosts');
    if (!box || !res) return;
    var rows = res.hosts.map(function (h) {
      var ports = h.open_ports.map(function (p) {
        return p.port + '/' + esc(p.service) + (p.banner ? ' (' + esc(p.banner.slice(0, 24)) + ')' : '');
      }).join(', ');
      var btns = '';
      if (!h.is_known) btns += '<button class="a" data-act="add" data-ip="' + esc(h.ip) + '" data-os="' + esc(h.os_guess) + '">+ в инвентарь</button>';
      btns += '<button class="a" data-act="block" data-ip="' + esc(h.ip) + '">⛔ блок</button>';
      return '<div class="item" style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">' +
        '<span class="b live">' + esc(h.ip) + '</span>' +
        (h.hostname ? '<span class="mono">' + esc(h.hostname) + '</span>' : '') +
        '<span class="mono">' + esc(h.os_guess) + '</span>' +
        '<span class="mono" style="opacity:.85">' + ports + '</span>' +
        (h.is_known ? '<span class="b live">в инвентаре</span>' : '<span class="b wip">новый</span>') +
        btns + '</div>';
    }).join('');
    box.innerHTML = rows || '<div class="mono">хостов нет</div>';
    box.querySelectorAll('button[data-act]').forEach(function (b) {
      b.onclick = async function () {
        var ip = b.dataset.ip;
        if (b.dataset.act === 'block') {
          try { await inv('traffic_block_ip', { ip: ip, reason: 'ручная блокировка из списка сети' }); b.textContent = '⛔ заблокирован'; }
          catch (e) { alert(e.message); }
        } else if (b.dataset.act === 'add') {
          try {
            var os = (b.dataset.os || '').indexOf('Windows') >= 0 ? 'Windows' : 'Linux';
            await inv('hosts_add', { name: ip, ip: ip, port: 22, username: null, osType: os, authMethod: 'ssh-key' });
            b.textContent = '✓ добавлен';
            renderInventory();
          } catch (e) { alert(e.message); }
        }
      };
    });
  }

  async function renderInventory() {
    var box = $('#h-list');
    if (!box) return;
    try {
      var hosts = await inv('hosts_list');
      box.innerHTML = hosts.map(function (h) {
        return '<div class="item" style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">' +
          '<span class="b live">' + esc(h.ip) + ':' + h.port + '</span>' +
          '<span class="mono">' + esc(h.name) + ' · ' + esc(h.os_type) + ' · ' + esc(h.status) + '</span>' +
          '<button class="a" data-id="' + esc(h.id) + '" data-act="conn">ПОДКЛЮЧИТЬ</button>' +
          '<button class="a" data-id="' + esc(h.id) + '" data-act="disc">ОТКЛЮЧИТЬ</button>' +
          '<button class="a" data-id="' + esc(h.id) + '" data-act="rm">✕</button></div>';
      }).join('') || '<div class="mono">инвентарь пуст</div>';
      box.querySelectorAll('button[data-act]').forEach(function (b) {
        b.onclick = async function () {
          var id = b.dataset.id;
          try {
            if (b.dataset.act === 'conn') { var r = await inv('hosts_connect', { hostId: id }); alert(r); }
            if (b.dataset.act === 'disc') await inv('hosts_disconnect', { hostId: id });
            if (b.dataset.act === 'rm') await inv('hosts_remove', { hostId: id });
            renderInventory();
          } catch (e) { alert(e.message); }
        };
      });
    } catch (e) { box.innerHTML = '<div class="mono">ошибка: ' + esc(e.message) + '</div>'; }
  }

  function wire() {
    var s = $('#n-scan'); if (s) s.onclick = scan;
    var r = $('#n-refresh'); if (r) r.onclick = function () { renderLast(); renderInventory(); };
    var d = $('#n-diff'); if (d) d.onclick = async function () {
      $('#n-stat').textContent = 'сравниваю два последних скана…';
      try {
        var diff = await inv('net_scan_diff');
        if (!diff) { $('#n-stat').textContent = 'нужно минимум 2 скана — сначала просканируйте сеть дважды'; return; }
        $('#n-stat').textContent = 'DIFF: новых ' + diff.new_hosts.length + ', исчезло ' + diff.removed_hosts.length;
        var box = $('#n-hosts');
        if (box) box.insertAdjacentHTML('afterbegin',
          '<div style="border:1px solid var(--border);padding:6px;margin-bottom:6px">' +
          '<b>DIFF</b> ' + esc(diff.prev_at.slice(0, 19)) + ' → ' + esc(diff.cur_at.slice(0, 19)) + '<br>' +
          '🆕 новые: ' + (diff.new_hosts.map(esc).join(', ') || '—') + '<br>' +
          '🚫 исчезли: ' + (diff.removed_hosts.map(esc).join(', ') || '—') + '<br>' +
          '<span style="opacity:.7">новые хосты ушли алертами в SIEM (source=net_scan)</span></div>');
      } catch (e) { $('#n-stat').textContent = 'ошибка diff: ' + (e && e.message || e); }
    };
    var add = $('#h-add');
    if (add) add.onclick = async function () {
      try {
        await inv('hosts_add', {
          name: $('#h-name').value || $('#h-ip').value,
          ip: $('#h-ip').value,
          port: parseInt($('#h-port').value || '22', 10),
          username: $('#h-user').value || null,
          osType: $('#h-os').value,
          authMethod: 'ssh-key',
        });
        renderInventory();
      } catch (e) { alert(e.message); }
    };
    renderLast(); renderInventory();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
  else wire();
})();

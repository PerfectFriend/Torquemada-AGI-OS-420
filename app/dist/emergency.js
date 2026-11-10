/* W420 EMERGENCY: аварийный режим — жёсткая фильтрация пакетов на всех каналах сразу.
   Кнопка 🚨 в шапке включает/выключает аварийный уровень; секция в панели настроек (⚙)
   задаёт уровень, жёсткий egress и авто-включение при алерте. Правила nft показываются. */
(function () {
  if (!window.__TAURI__ || !__TAURI__.invoke) return;
  var inv = __TAURI__.invoke;
  var $ = function (s) { return document.querySelector(s); };

  function stat(txt, bad) {
    var el = $('#e-stat');
    if (el) { el.textContent = txt; el.style.color = bad ? '#f44' : ''; }
  }

  async function refresh() {
    try {
      var st = await inv('emergency_status');
      var btn = $('#alarm');
      if (btn) btn.classList.toggle('on', !!st.enabled);
      if ($('#e-level')) $('#e-level').value = st.level || 'monitor';
      if ($('#e-egress')) $('#e-egress').checked = !!st.egress_strict;
      if ($('#e-auto')) $('#e-auto').checked = !!st.auto_on_alert;
      stat('режим: ' + (st.enabled ? st.level.toUpperCase() : 'мониторинг') +
        ' · таблица в ядре: ' + (st.table_present ? 'да' : 'нет'), false);
    } catch (e) { stat('ошибка статуса: ' + e.message, true); }
  }

  async function apply(level, egress, auto, enabled) {
    stat('применяю…');
    try {
      var r = await inv('emergency_set', {
        enabled: enabled,
        level: level,
        egressStrict: egress,
        autoOnAlert: auto,
      });
      $('#e-rules').textContent = r.rules || '';
      stat((r.applied ? 'ПРИМЕНЕНО: ' : 'сохранено, но не применено в ядро: ') + r.detail +
        (r.needs_root ? ' (нужен root)' : ''), !r.applied);
      await refresh();
    } catch (e) { stat('ошибка: ' + e.message, true); }
  }

  function wire() {
    var btn = $('#alarm');
    if (btn) btn.onclick = async function () {
      var st = await inv('emergency_status').catch(function () { return { enabled: false }; });
      if (st.enabled) {
        await apply('monitor', false, st.auto_on_alert, false);
      } else {
        if (!confirm('Включить АВАРИЙНЫЙ режим? Весь входящий трафик на всех интерфейсах будет отброшен (кроме lo/established/ICMP).')) return;
        await apply('emergency', $('#e-egress') ? $('#e-egress').checked : false, $('#e-auto') ? $('#e-auto').checked : false, true);
      }
    };
    var ap = $('#e-apply');
    if (ap) ap.onclick = function () {
      apply($('#e-level').value, $('#e-egress').checked, $('#e-auto').checked, $('#e-level').value !== 'monitor');
    };
    var off = $('#e-off');
    if (off) off.onclick = function () { apply('monitor', false, $('#e-auto').checked, false); };
    var lv = $('#e-level');
    if (lv) lv.onchange = function () {
      inv('emergency_rules_preview', { level: lv.value, egressStrict: $('#e-egress').checked })
        .then(function (r) { $('#e-rules').textContent = r; }).catch(function () {});
    };
    var eg = $('#e-egress');
    if (eg) eg.onchange = function () {
      inv('emergency_rules_preview', { level: $('#e-level').value, egressStrict: eg.checked })
        .then(function (r) { $('#e-rules').textContent = r; }).catch(function () {});
    };
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { wire(); refresh(); setInterval(refresh, 5000); });
  else { wire(); refresh(); setInterval(refresh, 5000); }
})();

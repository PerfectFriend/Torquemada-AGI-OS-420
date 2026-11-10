/* hud.js — Этап 25: HUD карточки AGI/MESH — реальные метрики, native-only.
   h-mesh ← bridge/tor/vpn статусы (число живых sidecar-узлов + пиров);
   h-agi ← статистика модели (tokens/s) вместо случайных «99.7%».
   Inline-интервал пишет h-agi каждую секунду — блокируем его через
   defineProperty (SIM-записи вида «NN.N%» игнорируем). */
(function(){
  const NATIVE = !!(window.__TAURI__ && window.__TAURI__.core);
  if(!NATIVE) return;
  const inv = window.__TAURI__.core.invoke;
  const $ = (id)=>document.getElementById(id);

  // Блокируем SIM-записи inline в h-agi
  const elAgi = $('h-agi');
  let realAgi = '—';
  if(elAgi){
    Object.defineProperty(elAgi, 'textContent', {
      configurable: true,
      get: () => realAgi,
      set: (v) => { if(!/^\d+(\.\d+)?%$/.test(String(v))) realAgi = String(v); },
    });
  }
  const setAgi = (v) => { realAgi = String(v); };

  // Плашки SIM → LIVE на обеих карточках
  document.querySelectorAll('aside .card.sim').forEach(c=>{
    const b = c.querySelector('.b.sim');
    if(b){ b.textContent = 'LIVE'; b.className = 'b live'; }
    c.className = 'card live';
  });

  async function tick(){
    // MESH: живые sidecar'ы и пиры
    try{
      let nodes = 0, parts = [];
      try{ const b = await inv('bridge_status'); if(b && (b.running || b.active)) { nodes++; parts.push('bridge'); } }catch(e){}
      try{ const t = await inv('tor_status'); if(t && (t.running || t.connected)) { nodes++; parts.push('tor'); } }catch(e){}
      try{ const v = await inv('vpn_status'); const n = Array.isArray(v) ? v.length : 0; if(n){ nodes += n; parts.push('vpn×'+n); } }catch(e){}
      $('h-mesh').textContent = String(nodes) + (parts.length ? ' (' + parts.join(',') + ')' : ' (все выкл)');
    }catch(e){}
    // AGI: tok/s последних вызовов модели + live
    try{
      const agi = await inv('agi_status');
      if(!agi.live){ setAgi('нет AI-ключа'); return; }
      const prov = await inv('ai_providers_status');
      const pid = prov && prov.default_provider_id;
      if(pid){
        const stats = await inv('ai_provider_model_stats', {providerId:pid, sortBy:null});
        if(Array.isArray(stats) && stats.length){
          const last = stats[0];
          const tps = last.tokens_per_sec || 0;
          setAgi(tps > 0 ? tps.toFixed(1) + ' tok/s' : 'idle · ' + (last.latency_ms||0) + ' мс');
          return;
        }
      }
      setAgi('LIVE');
    }catch(e){ setAgi('—'); }
  }
  tick();
  setInterval(tick, 5000);
})();

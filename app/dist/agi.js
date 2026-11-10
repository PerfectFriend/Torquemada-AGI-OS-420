/* agi.js — Этап 19: подключение AGI-оболочки к нативному Rust-бэкенду (agi.rs).
   В браузере без Tauri всё остаётся прежним (SIM); внутри native-оболочки:
   чат → agi_chat (ротация ключей, маски …abcd), бейдж → agi_status,
   инструменты → agi_tools_list/agi_tool_exec, задача → task_start/stop/status/approve.
   Глобальные function из inline-скрипта перезаписываются через window (без hoisting-ловушки). */
(function(){
  const NATIVE = !!(window.__TAURI__ && window.__TAURI__.core);
  if(!NATIVE) return; // чистый браузер — старое поведение
  const inv = window.__TAURI__.core.invoke;
  // $, store, hist, task, say, p, fd, audit — глобальные биндинги inline-скрипта index.html;
  // используем их напрямую (переобъявление const/let в другом скрипте — SyntaxError,
  // а window.hist/window.task не синхронизировались бы с let-биндингами).

  /* ---- 1. Чат: agi_chat вместо браузерного sample ---- */
  const origAskAGI = window.askAGI;
  window.askAGI = async function(q, onText){
    hist.push({role:'user', content:q});
    try{
      const r = await inv('agi_chat', {prompt:q, history: hist.slice(-20, hist.length-1).map(m=>({role:m.role, content:m.content}))});
      hist.push({role:'assistant', content:String(r.text||'')});
      hist = hist.slice(-40); store.set('w420.hist', hist);
      onText(String(r.text||''));
    }catch(e){
      onText('[ошибка] ' + (e && e.message ? e.message : String(e)));
    }
  };

  /* ---- 2. Бейдж LIVE/SIM + список инструментов ---- */
  (async()=>{
    try{
      const s = await inv('agi_status');
      const on = !!s.available;
      const aib = $('#aib');
      aib.textContent = on ? 'LIVE' : 'SIM'; aib.className = 'b ' + (on?'live':'sim');
      $('#v-ai').classList.toggle('live', on); $('#v-ai').classList.toggle('sim', !on);
      const nb = document.querySelector('nav button[data-id=ai]');
      if(nb){ nb.classList.toggle('live', on); nb.classList.toggle('sim', !on); }
      const tools = await inv('agi_tools_list');
      $('#aimsg').textContent = on
        ? 'AI-мост W420: agi_chat через ротацию ключей (наружу — только маска …abcd). Инструменты модели: ' + tools.map(t=>t.name).join(', ') + '. Автономная задача — карточка AUTONOMOUS TASK (PROPOSE → APPROVE).'
        : 'Нет активного AI-провайдера — чата в режиме [SIM]. Добавьте провайдера и ключ в настройках (ключи хранятся зашифрованно AES-256-GCM).';
      // Чипы-инструменты: ручной запуск read-only инструмента
      const chips = $('#chips');
      tools.forEach(t=>{
        const b = document.createElement('button');
        b.textContent = '⚙ ' + t.name;
        b.title = t.description || '';
        b.onclick = async()=>{
          try{
            const r = await inv('agi_tool_exec', {name:t.name, args:{}});
            say('⚙ ' + t.name + ': ' + JSON.stringify(r).slice(0, 400), 'var(--live)');
            audit('agi-tool', t.name);
          }catch(e){ say('⚙ ' + t.name + ' — ошибка: ' + (e.message||e), 'var(--wip)'); }
        };
        chips.appendChild(b);
      });
    }catch(e){ /* бэкенд недоступен — остаётся SIM */ }
  })();

  /* ---- 3. Автономная задача: нативный task_start/stop/status/approve ---- */
  const origStartTask = window.startTask, origStopTask = window.stopTask;
  let taskPoll = null;
  const seenProps = new Set();
  let lastNotes = 0;

  function renderProposal(pr){
    if(seenProps.has(pr.id)) return;
    seenProps.add(pr.id);
    const d = document.createElement('div');
    d.className = 'card'; d.style.margin = '6px 0';
    const h = document.createElement('div'); h.className = 'k';
    h.textContent = 'AGI ПРЕДЛАГАЕТ ДЕЙСТВИЕ · ТРЕБУЕТСЯ ПОДТВЕРЖДЕНИЕ';
    const t = document.createElement('div');
    t.textContent = pr.kind + ' · ' + JSON.stringify(pr.params||{}).slice(0,140);
    const m = document.createElement('div'); m.className = 'mono';
    const row = document.createElement('div'); row.className = 'row';
    const ok = document.createElement('button'); ok.className = 'a'; ok.textContent = 'APPROVE';
    const no = document.createElement('button'); no.className = 'a'; no.textContent = 'REJECT';
    no.style.setProperty('--c','var(--sim)');
    const done = s => { row.remove(); m.textContent += ' — ' + s; fd('proposal #'+pr.id+': '+s); };
    ok.onclick = async()=>{ try{ const r = await inv('task_approve',{id:pr.id, approve:true}); done(r.status); }catch(e){ done('ошибка: '+(e.message||e)); } };
    no.onclick = async()=>{ try{ const r = await inv('task_approve',{id:pr.id, approve:false}); done(r.status); }catch(e){ done('ошибка: '+(e.message||e)); } };
    row.append(ok, no); d.append(h, t, m, row);
    $('#chat').appendChild(d); $('#chat').scrollTop = 1e9;
  }

  async function taskStatusPoll(){
    try{
      const s = await inv('task_status');
      if(typeof task !== 'undefined' && task){ task.n = s.n; task.max = s.max; task.goal = s.goal; }
      $('#tstat').textContent = (s.running ? 'работает' : 'стоп') + ' · запуск ' + s.n + '/' + s.max +
        ' · интервал ' + s.interval_secs + ' с · цель: ' + String(s.goal||'').slice(0,40);
      // notes в status — последние 10 в обратном порядке; в терминал выводим только новые
      const notes = (s.notes || []).slice().reverse(); // прямая очередность
      for(let i = lastNotes; i < notes.length && i < s.n; i++){
        p('[TASK ' + (i+1) + '] ' + notes[i], 'u');
      }
      lastNotes = Math.max(lastNotes, Math.min(notes.length, s.n));
      (s.pending || []).forEach(renderProposal);
    }catch(e){}
  }

  window.startTask = async function(){
    const g = $('#tgoal').value.trim();
    if(!g) return;
    try{
      const r = await inv('task_start', {goal:g, intervalSecs: +$('#tint').value || 60, max: 10});
      audit('task', 'start: ' + g.slice(0,100));
      p('[TASK] старт: ' + g, 'u');
      fd('задача запущена: ' + g.slice(0,60), 'var(--live)');
      task = {goal:g, n:0, max:r.max};
      lastNotes = 0; seenProps.clear();
      $('#tstat').textContent = 'работает · интервал ' + r.interval_secs + ' с · макс. ' + r.max + ' запусков';
      if(taskPoll) clearInterval(taskPoll);
      taskPoll = setInterval(taskStatusPoll, 3000);
      taskStatusPoll();
    }catch(e){
      $('#tstat').textContent = 'ошибка: ' + (e && e.message ? e.message : String(e));
    }
  };
  window.stopTask = async function(why){
    try{ await inv('task_stop'); }catch(e){}
    if(taskPoll){ clearInterval(taskPoll); taskPoll = null; }
    task = null;
    $('#tstat').textContent = 'остановлено: ' + why;
    p('[TASK] остановлено: ' + why, 'w');
  };
  // inline-скрипт присвоил onclick СТАРЫЕ функции-объекты — перепривязываем на новые
  $('#tgo').onclick = ()=>window.startTask();
  $('#tstop').onclick = ()=>window.stopTask('пользователь');
})();

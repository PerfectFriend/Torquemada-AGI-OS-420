/* radio.js — Этап 23: AGI-Ω FM на нативном AGI-мосте + TTS, native-only.
   Переопределяем window.radioDJ / radioSay / epBuild (function-declaration →
   window-свойства, перезаписываются после inline-скрипта). Музыка Web Audio
   и radioStart/radioTick остаются как есть. В браузере без Tauri — как было. */
(function(){
  const NATIVE = !!(window.__TAURI__ && window.__TAURI__.core);
  if(!NATIVE) return;
  const inv = window.__TAURI__.core.invoke;
  const $ = window.$ || ((id)=>document.getElementById(id));
  const DJ = {seg:0, busy:false, req:'', max:20, ep:null};

  const KINDS = [
    ['наблюдение','Короткая остроумная мысль AGI о текущем состоянии системы или задаче, 1-2 предложения.'],
    ['анекдот','Короткий безобидный анекдот или шутка в тему задачи или системы, 2-3 предложения, без оскорблений.'],
    ['сводка','Сводка состояния системы в стиле радио, 2 предложения, только по данным из контекста.'],
    ['идея','Одна неожиданная практическая идея, как улучшить работу, 1-2 предложения.'],
  ];
  const CANNED = ['Эфир W420. Все системы в норме, музыка играет, агенты не спят.',
    'Совет дня: ключи — в vault, пароли — в голове, а эфиру — только лучшее.'];
  const onAir = () => $('#rbtn').textContent.includes('OFF AIR');

  /* Озвучка: TTS-сервер через radio_say; если сервер молчит — фолбек speechSynthesis */
  let audio = null;
  window.radioSay = async function(t){
    if(!t) return;
    try{
      const r = await inv('radio_say', {text:t});
      if(r.ok && r.b64){
        if(audio) audio.pause();
        audio = new Audio('data:audio/wav;base64,' + r.b64);
        audio.play().catch(()=>{});
        return;
      }
    }catch(e){}
    // фолбек: браузерный speechSynthesis (как раньше)
    if(window.speechSynthesis){
      speechSynthesis.cancel();
      const u = new SpeechSynthesisUtterance(t);
      u.lang = 'ru-RU'; u.pitch = .8;
      const v = speechSynthesis.getVoices().find(v=>v.lang && v.lang.startsWith('ru'));
      if(v) u.voice = v;
      speechSynthesis.speak(u);
    }
  };

  /* Ведущий: каждая реплика — через radio_script (agi_chat в Rust) */
  window.radioDJ = async function(first){
    if(!onAir() || DJ.busy) return;
    DJ.busy = true;
    const k = KINDS[DJ.seg++ % KINDS.length];
    const req = DJ.req; DJ.req = '';
    let text = null, live = true;
    try{
      if(DJ.seg > DJ.max) throw new Error('max');
      const mood = window.radioMood ? window.radioMood() : 'calm';
      const ctx = window.radioCtx ? window.radioCtx() : '';
      const r = await inv('radio_script', {kind:k[0], kindDesc:k[1], mood, ctx, request:req || null});
      text = String(r.text || '').trim().slice(0, 320);
      if(!text) throw new Error('empty');
    }catch(e){ live = false; text = CANNED[DJ.seg % CANNED.length]; }
    if(window.addSeg) window.addSeg(req ? 'заказ' : k[0], text, live);
    if(window.audit) window.audit('radio', (req ? 'заказ' : k[0]) + ': ' + text.slice(0, 80));
    window.radioSay(text);
    DJ.busy = false;
    if(onAir()) setTimeout(()=>window.radioDJ(), DJ.seg > DJ.max ? 300000 : (first ? 45000 : 90000));
  };

  /* Заказ темы — в своё состояние (R — lexical, недоступен) */
  $('#rask').onclick = ()=>{
    DJ.req = $('#rreq').value.trim().slice(0, 120);
    $('#rreq').value = '';
    if(onAir() && DJ.req && !DJ.busy) window.radioDJ();
  };

  /* Выпуск дня: статистика — window.epStats/epText, текст — radio_episode */
  window.epBuild = async function(){
    const c = window.epStats ? window.epStats() : {total:0};
    const st = window.epText ? window.epText(c) : '';
    $('#estat').textContent = st;
    if(!c.total){
      DJ.ep = {text:'За последние 24 часа в журнале пусто: агенты ничего не делали.', stats:st};
      $('#etext').style.color = 'var(--live)';
      $('#etext').textContent = DJ.ep.text;
      return;
    }
    let text, live = true;
    try{
      const A = JSON.parse(localStorage.getItem('w420.audit') || '[]');
      const last = A.slice(-25).map(e=>String(e.t).slice(11,16)+' '+e.ev+': '+String(e.d).slice(0,80)).join('\n');
      const r = await inv('radio_episode', {stats:st, entries:last});
      text = String(r.text || '').trim();
      if(!text) throw new Error('empty');
    }catch(e){
      live = false;
      text = 'Добрый вечер, это «День агентов». За сутки в журнале ' + c.total + ' записей. ' + st + '. Модель недоступна — выпуск по шаблону. До связи.';
    }
    DJ.ep = {text, stats:st};
    $('#etext').style.color = live ? 'var(--live)' : 'var(--wip)';
    $('#etext').textContent = text + (live ? '' : ' [шаблон]');
    if(window.audit) window.audit('radio', 'episode built: ' + c.total + ' entries');
  };
  $('#ebtn').onclick = async ()=>{ $('#ebtn').disabled = true; try{ await window.epBuild(); } finally { $('#ebtn').disabled = false; } };
  $('#esay').onclick = ()=>{ if(DJ.ep) window.radioSay(DJ.ep.text); };
  $('#evault').onclick = ()=>{
    const pw = $('#epw').value;
    if(!DJ.ep || !pw) return $('#estat').textContent = 'нужны выпуск и пароль';
    $('#vn').value = 'episode-' + new Date().toISOString().slice(0,10);
    $('#vt').value = DJ.ep.text + '\n\n[данные] ' + DJ.ep.stats;
    $('#vp').value = pw; $('#vput').click();
    $('#vp').value = ''; $('#epw').value = '';
    $('#estat').textContent = 'выпуск зашифрован в QFS Vault';
  };

  /* Плашка «запасные реплики: SIM» → LIVE, если AGI реально подключён */
  (async()=>{
    try{
      const st = await inv('radio_status');
      if(st.agi_live){
        document.querySelectorAll('#v-radio .b.sim').forEach(b=>{ b.textContent='ведущий: LIVE'; b.className='b live'; });
      }else{
        document.querySelectorAll('#v-radio .b.sim').forEach(b=>{ b.textContent='ведущий: нет AI-провайдера'; });
      }
    }catch(e){}
  })();
})();

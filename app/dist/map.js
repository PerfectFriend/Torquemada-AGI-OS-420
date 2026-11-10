/* map.js — Этап 24: MIND MAP AGI-GEN на нативном мосте (map.rs), native-only.
   Добавляет кнопку «СГЕНЕРИРОВАТЬ ИИ» рядом с ADD NODE: тема из поля #mt,
   узлы — из map_generate (валидация схемы в Rust), раскладка — та же,
   что у встроенного mindmap_build, запись в localStorage 'w420.map'. */
(function(){
  const NATIVE = !!(window.__TAURI__ && window.__TAURI__.core);
  if(!NATIVE) return;
  const inv = window.__TAURI__.core.invoke;

  /* Плашка AGI-GEN: SIM → LIVE при живом AGI */
  (async()=>{
    try{
      const st = await inv('map_agi_status');
      if(st.live) document.querySelectorAll('#v-map .b.sim').forEach(b=>{ b.textContent='AGI-GEN: LIVE'; b.className='b live'; });
    }catch(e){}
  })();

  const row = document.querySelector('#v-map .row');
  if(!row) return;
  const gen = document.createElement('button');
  gen.className = 'a'; gen.id = 'mgen'; gen.textContent = 'СГЕНЕРИРОВАТЬ ИИ';
  gen.title = 'map_generate — тема из поля ввода, карта строится моделью (до 40 узлов)';
  row.appendChild(gen);

  gen.onclick = async ()=>{
    const topic = document.getElementById('mt').value.trim();
    if(!topic) return document.getElementById('mt').placeholder = 'сначала введите тему для карты ИИ';
    gen.disabled = true;
    try{
      const r = await inv('map_generate', {prompt:topic});
      const arr = r.nodes || [];
      if(!arr.length) throw new Error('пустая карта');
      // Тот же layout, что у встроенного mindmap_build
      const nodes = arr.map((n,k)=>({id:k, t:String(n.text).slice(0,28), x:.5, y:.5, p:(n.parent>=0 && n.parent<k) ? n.parent : null}));
      if(nodes.length) nodes[0].p = null;
      const kids = {};
      nodes.forEach(n=>{ if(n.p!==null) (kids[n.p]=kids[n.p]||[]).push(n); });
      const cl = v=>Math.min(.93, Math.max(.07, v));
      const lay = (n,a0,a1,r)=>{
        const c = kids[n.id]||[];
        c.forEach((k,j)=>{
          const an = a0 + (a1-a0)*(j+.5)/c.length;
          k.x = cl(.5 + Math.cos(an)*r*.42); k.y = cl(.5 + Math.sin(an)*r*.42);
          lay(k, a0+(a1-a0)*j/c.length, a0+(a1-a0)*(j+1)/c.length, r+.45);
        });
      };
      if(nodes.length) lay(nodes[0], 0, Math.PI*2, .55);
      localStorage.setItem('w420.map', JSON.stringify(nodes));
      if(window.drawMap) window.drawMap();
      if(window.audit) window.audit('map', 'AGI-GEN: «' + topic.slice(0,40) + '» → ' + nodes.length + ' узлов');
      document.getElementById('mt').value = '';
    }catch(e){
      alert('генерация не удалась: ' + (e && e.message ? e.message : e));
    }finally{
      gen.disabled = false;
    }
  };
})();

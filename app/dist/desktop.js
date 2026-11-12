/* desktop.js — Этап 39: оконный менеджер Torquemada Desktop OS (W420 Desktop)
   Матричный неоновый киберпанк. Адаптивные окна, панель задач, tray, режим истинного fullscreen.
   Все окна — это существующие секции index.html (section.view), обернутые в оконную обёртку.
   Управление — через Rust-мост (open/minimize/close/app focus), а также мышью (drag, titlebar кнопки).
   Ключевые API:
     Desktop.register(id, {icon, label, section, onOpen, onClose, onBeforeClose})
     Desktop.open(id)  — открыть окно (или поднять, если открыто)
     Desktop.close(id) — закрыть окно (полная остановка — вызывает onBeforeClose)
     Desktop.minimize(id)
     Desktop.focus(id)
     Desktop.setAlert(id, count) — красный индикатор над иконкой
     Desktop.toggleFullscreen() — Alt+Enter: истинный fullscreen (скрывает заголовок/панель задач)
   Внутренний реестр:
     apps  — {id, icon, label, section, onOpen, onClose, onBeforeClose, element, state}
     win   — {id, z, x, y, w, h, minimized, fullscreen, top}
   Панель задач: иконки окон в центре, кнопка tools слева, tray справа.
   Tray: монитор · чат · AI -> выпадающее контекстное меню (basic commands).
   Drag-n-drop окон: захват за заголовок, перемещение по экрану.
   Состояния: 'hidden' (в трее / закрыто), 'minimized' (в панели задач), 'open', 'maximized', 'fullscreen'.
   Максимум z-index: 100-199 (окна), overlay 200+, settings 250, menus 300.
*/
(function(){
  'use strict';
  const NATIVE=!!(window.__TAURI__ && window.__TAURI__.core);
  const $=s=>document.querySelector(s);
  const inv=NATIVE?window.__TAURI__.core.invoke:()=>Promise.reject(new Error('no-tauri'));
  const styleSheet=document.createElement('style');document.head.appendChild(styleSheet);

  const STATE={
    apps:{}, win:{}, topZ:100, focused:null, activeApps:[], menus:{}, trays:{}, activeMenu:null, toolsOpen:false
  };
  let fullscreen=false;

  // === Всплывающие уведомления ===
  function notify(tag, msg, color){
    const d=document.createElement('div');
    d.className='w420-notify';
    d.style.cssText=`position:fixed;top:12px;right:12px;z-index:9999;background:var(--panel);border:1px solid ${color};padding:8px 12px;font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--ink);min-width:200px;opacity:1;transition:opacity .5s`;
    d.innerHTML=`<div style="font-weight:700;color:${color}">${tag}</div><div>${msg}</div>`;
    document.body.appendChild(d);
    setTimeout(()=>{d.style.opacity=0;setTimeout(()=>d.remove(),500)},3500);
  }

  // === Регистрация приложения ===
  async function register(id, cfg){
    if(STATE.apps[id]) return notify('w420','app already registered: '+id,'var(--wip)');
    if(cfg.aliasOf){ // deep-link: не своё окно, а открытие другого + скролл
      STATE.apps[id]={id,icon:cfg.icon||'\ud83d\udcc1',label:cfg.label||id,aliasOf:cfg.aliasOf,card:cfg.card,state:'alias'};
      return;
    }
    const el=typeof cfg.section==='string'?$(cfg.section):cfg.section;
    if(!el){ notify('w420','section not found: '+id,'var(--sim)'); return; }
    el.style.position='relative'; el.style.overflow='hidden'; el.style.height='100%';
    STATE.apps[id]={id,icon:cfg.icon||'\ud83d\udcc1',label:cfg.label||id,section:el,onOpen:cfg.onOpen,onClose:cfg.onClose,
      onBeforeClose:cfg.onBeforeClose,element:el,state:'hidden'};
    STATE.win[id]={x:60,y:60,w:Math.min(el.clientWidth||700, Math.round(window.innerWidth*0.72)),h:Math.min(el.clientHeight||500, Math.round(window.innerHeight*0.7)),minimized:false,
      fullscreen:false,maximized:false,z:100,appIcon:null,menu:null};
    if(cfg.basicMenu) STATE.win[id].menu=buildMenu(cfg.basicMenu);
    notify('w420','app registered: '+cfg.label||id,'var(--live)');
  }

  // === Контекстное меню трея (basic commands) ===
  function buildMenu(cmds){
    const menu=document.createElement('div');
    menu.className='w420-tray-menu';
    menu.style.cssText='position:absolute;z-index:300;background:var(--head);border:1px solid var(--live);border-radius:6px;min-width:200px;padding:6px;font-family:\'Share Tech Mono\',monospace;font-size:11px;color:var(--ink);box-shadow:0 0 16px var(--glow)';
    cmds.forEach(c=>{
      const btn=document.createElement('button');
      btn.style.cssText='width:100%;background:transparent;border:none;color:var(--ink);text-align:left;padding:6px 8px;font-family:\'Share Tech Mono\',monospace;font-size:11px;cursor:pointer;border-radius:4px';
      btn.innerHTML=c.label+ (c.kb?` <span style="opacity:.5;font-size:9px">${c.kb}</span>`:'');
      btn.onmouseover=()=>{ btn.style.background='var(--live)'; btn.style.color='#000'; };
      btn.onmouseout=()=>{ btn.style.background='transparent'; btn.style.color='var(--ink)'; };
      btn.onclick=async e=>{
        e.stopPropagation(); closeAllMenus();
        if(c.action) c.action();
        if(c.cmd) openApp(c.cmd);
        if(c.kb) notify('w420','hotkey: '+c.kb,'var(--wip)');
      };
      menu.appendChild(btn);
    });
    return menu;
  }

  // === Открытие окна ===
  async function openWindow(id){
    const app=STATE.apps[id]; if(!app) return;
    const w0=STATE.win[id];
    if(w0 && STATE.activeApps.includes(id)){
      // окно уже открыто: просто поднимаем/восстанавливаем
      if(w0.minimized){ w0.minimized=false; const wr=app.element.parentElement; wr.style.display='flex'; app.element.style.display='flex'; }
      focusWindow(id); return;
    }
    app.state='open'; const w=STATE.win[id];
    if(!app.element.parentElement.classList.contains('w420-window')){
      const wrap=document.createElement('div'); wrap.className='w420-window';
      wrap.style.cssText='position:fixed;background:var(--panel);border:1px solid var(--live);border-radius:6px;box-shadow:0 0 30px var(--glow),inset 0 0 20px var(--glow);overflow:hidden;font-family:\'Share Tech Mono\',monospace;color:var(--ink);';
      const titlebar=document.createElement('div');
      titlebar.className='w420-titlebar';
      titlebar.style.cssText='height:28px;background:var(--head);border-bottom:1px solid var(--live);display:flex;align-items:center;justify-content:space-between;user-select:none;padding:0 8px;cursor:default;';
      const left=document.createElement('div'); left.style.cssText='display:flex;align-items:center;gap:8px;font-size:11px;font-weight:700;color:var(--live);letter-spacing:1px;';
      const icon=document.createElement('span'); icon.style.cssText='font-size:13px'; icon.textContent=app.icon;
      const title=document.createElement('span'); title.textContent=app.label;
      left.appendChild(icon); left.appendChild(title);
      const right=document.createElement('div'); right.style.cssText='display:flex;gap:6px';
      const minb=document.createElement('button'); minb.textContent='\u2014';
      const closeb=document.createElement('button'); closeb.textContent='\u2715';
      minb.style.cssText='background:transparent;border:1px solid var(--live);color:var(--live);width:20px;height:20px;font-size:10px;cursor:pointer;border-radius:3px';
      closeb.style.cssText='background:transparent;border:1px solid #ff4444;color:#ff4444;width:20px;height:20px;font-size:10px;cursor:pointer;border-radius:3px';
      minb.onmouseover=()=>minb.style.background='var(--live)'; minb.onmouseout=()=>minb.style.background='transparent';
      closeb.onmouseover=()=>closeb.style.background='#ff4444'; closeb.onmouseout=()=>closeb.style.background='transparent';
      right.appendChild(minb); right.appendChild(closeb);
      titlebar.appendChild(left); titlebar.appendChild(right);
      wrap.appendChild(titlebar);
      app.element.parentNode.insertBefore(wrap, app.element);
      wrap.appendChild(app.element);
      w.appIcon=icon; w.titlebar=titlebar; w.wrap=wrap;
      minb.onclick=e=>{ e.stopPropagation(); minimizeWindow(id); };
      closeb.onclick=e=>{ e.stopPropagation(); closeWindow(id); };
    }
    const wrap=app.element.parentElement;
    const titlebar=wrap.querySelector('.w420-titlebar');
    if(w.x===undefined){ w.x=60+STATE.activeApps.length*25; w.y=60+STATE.activeApps.length*25; }
    wrap.style.left=(w.x||60)+'px'; wrap.style.top=(w.y||60)+'px';
    wrap.style.width=(w.w||'75%')+'px'; wrap.style.height=(w.h||'auto')+'px';
    wrap.style.display='flex'; wrap.style.flexDirection='column';
    wrap.style.zIndex=STATE.topZ++; STATE.win[id].z=STATE.topZ;
    STATE.activeApps.unshift(id); STATE.focused=id;
    w.minimized=false; w.fullscreen=false; w.maximized=false;
    app.element.style.display='flex'; app.element.style.flexDirection='column';
    if(app.onOpen){ try{await app.onOpen(id);}catch(e){notify('w420','open error '+id, 'var(--sim)');} }
    // drag заголовок
    titlebar.onmousedown=e=>{ if(e.target.closest('button'))return; e.preventDefault();
      const dx=e.clientX-w.x; const dy=e.clientY-w.y;
      const mousemove=(ev)=>{w.x=ev.clientX-dx; w.y=ev.clientY-dy; wrap.style.left=w.x+'px'; wrap.style.top=w.y+'px';};
      const mouseup=()=>{document.removeEventListener('mousemove',mousemove);document.removeEventListener('mouseup',mouseup);};
      document.addEventListener('mousemove',mousemove);document.addEventListener('mouseup',mouseup);
    };
    titlebar.oncontextmenu=e=>{ e.preventDefault(); openMenu(id, e.clientX, e.clientY); };
    wrap.onmousedown=()=>focusWindow(id);
    STATE.win[id]=w; renderTaskbar(); notify('w420','opened: '+app.label,'var(--live)');
  }

  // === Закрыть окно ===
  async function closeWindow(id){
    const app=STATE.apps[id]; if(!app || app.state==='hidden') return;
    if(app.onBeforeClose){ const cancel=await app.onBeforeClose(id); if(cancel!==false) return; }
    try{ if(app.onClose){ try{await app.onClose(id);}catch(e){}} }catch(e){}
    const wrap=app.element.parentElement;
    // ВАЖНО: обёртку НЕ удаляем — секция должна остаться в DOM, чтобы окно можно было открыть снова.
    // Закрытие = скрыть окно и остановить работу модуля (onClose выше); секция остаётся в wrap.
    if(wrap.classList.contains('w420-window')){ wrap.style.display='none'; app.element.style.display='none'; app.element.style.flexDirection=''; }
    else{ app.element.style.display='none'; app.element.style.flexDirection=''; }
    app.state='hidden';
    STATE.activeApps=STATE.activeApps.filter(a=>a!==id);
    if(STATE.focused===id) STATE.focused=STATE.activeApps[0]||null;
    renderTaskbar(); notify('w420','closed: '+app.label,'var(--sim)');
  }

  // === Свернуть ===
  function minimizeWindow(id){
    const app=STATE.apps[id]; if(!app) return;
    app.state='minimized'; const wrap=app.element.parentElement;
    wrap.style.display='none'; STATE.win[id].minimized=true;
    if(STATE.focused===id) STATE.focused=STATE.activeApps[0]||null;
    renderTaskbar();
  }

  // === Фокус / поднять ===
  function focusWindow(id){
    const w=STATE.win[id]; if(!w) return;
    STATE.topZ++; w.z=STATE.topZ;
    const wrap=STATE.apps[id].element.parentElement;
    if(wrap) wrap.style.zIndex=STATE.topZ;
    STATE.focused=id;
    STATE.activeApps=STATE.activeApps.filter(a=>a!==id); STATE.activeApps.unshift(id);
    renderTaskbar();
  }

  // === Полноэкранный режим всего приложения (Alt+Enter) ===
  // Разворачивает САМ ДЕСКТОП приложения во весь экран (нативное окно Tauri setFullscreen,
  // в браузере — requestFullscreen всего документа). Панель задач, трей и кнопка TOOLS
  // при этом остаются на месте и занимают весь экран — fullscreen относится к приложению, а не к одному окну.
  async function toggleFullscreen(){
    if(fullscreen){
      // выход: сворачиваем всё приложение из fullscreen
      if(NATIVE){
        try{ await window.__TAURI__.window.getCurrentWindow().setFullscreen(false); }catch(e){}
      } else if(document.exitFullscreen){ try{ await document.exitFullscreen(); }catch(e){} }
      fullscreen=false;
      document.body.classList.remove('w420-full');
      renderTaskbar(); notify('w420','fullscreen OFF — десктоп приложения','var(--wip)');
    }else{
      // вход: всё приложение на весь экран, taskbar/tray остаются видимыми
      if(NATIVE){
        try{ await window.__TAURI__.window.getCurrentWindow().setFullscreen(true); }catch(e){}
      } else if(document.documentElement.requestFullscreen){ try{ await document.documentElement.requestFullscreen(); }catch(e){} }
      fullscreen=true;
      document.body.classList.add('w420-full');
      renderTaskbar(); notify('w420','FULL SCREEN — весь десктоп приложения','var(--live)');
    }
  }

  function restoreWindow(id){
    const w=STATE.win[id];
    w.x=60+STATE.activeApps.indexOf(id)*25; w.y=60+STATE.activeApps.indexOf(id)*25;
    const wrap=STATE.apps[id].element.parentElement;
    const titlebar=wrap.querySelector('.w420-titlebar'); if(titlebar) titlebar.style.display='flex';
    wrap.style.top=w.y+'px'; wrap.style.left=w.x+'px'; wrap.style.width=(w.w||'75%')+'px'; wrap.style.height=(w.h||'auto')+'px';
    wrap.style.zIndex=STATE.topZ++; w.z=STATE.topZ;
    document.body.classList.remove('w420-full'); document.body.style.paddingBottom='';
    fullscreen=false; w.maximized=false;
    renderTaskbar(); notify('w420','restored','var(--wip)');
  }

  // === Открыть приложение ===
  function openApp(appId){
    const app=STATE.apps[appId]; if(!app) return;
    if(app.aliasOf){ // deep-link: открыть целевое окно и проскроллить к карточке
      openWindow(app.aliasOf);
      if(app.card) setTimeout(()=>{const c=$(app.card); if(c) c.scrollIntoView({block:'center',behavior:'smooth'});},200);
      return;
    }
    openWindow(appId);
  }

  // === Меню трея ===
  function openMenu(id, x, y){
    const w=STATE.win[id], menu=w&&w.menu; if(!menu) return;
    closeAllMenus();
    menu.style.display='block'; menu.style.left=(x||100)+'px'; menu.style.top=(y||100)+'px';
    STATE.activeMenu=menu;
  }

  // === Закрыть все меню ===
  function closeAllMenus(){
    Object.values(STATE.menus).forEach(m=>{ if(m) m.style.display='none'; });
    STATE.menus={}; STATE.activeMenu=null;
  }

  // === Рендер панели задач ===
  function renderTaskbar(){
    let tb=$('#w420-taskbar'); if(tb) tb.remove();
    tb=document.createElement('div'); tb.id='w420-taskbar';
    tb.style.cssText='position:fixed;bottom:0;left:0;right:0;height:40px;background:var(--head);border-top:1px solid var(--live);display:flex;align-items:center;justify-content:space-between;padding:0 8px;z-index:900;font-family:\'Share Tech Mono\',monospace;font-size:11px;';
    // кнопка TOOLS
    const tools=document.createElement('button');
    tools.textContent='TOOLS';
    tools.style.cssText='background:transparent;border:1px solid var(--live);color:var(--live);padding:5px 14px;font-size:10px;font-weight:700;letter-spacing:1px;cursor:pointer;border-radius:4px;';
    tools.onmouseover=()=>{tools.style.background='var(--live)';tools.style.color='#000';};
    tools.onmouseout=()=>{tools.style.background='transparent';tools.style.color='var(--live)';};
    tools.onclick=toggleToolsMenu;
    tb.appendChild(tools);
    // центр: открытые окна
    const center=document.createElement('div');
    center.style.cssText='display:flex;gap:6px;flex:1;justify-content:center;align-items:center;overflow-x:auto;';
    STATE.activeApps.forEach(id=>{
      const app=STATE.apps[id]; if(!app) return; const w=STATE.win[id];
      const btn=document.createElement('button');
      btn.style.cssText=`background:${w.minimized?'var(--panel)':'var(--live)'};border:1px solid var(--live);color:${w.minimized?'var(--ink)':'#000'};width:34px;height:30px;font-size:14px;cursor:pointer;border-radius:4px;display:flex;align-items:center;justify-content:center;`;
      btn.innerHTML=app.icon;
      btn.onclick=()=>{ if(w.minimized){ openWindow(id); } else if(STATE.focused===id){ minimizeWindow(id); } else { focusWindow(id); } };
      btn.oncontextmenu=e=>{ e.preventDefault(); openMenu(id, e.clientX, e.clientY); };
      center.appendChild(btn);
      if(w.alert){
        const badge=document.createElement('div');
        badge.style.cssText='position:absolute;top:-4px;right:-4px;background:#ff4444;color:#000;width:14px;height:14px;font-size:9px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;border:1px solid #fff;';
        badge.textContent=w.alert; btn.appendChild(badge);
      }
    });
    tb.appendChild(center);
    // правая часть: трей
    const tray=document.createElement('div'); tray.style.cssText='display:flex;gap:8px;align-items:center;';
    const trayItems=[
      {id:'monitor',icon:'\ud83d\udda0',menu:{cmds:[{label:'Health dashboard',cmd:'health'},{label:'System operations',cmd:'sysops'},{label:'Network scanner',cmd:'net'},{label:'Emergency',cmd:'emergency'}]}},
      {id:'chat',icon:'\ud83d\udcac',menu:{cmds:[{label:'Send',cmd:'term'}]}},
      {id:'ai',icon:'\ud83e\udde0',menu:{cmds:[{label:'Brief',action:()=>goAI('BRIEF')},{label:'Stop task',action:()=>stopTask('трей')},{label:'Lock keys',action:()=>lockKeys()},{label:'Full screen',action:()=>toggleFullscreen()}]}}
    ];
    trayItems.forEach(ti=>{
      const b=document.createElement('button');
      b.style.cssText=`width:30px;height:30px;background:var(--panel);border:1px solid var(--live);color:var(--ink);font-size:15px;cursor:pointer;border-radius:4px;display:flex;align-items:center;justify-content:center;`;
      b.textContent=ti.icon;
      b.onmouseover=()=>{b.style.background='var(--live)';b.style.color='#000';};
      b.onmouseout=()=>{b.style.background='var(--panel)';b.style.color='var(--ink)';};
      const menu=buildMenu(ti.menu.cmds);
      document.body.appendChild(menu); menu.style.display='none';
      STATE.trays[ti.id]={button:b,menu};
      b.onclick=e=>{
        e.stopPropagation(); closeAllMenus();
        menu.style.display='block';
        const r=b.getBoundingClientRect();
        menu.style.left=(r.left-170)+'px'; menu.style.top=(r.top-10-menu.offsetHeight)+'px';
        STATE.activeMenu=menu;
      };
      tray.appendChild(b);
    });
    tb.appendChild(tray);
    document.body.appendChild(tb);
  }

  // === Кнопка tools (меню приложений) ===
  function toggleToolsMenu(){
    let tm=$('#w420-tools-menu');
    if(tm){ tm.remove(); STATE.toolsOpen=false; return; }
    tm=document.createElement('div'); tm.id='w420-tools-menu';
    tm.style.cssText='position:fixed;bottom:48px;left:10px;z-index:310;background:var(--head);border:1px solid var(--live);border-radius:8px;min-width:280px;padding:10px;font-family:\'Share Tech Mono\',monospace;font-size:11px;color:var(--ink);max-height:calc(100vh - 120px);overflow:auto;';
    const grid=document.createElement('div');
    grid.style.cssText='display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:10px;';
    Object.values(STATE.apps).forEach(app=>{
      const b=document.createElement('button');
      b.style.cssText='background:var(--panel);border:1px solid var(--live);color:var(--ink);padding:8px 6px;font-size:10px;cursor:pointer;border-radius:6px;display:flex;flex-direction:column;align-items:center;gap:4px;';
      b.innerHTML=`<span style="font-size:22px">${app.icon}</span><span style="font-weight:600">${app.label}</span>`;
      b.onmouseover=()=>{b.style.background='var(--live)';b.style.color='#000';};
      b.onmouseout=()=>{b.style.background='var(--panel)';b.style.color='var(--ink)';};
      b.onclick=()=>{ if(app.id==='settings'){const s=$('#spanel'); if(s) s.hidden=!s.hidden; toggleToolsMenu(); return;} openApp(app.id); toggleToolsMenu(); };
      grid.appendChild(b);
    });
    tm.appendChild(grid); document.body.appendChild(tm); STATE.toolsOpen=true;
    const outside=()=>{ if(STATE.toolsOpen){ toggleToolsMenu(); document.removeEventListener('click',outside); } };
    setTimeout(()=>document.addEventListener('click',outside),10);
  }

  // === Горячие клавиши ===
  document.addEventListener('keydown',e=>{
    if(e.altKey && e.key==='Enter'){ e.preventDefault(); toggleFullscreen(); }
    if(e.altKey && /\d/.test(e.key)){ const idx=parseInt(e.key)-1; if(STATE.activeApps[idx]){ focusWindow(STATE.activeApps[idx]); } }
  });

  // === Экспорт API ===
  window.Desktop={
    register, openWindow, closeWindow, minimizeWindow, focusWindow, toggleFullscreen, restoreWindow,
    openApp, renderTaskbar, notify, apps:()=>STATE.apps, win:()=>STATE.win, state:()=>STATE
  };

  // === Инициализация (регистрация 10 базовых приложений) ===
  document.addEventListener('DOMContentLoaded',()=>{
    document.addEventListener('click',e=>{ if(e.target.closest('[id="w420-tools-menu"]') || e.target.closest('[id="w420-taskbar"]')) return; closeAllMenus(); });
    renderTaskbar();
    // 10 окон по реальным секциям index.html
    register('term',{icon:'\ud83d\udda5\ufe0f',label:'Terminal',section:'#v-term',basicMenu:{cmds:[{label:'Clear output',action:()=>{const o=$('#out');if(o)o.textContent=''}}]}});
    register('vault',{icon:'\ud83d\udd10',label:'QFS Vault',section:'#v-vault',basicMenu:{cmds:[{label:'Encrypt + save',cmd:'vault'}]}});
    register('id',{icon:'\ud83c\udd94',label:'Digital ID',section:'#v-id',basicMenu:{cmds:[{label:'Generate identity',action:()=>$('#idgen').click()}]}});
    register('map',{icon:'\ud83d\uddfa\ufe0f',label:'Mind Map',section:'#v-map',onOpen:()=>{if(typeof sizeMap==='function')sizeMap()}});
    register('radio',{icon:'\ud83d\udcfb\ufe0f',label:'AGI-\u03a9 FM',section:'#v-radio',basicMenu:{cmds:[{label:'On air',action:()=>$('#rbtn').click()},{label:'Request theme',action:()=>{}}]}});
    register('audit',{icon:'\ud83d\udccb',label:'Audit Log',section:'#v-audit',onOpen:()=>{if(typeof drawAudit==='function')drawAudit()}});
    register('key',{icon:'\ud83d\udcb3',label:'Wallet',section:'#v-key',basicMenu:{cmds:[{label:'New wallet',action:()=>$('#kgen').click()}]}});
    register('wallet',{icon:'\ud83d\udcb0',label:'Mint \u00b7 DEX [SIM]',section:'#v-wallet'});
    register('ai',{icon:'\ud83e\udde0',label:'AGI Assistant',section:'#v-ai',basicMenu:{cmds:[{label:'Brief',action:()=>goAI(BRIEF||'BRIEF')},{label:'Stop task',action:()=>stopTask('трей')},{label:'Clear chat',action:()=>{const c=$('#chat');if(c)c.innerHTML=''}}]}});
    register('net',{icon:'\ud83c\udf10',label:'Network \u00b7 Madre \u00b7 SIEM \u00b7 Health',section:'#v-net',basicMenu:{cmds:[{label:'Scan network',action:()=>$('#n-scan').click()},{label:'Madre: refresh',action:()=>$('#madre-refresh').click()},{label:'Health: refresh all',action:()=>$('#hl-refresh').click()},{label:'SIEM: dashboard',action:()=>$('#siem-dash').click()}]}});
    // deep-link пункты меню: открывают окно net и скроллят к нужной карточке
    const deep=(appId,cardId,icon)=>({icon,label:appId,aliasOf:'net',card:cardId});
    register('watchdog',deep('Watchdog / Madre','#madre-out','\ud83d\udee1\ufe0f'));
    register('siem',deep('SIEM','#siem-out','\ud83d\udd14'));
    register('health',deep('Health','#hl-out','\ud83e\ude7a'));
    register('settings',{icon:'\u2699\ufe0f',label:'Settings',section:'#spanel',basicMenu:{cmds:[{label:'Close',action:()=>{const s=$('#spanel');if(s)s.hidden=true}}]}});
    setTimeout(()=>{ window.Desktop.openWindow('term'); }, 300);
  });

  // === Fallbacks для tray-меню ===
  window.goAI=function(s){ notify('AI','goAI('+s+')'); };
  window.stopTask=function(why){ notify('AI','stopTask('+why+')'); };
  window.lockKeys=function(){ notify('AI','keys locked'); };
  window.inv=function(c,a){ return Promise.resolve(); };
})();

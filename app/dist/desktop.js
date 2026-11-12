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
    apps:{}, win:{}, topZ:100, focused:null, activeApps:[], menus:{}, trays:{}, activeMenu:null, toolsOpen:false,
    notifs:[], iconPos:{}, metrics:null, showDesktop:false, launcherOpen:false, notifPanelOpen:false, taskViewOpen:false, altTabOpen:false,
    ws:[[]], wsIndex:0
  };
  let fullscreen=false;

  // === Всплывающие уведомления (+ запись в центр уведомлений) ===
  function notify(tag, msg, color, app){
    STATE.notifs.push({tag, msg, ts:Date.now(), app:app||null});
    if(STATE.notifs.length>50) STATE.notifs.shift();
    updateBell();
    const d=document.createElement('div');
    d.className='w420-notify';
    d.style.cssText=`position:fixed;top:12px;right:12px;z-index:9999;background:var(--panel);border:1px solid ${color};padding:8px 12px;font-family:var(--fb);font-size:11px;color:var(--ink);min-width:200px;opacity:1;transition:opacity .5s`;
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
      onBeforeClose:cfg.onBeforeClose, onDropFiles:cfg.onDropFiles, element:el, state:'hidden'};
    STATE.win[id]={x:60,y:60,w:Math.min(el.clientWidth||700, Math.round(window.innerWidth*0.72)),h:Math.min(el.clientHeight||500, Math.round(window.innerHeight*0.7)),minimized:false,
      fullscreen:false,maximized:false,z:100,appIcon:null,menu:null,ws:STATE.wsIndex};
    if(cfg.basicMenu){ STATE.win[id].menu=buildMenu(cfg.basicMenu); STATE.win[id].menuCmds=cfg.basicMenu.cmds; }
    notify('w420','app registered: '+cfg.label||id,'var(--live)');
  }

  // === Контекстное меню трея (basic commands) ===
  function buildMenu(cmds){
    const menu=document.createElement('div');
    menu.className='w420-tray-menu';
    menu.style.cssText='position:absolute;z-index:300;background:var(--head);border:1px solid var(--live);border-radius:6px;min-width:200px;padding:6px;font-family:\'var(--fb)\';font-size:11px;color:var(--ink);box-shadow:0 0 16px var(--glow)';
    cmds.forEach(c=>{
      const btn=document.createElement('button');
      btn.style.cssText='width:100%;background:transparent;border:none;color:var(--ink);text-align:left;padding:6px 8px;font-family:\'var(--fb)\';font-size:11px;cursor:pointer;border-radius:4px';
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
      wrap.style.cssText='position:fixed;background:var(--panel);border:1px solid var(--live);border-radius:6px;box-shadow:0 0 30px var(--glow),inset 0 0 20px var(--glow);overflow:hidden;font-family:\'var(--fb)\';color:var(--ink);';
      const titlebar=document.createElement('div');
      titlebar.className='w420-titlebar';
      titlebar.style.cssText='height:28px;background:var(--head);border-bottom:1px solid var(--live);display:flex;align-items:center;justify-content:space-between;user-select:none;padding:0 8px;cursor:default;';
      const left=document.createElement('div'); left.style.cssText='display:flex;align-items:center;gap:8px;font-size:11px;font-weight:700;color:var(--live);letter-spacing:1px;';
      const icon=document.createElement('span'); icon.style.cssText='font-size:13px'; icon.textContent=app.icon;
      const title=document.createElement('span'); title.textContent=app.label;
      left.appendChild(icon); left.appendChild(title);
      const right=document.createElement('div'); right.style.cssText='display:flex;gap:6px';
      const maxb=document.createElement('button'); maxb.textContent=String.fromCharCode(9634); maxb.title='Развернуть / восстановить';
      const minb=document.createElement('button'); minb.textContent='\u2014';
      const closeb=document.createElement('button'); closeb.textContent='\u2715';
      minb.style.cssText='background:transparent;border:1px solid var(--live);color:var(--live);width:20px;height:20px;font-size:10px;cursor:pointer;border-radius:3px';
      maxb.style.cssText='background:transparent;border:1px solid var(--live);color:var(--live);width:20px;height:20px;font-size:10px;cursor:pointer;border-radius:3px';
      closeb.style.cssText='background:transparent;border:1px solid #ff4444;color:#ff4444;width:20px;height:20px;font-size:10px;cursor:pointer;border-radius:3px';
      minb.onmouseover=()=>minb.style.background='var(--live)'; minb.onmouseout=()=>minb.style.background='transparent';
      maxb.onmouseover=()=>maxb.style.background='var(--live)'; maxb.onmouseout=()=>maxb.style.background='transparent';
      closeb.onmouseover=()=>closeb.style.background='#ff4444'; closeb.onmouseout=()=>closeb.style.background='transparent';
      right.appendChild(minb); right.appendChild(maxb); right.appendChild(closeb);
      titlebar.appendChild(left); titlebar.appendChild(right);
      wrap.appendChild(titlebar);
      // resize-хендлы по краям и углам окна (внутри wrap, т.к. у wrap overflow:hidden)
      ['n','s','e','w','ne','nw','se','sw'].forEach(d=>{
        const h=document.createElement('div'); h.className='w420-rz w420-rz-'+d; h.dataset.dir=d;
        h.onmousedown=e=>startResize(e,id,d);
        wrap.appendChild(h);
      });
      app.element.parentNode.insertBefore(wrap, app.element);
      wrap.appendChild(app.element);
      w.appIcon=icon; w.titlebar=titlebar; w.wrap=wrap;
      minb.onclick=e=>{ e.stopPropagation(); minimizeWindow(id); };
      maxb.onclick=e=>{ e.stopPropagation(); maximizeWindow(id); };
      titlebar.ondblclick=e=>{ if(e.target.closest('button'))return; maximizeWindow(id); };
      closeb.onclick=e=>{ e.stopPropagation(); closeWindow(id); };
    }
    const wrap=app.element.parentElement;
    const titlebar=wrap.querySelector('.w420-titlebar');
    if(w.x===undefined){ w.x=60+STATE.activeApps.length*25; w.y=60+STATE.activeApps.length*25; }
    const sv=((loadLayout()||{}).win||{})[id]; // B5: восстановить сохранённую геометрию
    if(sv){ w.x=sv.x??w.x; w.y=sv.y??w.y; w.w=sv.w??w.w; w.h=sv.h??w.h; if(sv.ws!==undefined) w.ws=sv.ws; }
    if(w.ws===undefined) w.ws=STATE.wsIndex;
    wrap.style.left=(w.x||60)+'px'; wrap.style.top=(w.y||60)+'px';
    wrap.style.width=(w.w||'75%')+'px'; wrap.style.height=(w.h||'auto')+'px';
    wrap.style.display='flex'; wrap.style.flexDirection='column';
    wrap.style.zIndex=STATE.topZ++; STATE.win[id].z=STATE.topZ;
    STATE.activeApps.unshift(id); STATE.focused=id;
    w.minimized=false; w.fullscreen=false; w.maximized=false;
    app.element.style.display='flex'; app.element.style.flexDirection='column';
    if(app.onOpen){ try{await app.onOpen(id);}catch(e){notify('w420','open error '+id, 'var(--sim)');} }
    // drag заголовок + snap к краям экрана (B1)
    titlebar.onmousedown=e=>{ if(e.target.closest('button'))return; e.preventDefault();
      const dx=e.clientX-w.x, dy=e.clientY-w.y;
      let preview=null, snapG=null;
      const mousemove=(ev)=>{
        w.x=ev.clientX-dx; w.y=ev.clientY-dy;
        wrap.style.left=w.x+'px'; wrap.style.top=w.y+'px';
        const g=snapAt(w.x, w.y, wrap.offsetWidth, wrap.offsetHeight);
        snapG=g;
        if(g){ if(!preview){ preview=document.createElement('div'); preview.id='w420-snap-preview'; preview.style.cssText='position:fixed;border:2px dashed var(--live);background:color-mix(in srgb,var(--live) 12%,transparent);z-index:899;pointer-events:none;border-radius:6px;'; document.body.appendChild(preview);} preview.style.left=g.x+'px'; preview.style.top=g.y+'px'; preview.style.width=g.w+'px'; preview.style.height=g.h+'px'; preview.style.display='block'; }
        else if(preview) preview.style.display='none';
      };
      const mouseup=()=>{
        document.removeEventListener('mousemove',mousemove);document.removeEventListener('mouseup',mouseup);
        if(preview) preview.remove();
        if(snapG){
          if(snapG.max){ w.prev=w.prev||{x:w.x,y:w.y,w:w.w,h:w.h}; w.maximized=true; wrap.classList.add('w420-max'); }
          else { w.maximized=false; wrap.classList.remove('w420-max'); w.x=snapG.x; w.y=snapG.y; w.w=snapG.w; w.h=snapG.h; wrap.style.left=snapG.x+'px'; wrap.style.top=snapG.y+'px'; wrap.style.width=snapG.w+'px'; wrap.style.height=snapG.h+'px'; }
        }
        saveLayout();
      };
      document.addEventListener('mousemove',mousemove);document.addEventListener('mouseup',mouseup);
    };
    titlebar.oncontextmenu=e=>{ e.preventDefault(); openWindowMenu(id, e.clientX, e.clientY); };
    wrap.onmousedown=()=>focusWindow(id);
    STATE.win[id]=w; renderTaskbar(); notify('w420','opened: '+app.label,'var(--live)',id);
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

  // === Развернуть окно на весь десктоп (или восстановить) ===
  // Разворачивает окно инструмента на всю область над панелью задач (класс .w420-max),
  // предыдущая геометрия сохраняется в w.prev и восстанавливается повторным нажатием.
  function maximizeWindow(id){
    const app=STATE.apps[id]; if(!app||app.state==='hidden') return;
    const w=STATE.win[id]; const wrap=app.element.parentElement;
    if(w.maximized||fullscreen){
      // восстановить прежние размеры
      w.maximized=false;
      const p=w.prev||{x:60,y:60,w:'75%',h:'auto'};
      w.x=p.x; w.y=p.y; w.w=p.w; w.h=p.h;
      wrap.classList.remove('w420-max');
      wrap.style.left=w.x+'px'; wrap.style.top=w.y+'px';
      wrap.style.width=(typeof w.w==='number')?w.w+'px':w.w;
      wrap.style.height=(typeof w.h==='number')?w.h+'px':w.h;
    }else{
      w.prev={x:w.x,y:w.y,w:w.w,h:w.h};
      w.maximized=true;
      wrap.classList.add('w420-max');
    }
    focusWindow(id); renderTaskbar();
  }

  // === Resize окна курсором мыши за края/углы ===
  function startResize(e,id,dir){
    const app=STATE.apps[id]; if(!app) return;
    const w=STATE.win[id]; const wrap=app.element.parentElement;
    if(w.maximized||w.fullscreen||fullscreen) return; // в max/fullscreen размер не меняем
    e.preventDefault(); e.stopPropagation(); focusWindow(id);
    const startX=e.clientX, startY=e.clientY;
    const geo=wrap.getBoundingClientRect();
    const ox=geo.left, oy=geo.top, ow=geo.width, oh=geo.height;
    const MIN_W=280, MIN_H=180;
    const move=ev=>{
      const dx=ev.clientX-startX, dy=ev.clientY-startY;
      let nx=ox, ny=oy, nw=ow, nh=oh;
      if(dir.includes('e')) nw=Math.max(MIN_W, ow+dx);
      if(dir.includes('s')) nh=Math.max(MIN_H, oh+dy);
      if(dir.includes('w')){ nw=Math.max(MIN_W, ow-dx); nx=ox+(ow-nw); }
      if(dir.includes('n')){ nh=Math.max(MIN_H, oh-dy); ny=oy+(oh-nh); }
      w.x=nx; w.y=ny; w.w=nw; w.h=nh;
      wrap.style.left=nx+'px'; wrap.style.top=ny+'px';
      wrap.style.width=nw+'px'; wrap.style.height=nh+'px';
    };
    const up=()=>{ document.removeEventListener('mousemove',move); document.removeEventListener('mouseup',up); };
    document.addEventListener('mousemove',move); document.addEventListener('mouseup',up);
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
        try{ const r=await inv('app_fullscreen_toggle'); fullscreen=!!(r&&r.fullscreen); }catch(e){}
      } else if(document.exitFullscreen){ try{ await document.exitFullscreen(); }catch(e){} }
      fullscreen=false;
      document.body.classList.remove('w420-full');
      renderTaskbar(); notify('w420','fullscreen OFF — десктоп приложения','var(--wip)');
    }else{
      // вход: всё приложение на весь экран, taskbar/tray остаются видимыми
      if(NATIVE){
        try{ const r=await inv('app_fullscreen_toggle'); fullscreen=!!(r&&r.fullscreen); }catch(e){}
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

  // === Закрыть все меню (контекстные, трея и tools) ===
  function closeAllMenus(){
    Object.values(STATE.menus).forEach(m=>{ if(m) m.style.display='none'; });
    Object.values(STATE.trays).forEach(t=>{ if(t&&t.menu) t.menu.style.display='none'; });
    STATE.menus={}; STATE.activeMenu=null;
    const tm=$('#w420-tools-menu'); if(tm){ tm.remove(); STATE.toolsOpen=false; }
  }

  // === Рендер панели задач ===
  function renderTaskbar(){
    let tb=$('#w420-taskbar'); if(tb) tb.remove();
    tb=document.createElement('div'); tb.id='w420-taskbar';
    tb.style.cssText='position:fixed;bottom:0;left:0;right:0;height:40px;background:var(--head);border-top:1px solid var(--live);display:flex;align-items:center;justify-content:space-between;padding:0 8px;z-index:900;font-family:\'var(--fb)\';font-size:11px;';
    // кнопка TOOLS
    const tools=document.createElement('button');
    tools.textContent='TOOLS';
    tools.style.cssText='background:transparent;border:1px solid var(--live);color:var(--live);padding:5px 14px;font-size:10px;font-weight:700;letter-spacing:1px;cursor:pointer;border-radius:4px;';
    tools.onmouseover=()=>{tools.style.background='var(--live)';tools.style.color='#000';};
    tools.onmouseout=()=>{tools.style.background='transparent';tools.style.color='var(--live)';};
    tools.onclick=toggleToolsMenu;
    tb.appendChild(tools);
    // центр: открытые окна ТЕКУЩЕГО рабочего стола
    const center=document.createElement('div');
    center.style.cssText='display:flex;gap:6px;flex:1;justify-content:center;align-items:center;overflow-x:auto;';
    visibleApps().forEach(id=>{
      const app=STATE.apps[id]; if(!app) return; const w=STATE.win[id];
      const btn=document.createElement('button');
      btn.style.cssText=`background:${w.minimized?'var(--panel)':'var(--live)'};border:1px solid var(--live);color:${w.minimized?'var(--ink)':'#000'};width:34px;height:30px;font-size:14px;cursor:pointer;border-radius:4px;display:flex;align-items:center;justify-content:center;`;
      btn.innerHTML=app.icon;
      btn.onclick=()=>{ if(w.minimized){ openWindow(id); } else if(STATE.focused===id){ minimizeWindow(id); } else { focusWindow(id); } };
      btn.onmouseenter=()=>showPreview(id,btn); btn.onmouseleave=hidePreview; // B2: превью окна
      btn.oncontextmenu=e=>{ e.preventDefault(); openWindowMenu(id, e.clientX, e.clientY); };
      center.appendChild(btn);
      if(w.alert){
        const badge=document.createElement('div');
        badge.style.cssText='position:absolute;top:-4px;right:-4px;background:#ff4444;color:#000;width:14px;height:14px;font-size:9px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;border:1px solid #fff;';
        badge.textContent=w.alert; btn.appendChild(badge);
      }
    });
    tb.appendChild(center);
    // B4: пейджер рабочих столов
    const pager=document.createElement('div'); pager.id='w420-ws-pager';
    pager.style.cssText='display:flex;gap:4px;align-items:center;padding:0 6px;border-left:1px solid var(--line);border-right:1px solid var(--line);';
    STATE.ws.forEach((_,i)=>{
      const b=document.createElement('button');
      b.textContent=String(i+1);
      b.title='Рабочий стол '+(i+1)+' (Win+Ctrl+←/→)';
      b.style.cssText='width:22px;height:22px;background:'+(i===STATE.wsIndex?'var(--live)':'transparent')+';border:1px solid var(--live);color:'+(i===STATE.wsIndex?'#000':'var(--live)')+';font-size:10px;cursor:pointer;border-radius:3px;font-family:var(--fb);';
      b.onclick=()=>switchWs(i);
      pager.appendChild(b);
    });
    const plus=document.createElement('button'); plus.textContent='+'; plus.title='Новый рабочий стол (Win+Ctrl+D)';
    plus.style.cssText='width:22px;height:22px;background:transparent;border:1px dashed var(--live);color:var(--live);font-size:11px;cursor:pointer;border-radius:3px;font-family:var(--fb);';
    plus.onclick=()=>newWs();
    pager.appendChild(plus);
    tb.appendChild(pager);
    // правая часть: трей
    const tray=document.createElement('div'); tray.style.cssText='display:flex;gap:8px;align-items:center;';
    const trayItems=[
      {id:'monitor',icon:'\ud83d\udda0',menu:{cmds:[
        // D2: быстрые действия
        {label:'🔍 Скан сети',cmd:'net'},
        {label:'🚨 Emergency',action:()=>{ openApp('net'); setTimeout(()=>{ const b=$('#e-apply'); if(b){ b.scrollIntoView({block:'center'}); } },400); }},
        {label:'🔒 Lock keys',action:()=>lockKeys()},
        {label:'📡 SIEM dashboard',cmd:'siem'},
        {label:'💚 Health: refresh all',action:()=>{ openApp('health'); const b=$('#hl-refresh'); if(b) b.click(); }},
        {label:'─ все модули ─',action:()=>{}},
        // D2: полный список зарегистрированных приложений
        ...Object.values(STATE.apps).filter(a=>!a.aliasOf).map(a=>({label:a.icon+' '+a.label, cmd:a.id}))
      ]}},
      {id:'chat',icon:'\ud83d\udcac',menu:{cmds:[{label:'Send',cmd:'term'},{label:'🤖 AI-чат',cmd:'ai'},{label:'📻 Radio',cmd:'radio'}]}},
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
        e.stopPropagation();
        const wasOpen = menu.style.display==='block';
        closeAllMenus();
        if(wasOpen) return; // повторное нажатие по иконке — закрыть меню (toggle)
        menu.style.display='block';
        const r=b.getBoundingClientRect();
        menu.style.left=Math.max(8, r.left-170)+'px'; menu.style.top=(r.top-10-menu.offsetHeight)+'px';
        STATE.activeMenu=menu;
      };
      tray.appendChild(b);
    });
    tb.appendChild(tray);
    // D1: инлайн-монитор CPU/RAM/Net в трее (данные из system_metrics бэкенда)
    const sm=document.createElement('span'); sm.id='w420-sysmon';
    sm.style.cssText='color:var(--live);font-size:10px;cursor:default;user-select:none;white-space:nowrap;padding:0 4px;border:1px solid var(--line);border-radius:4px;background:var(--panel);';
    sm.textContent=sysmonText();
    sm.title='CPU / RAM / Net — обновление каждые 2 с (system_metrics)';
    tray.appendChild(sm);
    const bell=document.createElement('button'); bell.id='w420-bell'; bell.textContent='🔔';
    bell.style.cssText='width:30px;height:30px;background:var(--panel);border:1px solid var(--live);color:var(--ink);font-size:13px;cursor:pointer;border-radius:4px;';
    bell.onclick=e=>{ e.stopPropagation(); toggleNotifPanel(); };
    tray.appendChild(bell); updateBell();
    // A2: часы (клик — календарь)
    const clock=document.createElement('span'); clock.id='w420-clock';
    clock.style.cssText='color:var(--ink);font-size:11px;cursor:pointer;padding:0 6px;user-select:none;';
    clock.onclick=e=>{ e.stopPropagation(); toggleCalendar(); };
    tray.appendChild(clock);
    // A5: «показать десктоп» — узкая полоска на самом краю taskbar
    const sd=document.createElement('div'); sd.id='w420-showdesk'; sd.title='Показать десктоп (Win+D)';
    sd.style.cssText='width:7px;height:100%;border-left:1px solid var(--line);cursor:pointer;margin-left:2px;';
    sd.onmouseover=()=>sd.style.background='var(--live)'; sd.onmouseout=()=>sd.style.background='transparent';
    sd.onclick=()=>toggleShowDesktop();
    tray.appendChild(sd);
    document.body.appendChild(tb);
    saveLayout(); // B5: автосохранение раскладки при любом изменении taskbar
  }

  // === Кнопка tools (меню приложений) ===
  function toggleToolsMenu(){
    let tm=$('#w420-tools-menu');
    if(tm){ tm.remove(); STATE.toolsOpen=false; return; }
    tm=document.createElement('div'); tm.id='w420-tools-menu';
    tm.style.cssText='position:fixed;bottom:48px;left:10px;z-index:310;background:var(--head);border:1px solid var(--live);border-radius:8px;min-width:280px;padding:10px;font-family:\'var(--fb)\';font-size:11px;color:var(--ink);max-height:calc(100vh - 120px);overflow:auto;';
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
    if(e.metaKey && e.ctrlKey && e.key==='ArrowLeft'){ e.preventDefault(); switchWs(STATE.wsIndex-1); }
    if(e.metaKey && e.ctrlKey && e.key==='ArrowRight'){ e.preventDefault(); switchWs(STATE.wsIndex+1); }
    if(e.metaKey && e.ctrlKey && e.key==='d'){ e.preventDefault(); newWs(); }
    if(e.metaKey && e.ctrlKey && e.key==='w'){ e.preventDefault(); closeWs(); }
    if(e.metaKey && !e.ctrlKey && e.key==='d'){ e.preventDefault(); toggleShowDesktop(); }
    if(e.metaKey && !e.ctrlKey && e.key==='m'){ e.preventDefault(); minimizeAll(); }
    if(e.metaKey && !e.ctrlKey && e.key.startsWith('Arrow')){ e.preventDefault(); snapFocused(e.key.slice(5).toLowerCase()); }
    if(e.metaKey && !e.ctrlKey && e.key==='Tab'){ e.preventDefault(); openTaskView(); }
    if((e.metaKey||e.ctrlKey) && e.key==='k'){ e.preventDefault(); STATE.launcherOpen?closeLauncher():openLauncher(); }
    if(e.key==='Escape'){ closeLauncher(); closeNotifPanel(); closeCalendar(); closeAllMenus(); }
    if(e.altKey && /\d/.test(e.key)){ const idx=parseInt(e.key)-1; if(STATE.activeApps[idx]){ focusWindow(STATE.activeApps[idx]); } }
  });

  // ================= ФАЗА A: десктоп как у настоящей ОС =================

  // === A1. Иконки приложений на рабочем столе ===
  // === C1. Обои рабочего стола ===
  // Предустановки — только CSS-градиенты/паттерны на переменных темы, без хардкода цветов.
  const WALLPAPERS=[
    {id:'theme',   label:'По умолчанию (под тему)'},
    {id:'void',    label:'Бездна (чистый фон темы)'},
    {id:'grid',    label:'Сетка',            css:'linear-gradient(var(--glow) 1px,transparent 1px),linear-gradient(90deg,var(--glow) 1px,transparent 1px)', size:'34px 34px'},
    {id:'scan',    label:'Сканлайны',        css:'repeating-linear-gradient(0deg,transparent 0 2px,var(--glow) 2px 3px)'},
    {id:'radial',  label:'Свечение из центра', css:'radial-gradient(ellipse at 50% 40%,var(--glow) 0%,transparent 55%)'},
    {id:'diag',    label:'Диагонали',        css:'repeating-linear-gradient(45deg,transparent 0 14px,var(--glow) 14px 15px)'},
    {id:'stars',   label:'Точки',            css:'radial-gradient(var(--live) 1px,transparent 1px)', size:'26px 26px'},
    {id:'vignette',label:'Виньетка',         css:'radial-gradient(ellipse at center,transparent 45%,var(--head) 100%)'}
  ];
  const THEME_WALL={matrix:'grid',amber:'scan',cyan:'radial',violet:'stars',red:'vignette',light:'diag',cyberpunk:'diag',vangogh:'radial'};
  function applyWallpaper(id){
    const saved=id||localStorage.getItem('w420-wallpaper')||'theme';
    if(saved.startsWith('url:')){ document.body.style.background=`url("${saved.slice(4)}") center/cover no-repeat, var(--bg)`; document.body.style.backgroundSize='cover'; }
    else{
      let w=WALLPAPERS.find(x=>x.id===saved);
      if(!w||saved==='theme'){ const t=(document.documentElement.getAttribute('data-theme')||'matrix'); const wid=THEME_WALL[t]||'grid'; w=WALLPAPERS.find(x=>x.id===wid)||WALLPAPERS[2]; }
      document.body.style.backgroundColor='var(--bg)';
      if(w.id==='void'){ document.body.style.background='var(--bg)'; }
      else{ document.body.style.background=`${w.css}, var(--bg)`; document.body.style.backgroundSize=w.size||'auto'; }
    }
    if(id){ try{ localStorage.setItem('w420-wallpaper', id); }catch(e){} }
  }
  function wallpaperMenu(x,y){
    closeAllMenus();
    const items=WALLPAPERS.map(w=>({label:(localStorage.getItem('w420-wallpaper')||'theme')===w.id?'● '+w.label:'○ '+w.label, action:()=>applyWallpaper(w.id)}));
    items.push({label:'🖼 Свой URL изображения…', action:()=>{ const u=prompt('URL изображения для обоев:'); if(u) applyWallpaper('url:'+u); }});
    const m=buildMenu(items);
    document.body.appendChild(m); m.style.display='block';
    m.style.left=Math.min(x,innerWidth-260)+'px'; m.style.top=Math.min(y,innerHeight-320)+'px';
    STATE.menus['wallpaper']=m; STATE.activeMenu=m;
  }
  function themeMenu(x,y){
    closeAllMenus();
    const themes=['matrix','amber','cyan','violet','red','light','cyberpunk','vangogh'];
    const m=buildMenu(themes.map(t=>({label:(document.documentElement.getAttribute('data-theme')===t?'● ':'○ ')+t, action:()=>{
      document.documentElement.setAttribute('data-theme',t);
      try{ localStorage.setItem('w420-theme',t); }catch(e){}
      if(window.I18N&&window.I18N.saveSettings) window.I18N.saveSettings({theme:t});
      if(!localStorage.getItem('w420-wallpaper')||localStorage.getItem('w420-wallpaper')==='theme') applyWallpaper('theme');
      notify('w420','тема: '+t,'var(--live)');
    }})));
    document.body.appendChild(m); m.style.display='block';
    m.style.left=Math.min(x,innerWidth-220)+'px'; m.style.top=Math.min(y,innerHeight-300)+'px';
    STATE.menus['theme']=m; STATE.activeMenu=m;
  }

  function initDesktopIcons(){
    let layer=$('#w420-desktop-icons'); if(layer) layer.remove();
    try{ STATE.iconPos=JSON.parse(localStorage.getItem('w420-iconpos')||'{}'); }catch(e){}
    layer=document.createElement('div'); layer.id='w420-desktop-icons';
    layer.style.cssText='position:fixed;left:8px;top:56px;right:8px;bottom:48px;z-index:5;pointer-events:none;';
    Object.values(STATE.apps).forEach(app=>{
      if(app.aliasOf) return;
      const ic=document.createElement('div'); ic.className='w420-dicon'; ic.dataset.app=app.id;
      ic.style.cssText='position:absolute;width:96px;display:flex;flex-direction:column;align-items:center;gap:3px;padding:6px 2px;cursor:pointer;border:1px solid transparent;border-radius:6px;text-align:center;pointer-events:auto;';
      const pos=STATE.iconPos[app.id]||{x:8+Object.keys(STATE.iconPos).length*0, y:56+ (Object.values(STATE.apps).filter(a=>!a.aliasOf).indexOf(app))*86};
      ic.style.left=pos.x+'px'; ic.style.top=pos.y+'px';
      ic.innerHTML=`<span style="font-size:26px">${app.icon}</span><span style="font-size:10px;color:var(--ink);word-break:break-word">${app.label}</span>`;
      ic.ondblclick=()=>openApp(app.id);
      ic.onclick=e=>{ e.stopPropagation(); document.querySelectorAll('.w420-dicon.sel').forEach(x=>x.classList.remove('sel')); ic.classList.add('sel'); };
      ic.oncontextmenu=e=>{
        e.preventDefault(); e.stopPropagation(); closeAllMenus();
        const items=[{label:'Открыть',action:()=>openApp(app.id)}];
        if(app.state!=='hidden') items.push({label:'Закрыть окно',action:()=>closeWindow(app.id)});
        items.push({label:'Переименовать…',action:()=>notify('w420','id: '+app.id,'var(--wip)')});
        const m=buildMenu(items);
        document.body.appendChild(m); m.style.display='block';
        m.style.left=Math.min(e.clientX,innerWidth-230)+'px'; m.style.top=Math.min(e.clientY,innerHeight-180)+'px';
        STATE.menus['icon-'+app.id]=m; STATE.activeMenu=m;
      };
      // drag иконки по десктопу (позиция сохраняется)
      ic.onmousedown=e=>{
        if(e.button!==0||e.detail>1) return;
        e.preventDefault();
        const sx=e.clientX-ic.offsetLeft, sy=e.clientY-ic.offsetTop;
        const mv=ev=>{ ic.style.left=(ev.clientX-sx)+'px'; ic.style.top=(ev.clientY-sy)+'px'; };
        const up=ev=>{
          document.removeEventListener('mousemove',mv); document.removeEventListener('mouseup',up);
          STATE.iconPos[app.id]={x:ev.clientX-sx, y:ev.clientY-sy};
          try{ localStorage.setItem('w420-iconpos', JSON.stringify(STATE.iconPos)); }catch(err){}
        };
        document.addEventListener('mousemove',mv); document.addEventListener('mouseup',up);
      };
      // C3: drag&drop файлов на иконку приложения
      ic.ondragover=e=>{ e.preventDefault(); e.dataTransfer.dropEffect='copy'; ic.style.borderColor='var(--live)'; ic.style.background='var(--glow)'; };
      ic.ondragleave=()=>{ ic.style.borderColor='transparent'; ic.style.background='transparent'; };
      ic.ondrop=e=>{
        e.preventDefault(); e.stopPropagation();
        ic.style.borderColor='transparent'; ic.style.background='transparent';
        const files=[...e.dataTransfer.files].map(f=>f.name);
        if(!files.length) return;
        if(typeof app.onDropFiles==='function'){ app.onDropFiles(e.dataTransfer.files); }
        else{
          const inp=app.element.querySelector('input,textarea');
          if(inp){ inp.value=(inp.value?inp.value+' ':'')+files.join(' '); inp.focus(); }
        }
        notify(app.id,'файлы: '+files.join(', '),'var(--live)');
      };
      layer.appendChild(ic);
    });
    document.body.appendChild(layer);
  }

  // === ПКМ по пустому десктопу: контекстное меню рабочего стола ===
  document.addEventListener('contextmenu',e=>{
    if(e.target.closest('.w420-window,#w420-taskbar,.w420-tray-menu,#w420-tools-menu,.w420-dicon,#w420-launcher,.w420-panel')) return;
    e.preventDefault(); closeAllMenus();
    const m=buildMenu([
      {label:'📟 Открыть терминал',cmd:'term'},
      {label:'🤖 Открыть AI-чат',cmd:'ai'},
      {label:'🗂 Task view (Win+Tab)',action:()=>openTaskView()},
      {label:'Показать десктоп (Win+D)',action:()=>toggleShowDesktop()},
      {label:'Свернуть все окна (Win+M)',action:()=>minimizeAll()},
      {label:'Каскад окон',action:()=>cascadeWindows()},
      {label:'Плитка сеткой',action:()=>tileWindows('grid')},
      {label:'Рядами по горизонтали',action:()=>tileWindows('h')},
      {label:'Поиск приложений (Win+K)',action:()=>openLauncher()},
      {label:'Центр уведомлений',action:()=>toggleNotifPanel()},
      // C1/C2: обои и тема прямо из меню десктопа
      {label:'🖼 Обои ▸',action:()=>wallpaperMenu(e.clientX+10,e.clientY)},
      {label:'🎨 Тема ▸',action:()=>themeMenu(e.clientX+10,e.clientY)},
      {label:'🔄 Обновить иконки',action:()=>{ initDesktopIcons(); notify('w420','иконки обновлены','var(--live)'); }},
      {label:'ℹ Свойства десктопа',action:()=>notify('w420','столов: '+STATE.ws.length+', окон: '+STATE.activeApps.length+', тема: '+(document.documentElement.getAttribute('data-theme')||'matrix'),'var(--wip)')}
    ]);
    document.body.appendChild(m); m.style.display='block';
    m.style.left=Math.min(e.clientX,innerWidth-240)+'px'; m.style.top=Math.min(e.clientY,innerHeight-240)+'px';
    STATE.menus['desktop']=m; STATE.activeMenu=m;
  });

  // === A5. «Показать десктоп» (Win+D): сворачивает все окна, повтор — восстанавливает ===
  function toggleShowDesktop(){
    if(STATE.showDesktop){
      STATE.showDesktop=false;
      visibleApps().forEach(id=>{
        const app=STATE.apps[id]; if(!app) return;
        const w=STATE.win[id];
        if(w.minimized){ w.minimized=false; app.state='open';
          const wrap=app.element.parentElement; wrap.style.display='flex'; app.element.style.display='flex'; }
      });
      notify('w420','окна восстановлены','var(--live)');
    }else{
      STATE.showDesktop=true;
      visibleApps().slice().forEach(id=>minimizeWindow(id));
      notify('w420','показан рабочий стол','var(--wip)');
    }
    renderTaskbar();
  }

  // === A6. Свернуть все (Win+M) ===
  function minimizeAll(){
    STATE.showDesktop=false;
    visibleApps().slice().forEach(id=>minimizeWindow(id));
    notify('w420','все окна свёрнуты','var(--wip)');
  }

  // === A6. Каскад / плитка окон ===
  function _unhide(id){
    const app=STATE.apps[id]; const w=STATE.win[id]; const wrap=app.element.parentElement;
    if(w.minimized){ w.minimized=false; app.state='open'; wrap.style.display='flex'; app.element.style.display='flex'; }
    w.maximized=false; wrap.classList.remove('w420-max');
  }
  function cascadeWindows(){
    const ids=visibleApps(); if(!ids.length) return;
    ids.forEach((id,i)=>{
      _unhide(id);
      const w=STATE.win[id], wrap=STATE.apps[id].element.parentElement;
      w.x=90+i*32; w.y=64+i*32; w.w=Math.min(720,innerWidth-200); w.h=Math.min(520,innerHeight-180);
      wrap.style.left=w.x+'px'; wrap.style.top=w.y+'px'; wrap.style.width=w.w+'px'; wrap.style.height=w.h+'px';
    });
    renderTaskbar(); notify('w420','каскад: '+ids.length+' окн.','var(--live)');
  }
  function tileWindows(orient){
    const ids=visibleApps(); const n=ids.length; if(!n) return;
    const H=innerHeight-40;
    ids.forEach((id,i)=>{
      _unhide(id);
      const w=STATE.win[id], wrap=STATE.apps[id].element.parentElement;
      let g;
      if(orient==='h'){ g={x:0, y:Math.floor(H*i/n), w:innerWidth, h:Math.floor(H/n)}; }
      else { const cols=Math.ceil(Math.sqrt(n)), rows=Math.ceil(n/cols), c=i%cols, r=Math.floor(i/cols);
        g={x:Math.floor(innerWidth*c/cols), y:Math.floor(H*r/rows), w:Math.floor(innerWidth/cols), h:Math.floor(H/rows)}; }
      w.x=g.x; w.y=g.y; w.w=g.w; w.h=g.h;
      wrap.style.left=g.x+'px'; wrap.style.top=g.y+'px'; wrap.style.width=g.w+'px'; wrap.style.height=g.h+'px';
    });
    renderTaskbar(); notify('w420','плитка: '+n+' окн.','var(--live)');
  }

  // === A3. Центр уведомлений: колокольчик в трее + панель ===
  function updateBell(){
    const b=$('#w420-bell'); if(!b) return;
    const n=STATE.notifs.length;
    b.textContent = n>0 ? '🔔 '+n : '🔔';
    b.style.borderColor = n>0 ? '#ff4444' : 'var(--live)';
  }
  function toggleNotifPanel(){
    const old=$('#w420-notif-panel'); if(old){ old.remove(); STATE.notifPanelOpen=false; return; }
    closeAllMenus();
    const p=document.createElement('div'); p.id='w420-notif-panel'; p.className='w420-panel';
    const h=document.createElement('h3');
    h.innerHTML=`<span>УВЕДОМЛЕНИЯ</span><button class="a" style="padding:2px 8px;font-size:10px" id="w420-notif-clear">очистить</button>`;
    p.appendChild(h);
    const list=document.createElement('div');
    if(!STATE.notifs.length){ list.innerHTML='<div style="opacity:.5;padding:8px">Пока пусто</div>'; }
    STATE.notifs.slice().reverse().forEach(n=>{
      const d=new Date(n.ts);
      const it=document.createElement('div'); it.className='w420-notif-item';
      it.innerHTML=`<div class="t">${d.toLocaleTimeString('ru-RU')} · ${n.tag}</div><div>${n.msg}</div>`;
      if(n.app){ // D3: клик по уведомлению открывает соответствующее окно (deep-link)
        it.style.cursor='pointer'; it.title='Открыть: '+n.app;
        it.onclick=e=>{ e.stopPropagation(); closeNotifPanel(); openApp(n.app); };
      }
      list.appendChild(it);
    });
    p.appendChild(list);
    document.body.appendChild(p);
    STATE.notifPanelOpen=true;
    h.querySelector('#w420-notif-clear').onclick=e=>{ e.stopPropagation(); STATE.notifs=[]; updateBell(); toggleNotifPanel(); toggleNotifPanel(); };
  }
  function closeNotifPanel(){ const p=$('#w420-notif-panel'); if(p) p.remove(); STATE.notifPanelOpen=false; }

  // === D1. Инлайн-монитор системы в трее ===
  function sysmonText(){
    const m=STATE.metrics;
    if(!m) return 'CPU … · RAM …';
    const ram=(m.mem_used/1073741824).toFixed(1)+'/'+(m.mem_total/1073741824).toFixed(0)+'G';
    let net='—';
    try{ const c=navigator.connection; if(c&&c.downlink) net=c.downlink.toFixed(1)+'Mb/s'; }catch(e){}
    return `CPU ${Math.round(m.cpu)}% (${m.cores} ядер) · RAM ${ram} · NET ${net}`;
  }
  function startSysmon(){
    const tick=async()=>{
      try{
        if(NATIVE){ STATE.metrics=await inv('system_metrics'); }
        else{ // веб-режим: приблизительная оценка
          const m=await navigator.storage?.estimate?.()||{};
          STATE.metrics={cpu:0,cores:navigator.hardwareConcurrency||0,mem_used:m.usage||0,mem_total:m.quota||0,uptime:0,os:'web',host:'browser'};
        }
      }catch(e){}
      const el=$('#w420-sysmon'); if(el) el.textContent=sysmonText();
      setTimeout(tick,2000);
    };
    tick();
  }

  // === A2. Часы в трее + календарь по клику ===
  function startClock(){
    const tick=()=>{
      const c=$('#w420-clock'); if(!c) return;
      const d=new Date();
      c.textContent=d.toLocaleTimeString('ru-RU');
      c.title=d.toLocaleDateString('ru-RU',{weekday:'long', day:'numeric', month:'long', year:'numeric'});
    };
    tick(); setInterval(tick,1000);
  }
  let calCursor=null;
  function toggleCalendar(){
    const old=$('#w420-cal'); if(old){ old.remove(); return; }
    closeAllMenus();
    if(!calCursor){ const d=new Date(); calCursor=new Date(d.getFullYear(),d.getMonth(),1); }
    const p=document.createElement('div'); p.id='w420-cal'; p.className='w420-panel'; p.style.width='250px';
    const render=()=>{
      p.innerHTML='';
      const y=calCursor.getFullYear(), m=calCursor.getMonth();
      const h=document.createElement('h3');
      h.innerHTML=`<button class="a" id="cal-prev" style="padding:0 8px">‹</button><span>${calCursor.toLocaleDateString('ru-RU',{month:'long', year:'numeric'})}</span><button class="a" id="cal-next" style="padding:0 8px">›</button>`;
      p.appendChild(h);
      const grid=document.createElement('div'); grid.className='w420-cal-grid';
      ['пн','вт','ср','чт','пт','сб','вс'].forEach(d=>{ const c=document.createElement('div'); c.className='dow'; c.textContent=d; grid.appendChild(c); });
      const first=new Date(y,m,1); const startDow=(first.getDay()+6)%7; // пн=0
      const days=new Date(y,m+1,0).getDate();
      const today=new Date();
      for(let i=0;i<startDow;i++){ grid.appendChild(document.createElement('div')); }
      for(let d=1;d<=days;d++){
        const c=document.createElement('div'); c.className='day'+(d===today.getDate()&&m===today.getMonth()&&y===today.getFullYear()?' today':'');
        c.textContent=d;
        c.onclick=()=>{ notify('дата', `${d}.${m+1}.${y}`, 'var(--live)'); toggleCalendar(); };
        grid.appendChild(c);
      }
      p.appendChild(grid);
      h.querySelector('#cal-prev').onclick=()=>{ calCursor=new Date(y,m-1,1); render(); };
      h.querySelector('#cal-next').onclick=()=>{ calCursor=new Date(y,m+1,1); render(); };
    };
    render();
    document.body.appendChild(p);
  }
  function closeCalendar(){ const p=$('#w420-cal'); if(p) p.remove(); }

  // === A4. Глобальный поиск/launcher (Win+K / Ctrl+K) ===
  function openLauncher(){
    if(STATE.launcherOpen) return; STATE.launcherOpen=true; closeAllMenus();
    const ov=document.createElement('div'); ov.id='w420-launcher';
    ov.style.cssText='position:fixed;inset:0;z-index:950;background:rgba(0,0,0,.55);display:flex;justify-content:center;';
    const box=document.createElement('div');
    box.style.cssText='margin-top:12vh;width:min(560px,90vw);height:fit-content;background:color-mix(in srgb,var(--head) 97%,transparent);border:1px solid var(--live);border-radius:10px;box-shadow:0 0 30px var(--glow);padding:10px;backdrop-filter:blur(8px);';
    const inp=document.createElement('input');
    inp.placeholder='Поиск приложений и команд… (Esc — закрыть)';
    inp.style.cssText='width:100%;margin-bottom:8px;';
    const list=document.createElement('div'); list.style.cssText='max-height:50vh;overflow:auto;display:flex;flex-direction:column;gap:2px;';
    const items=[];
    Object.values(STATE.apps).forEach(a=>{ if(a.aliasOf) return; items.push({label:a.label, icon:a.icon, id:a.id, run:()=>openApp(a.id)}); });
    items.push({label:'Полный экран (Alt+Enter)', icon:'🖥️', run:()=>toggleFullscreen()});
    items.push({label:'Показать десктоп (Win+D)', icon:'🗔', run:()=>toggleShowDesktop()});
    items.push({label:'Свернуть все окна (Win+M)', icon:'🗕', run:()=>minimizeAll()});
    items.push({label:'Каскад окон', icon:'🪟', run:()=>cascadeWindows()});
    items.push({label:'Центр уведомлений', icon:'🔔', run:()=>toggleNotifPanel()});
    const renderList=q=>{
      list.innerHTML='';
      items.filter(i=>i.label.toLowerCase().includes(q.toLowerCase())||((i.id||'').toLowerCase().includes(q.toLowerCase()))).forEach(i=>{
        const b=document.createElement('button');
        b.style.cssText='display:flex;gap:8px;align-items:center;background:transparent;border:none;color:var(--ink);padding:6px 8px;cursor:pointer;font:inherit;text-align:left;border-radius:4px;';
        b.innerHTML=`<span>${i.icon||'▸'}</span><span>${i.label}</span>`;
        b.onmouseover=()=>{ b.style.background='var(--live)'; b.style.color='#000'; };
        b.onmouseout=()=>{ b.style.background='transparent'; b.style.color='var(--ink)'; };
        b.onclick=()=>{ closeLauncher(); i.run(); };
        list.appendChild(b);
      });
      if(!list.children.length) list.innerHTML='<div style="opacity:.5;padding:8px">Ничего не найдено</div>';
    };
    inp.oninput=()=>renderList(inp.value);
    inp.onkeydown=e=>{
      if(e.key==='Enter'){ const f=list.querySelector('button'); if(f) f.click(); }
      if(e.key==='Escape'){ closeLauncher(); }
      e.stopPropagation();
    };
    box.appendChild(inp); box.appendChild(list); ov.appendChild(box); document.body.appendChild(ov);
    renderList(''); setTimeout(()=>inp.focus(),50);
    ov.onmousedown=e=>{ if(e.target===ov) closeLauncher(); };
  }
  function closeLauncher(){ const l=$('#w420-launcher'); if(l) l.remove(); STATE.launcherOpen=false; }

  // ================= ФАЗА B: оконный менеджер уровня WM =================

  // === B4. Виртуальные рабочие столы (workspaces) ===
  function visibleApps(){ return STATE.activeApps.filter(id=>STATE.win[id]&&STATE.win[id].ws===STATE.wsIndex); }
  function switchWs(i){
    if(i<0||i>=STATE.ws.length) return;
    STATE.wsIndex=i;
    STATE.activeApps.forEach(id=>{
      const app=STATE.apps[id]; if(!app) return;
      const w=STATE.win[id], wrap=app.element.parentElement;
      if(w.ws!==i){ wrap.style.display='none'; }
      else if(!w.minimized){ wrap.style.display='flex'; app.element.style.display='flex'; app.state='open'; }
    });
    const vis=visibleApps();
    STATE.focused=vis.find(id=>!STATE.win[id].minimized)||vis[0]||null;
    renderTaskbar(); saveLayout();
    notify('w420','рабочий стол '+(i+1)+' / '+STATE.ws.length,'var(--live)');
  }
  function newWs(){ STATE.ws.push([]); switchWs(STATE.ws.length-1); }
  function closeWs(){
    if(STATE.ws.length<=1) return;
    const cur=STATE.wsIndex, ids=visibleApps();
    ids.forEach(id=>{ STATE.win[id].ws=Math.max(0,cur-1); });
    STATE.ws.splice(cur,1);
    switchWs(Math.min(cur, STATE.ws.length-1));
    notify('w420','рабочий стол закрыт, окна перенесены','var(--wip)');
  }
  function moveWindowToWs(id, wsIdx){
    const w=STATE.win[id]; if(!w||wsIdx>=STATE.ws.length) return;
    w.ws=wsIdx;
    if(wsIdx!==STATE.wsIndex){ const wrap=STATE.apps[id].element.parentElement; wrap.style.display='none'; }
    renderTaskbar(); saveLayout();
    notify('w420','окно → рабочий стол '+(wsIdx+1),'var(--live)');
  }

  // === B1. Snap: геометрия прилипания к краям ===
  function snapAt(x,y,ww,hh){
    const W=innerWidth, H=innerHeight-40, E=14;
    if(y<=E) return {x:0,y:0,w:W,h:H,max:true};
    const left=x<=E, right=x+ww>=W-E;
    if(left&&right) return {x:0,y:0,w:W,h:H};
    if(left)  return {x:0,y:0,w:Math.floor(W/2),h:H};
    if(right) return {x:Math.floor(W/2),y:0,w:Math.ceil(W/2),h:H};
    return null;
  }
  // Win+стрелки: снап фокусированного окна
  function snapFocused(dir){
    const id=STATE.focused; if(!id||!STATE.apps[id]) return;
    const w=STATE.win[id], wrap=STATE.apps[id].element.parentElement;
    const W=innerWidth, H=innerHeight-40; let g;
    if(dir==='left') g={x:0,y:0,w:Math.floor(W/2),h:H};
    else if(dir==='right') g={x:Math.floor(W/2),y:0,w:Math.ceil(W/2),h:H};
    else if(dir==='up') g={x:0,y:0,w:W,h:H,max:true};
    else g={x:0,y:Math.floor(H/2),w:W,h:Math.ceil(H/2)};
    if(w.minimized){ w.minimized=false; STATE.apps[id].state='open'; wrap.style.display='flex'; STATE.apps[id].element.style.display='flex'; }
    if(g.max){ w.prev=w.prev||{x:w.x,y:w.y,w:w.w,h:w.h}; w.maximized=true; wrap.classList.add('w420-max'); }
    else { w.maximized=false; wrap.classList.remove('w420-max'); w.x=g.x; w.y=g.y; w.w=g.w; w.h=g.h; wrap.style.left=g.x+'px'; wrap.style.top=g.y+'px'; wrap.style.width=g.w+'px'; wrap.style.height=g.h+'px'; }
    focusWindow(id); saveLayout();
  }

  // === B2. Превью окна при наведении на кнопку taskbar ===
  let previewEl=null;
  function showPreview(id, anchorBtn){
    hidePreview();
    const app=STATE.apps[id]; if(!app) return;
    const wrap=app.element.parentElement;
    if(!wrap||wrap.style.display==='none') return;
    previewEl=document.createElement('div'); previewEl.id='w420-preview'; previewEl.className='w420-panel';
    previewEl.style.cssText+=';width:auto;max-width:360px;padding:6px;';
    const r=anchorBtn.getBoundingClientRect();
    previewEl.style.left=Math.max(8,Math.min(innerWidth-370, r.left+r.width/2-170))+'px'; previewEl.style.right='auto';
    const title=document.createElement('div');
    title.style.cssText='font-size:10px;color:var(--live);margin-bottom:4px;font-family:var(--fh);letter-spacing:1px;';
    title.textContent=app.icon+' '+app.label; previewEl.appendChild(title);
    const holder=document.createElement('div'); holder.style.cssText='overflow:hidden;border:1px solid var(--line);border-radius:4px;';
    const ow=Math.max(1,wrap.offsetWidth), oh=Math.max(1,wrap.offsetHeight);
    const scale=Math.min(320/ow, 200/oh, 0.45);
    const clone=wrap.cloneNode(true);
    clone.style.cssText='position:static;transform:scale('+scale+');transform-origin:top left;width:'+ow+'px;height:'+oh+'px;display:flex;pointer-events:none;box-shadow:none;border:none;';
    holder.style.width=(ow*scale)+'px'; holder.style.height=Math.min(200,oh*scale)+'px';
    holder.appendChild(clone); previewEl.appendChild(holder);
    document.body.appendChild(previewEl);
  }
  function hidePreview(){ if(previewEl){ previewEl.remove(); previewEl=null; } }

  // === B3. Task view (Win+Tab): все окна плиткой ===
  function openTaskView(){
    if(STATE.taskViewOpen){ closeTaskView(); return; }
    STATE.taskViewOpen=true; closeAllMenus(); hidePreview();
    const ov=document.createElement('div'); ov.id='w420-taskview';
    ov.style.cssText='position:fixed;inset:0 0 40px 0;z-index:960;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(6px);padding:24px;overflow:auto;';
    const grid=document.createElement('div'); grid.style.cssText='display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px;';
    if(!visibleApps().length){ grid.innerHTML='<div style="opacity:.6">Нет открытых окон — откройте из TOOLS или двойным кликом по иконке десктопа</div>'; }
    // B4: полоса рабочих столов сверху task view
    const wsStrip=document.createElement('div');
    wsStrip.style.cssText='display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;';
    STATE.ws.forEach((_,i)=>{
      const cnt=STATE.activeApps.filter(id=>STATE.win[id]&&STATE.win[id].ws===i&&!STATE.win[id].minimized).length;
      const b=document.createElement('button');
      b.className='a'; b.style.cssText='padding:6px 12px;'+(i===STATE.wsIndex?'border-width:2px;box-shadow:0 0 10px var(--glow);':'');
      b.textContent='🖥 '+(i+1)+' ('+cnt+')';
      b.onclick=()=>{ switchWs(i); closeTaskView(); };
      wsStrip.appendChild(b);
    });
    const nb=document.createElement('button'); nb.className='a'; nb.textContent='+ новый стол (Win+Ctrl+D)';
    nb.onclick=()=>{ newWs(); closeTaskView(); };
    wsStrip.appendChild(nb);
    ov.appendChild(wsStrip);
    visibleApps().forEach(id=>{
      const app=STATE.apps[id]; if(!app) return;
      const wrap=app.element.parentElement;
      const card=document.createElement('div');
      card.style.cssText='border:1px solid '+(STATE.focused===id?'var(--live)':'var(--line)')+';border-radius:8px;background:var(--panel);padding:8px;cursor:pointer;box-shadow:0 0 12px var(--glow);';
      const t=document.createElement('div');
      t.style.cssText='font-size:11px;color:var(--live);margin-bottom:6px;font-family:var(--fh);letter-spacing:1px;';
      t.textContent=app.icon+' '+app.label+(STATE.win[id].minimized?' (свёрнуто)':''); card.appendChild(t);
      const holder=document.createElement('div'); holder.style.cssText='overflow:hidden;border:1px solid var(--line);border-radius:4px;';
      const ow=Math.max(1,wrap.offsetWidth), oh=Math.max(1,wrap.offsetHeight);
      const scale=Math.min(244/ow, 150/oh, 0.4);
      const clone=wrap.cloneNode(true);
      clone.style.cssText='position:static;transform:scale('+scale+');transform-origin:top left;width:'+ow+'px;height:'+oh+'px;display:flex;pointer-events:none;box-shadow:none;border:none;';
      holder.style.width=(ow*scale)+'px'; holder.style.height=Math.min(150,oh*scale)+'px';
      holder.appendChild(clone); card.appendChild(holder);
      card.onclick=()=>{ closeTaskView(); const w=STATE.win[id]; if(w.minimized) openWindow(id); else focusWindow(id); };
      grid.appendChild(card);
    });
    ov.appendChild(grid); document.body.appendChild(ov);
    ov.onclick=e=>{ if(e.target===ov) closeTaskView(); };
  }
  function closeTaskView(){ const t=$('#w420-taskview'); if(t) t.remove(); STATE.taskViewOpen=false; }

  // === B3. Alt+Tab: переключатель открытых окон ===
  let altList=[], altSel=-1;
  function showAltSwitcher(){
    let sw=$('#w420-altsw');
    if(!sw){ sw=document.createElement('div'); sw.id='w420-altsw'; sw.style.cssText='position:fixed;left:50%;top:40%;transform:translate(-50%,-50%);z-index:970;display:flex;gap:10px;background:color-mix(in srgb,var(--head) 95%,transparent);border:1px solid var(--live);border-radius:10px;padding:12px;box-shadow:0 0 24px var(--glow);backdrop-filter:blur(6px);'; document.body.appendChild(sw); }
    sw.innerHTML='';
    altList.forEach((id,i)=>{
      const a=STATE.apps[id]; if(!a) return;
      const b=document.createElement('div');
      b.style.cssText='width:84px;padding:8px 4px;text-align:center;border-radius:6px;border:1px solid '+(i===altSel?'var(--live)':'transparent')+';background:'+(i===altSel?'color-mix(in srgb,var(--live) 15%,transparent)':'transparent')+';';
      b.innerHTML='<div style="font-size:24px">'+a.icon+'</div><div style="font-size:9px;color:var(--ink)">'+a.label+'</div>';
      sw.appendChild(b);
    });
  }
  function closeAltSwitcher(){ const s=$('#w420-altsw'); if(s) s.remove(); STATE.altTabOpen=false; altSel=-1; altList=[]; }
  document.addEventListener('keydown',e=>{
    if(e.altKey && e.key==='Tab'){
      e.preventDefault();
      if(!STATE.altTabOpen){ altList=visibleApps().slice(); if(!altList.length) return; altSel=1%altList.length; STATE.altTabOpen=true; }
      else altSel=(altSel+1)%altList.length;
      showAltSwitcher();
    }
  });
  document.addEventListener('keyup',e=>{
    if(e.key==='Alt' && STATE.altTabOpen){
      const id=altList[altSel]; closeAltSwitcher();
      if(id){ const w=STATE.win[id]; if(w&&w.minimized) openWindow(id); else focusWindow(id); }
    }
  });

  // === B6. Shade: свернуть окно в заголовок ===
  function shadeWindow(id){
    const app=STATE.apps[id]; if(!app) return;
    const w=STATE.win[id], wrap=app.element.parentElement;
    if(w.shaded){ w.shaded=false; app.element.style.display='flex'; wrap.style.height=(typeof w.h==='number'?w.h+'px':(w.h||'auto')); }
    else { w.shaded=true; if(typeof w.h!=='number') w.h=wrap.offsetHeight; app.element.style.display='none'; wrap.style.height='28px'; }
    saveLayout();
  }

  // === Контекстное меню окна: общие команды + basicMenu приложения ===
  function openWindowMenu(id,x,y){
    const app=STATE.apps[id]; if(!app) return; closeAllMenus(); hidePreview();
    const w=STATE.win[id];
    const cmds=[
      {label: w.minimized?'Развернуть':'Свернуть', action:()=>{ w.minimized?openWindow(id):minimizeWindow(id); }},
      {label: w.maximized?'Восстановить размер':'Развернуть на весь десктоп', action:()=>maximizeWindow(id)},
      {label: w.shaded?'Развернуть тело окна':'Свернуть в заголовок (shade)', action:()=>shadeWindow(id)},
      {label:'Во весь экран приложения (Alt+Enter)', action:()=>toggleFullscreen()}
    ];
    // B4: перенос окна на другой рабочий стол
    if(STATE.ws.length>1||true){
      cmds.push({label:'→ на рабочий стол 1', action:()=>moveWindowToWs(id,0)});
      for(let i=1;i<STATE.ws.length;i++) cmds.push({label:'→ на рабочий стол '+(i+1), action:()=>moveWindowToWs(id,i)});
      cmds.push({label:'→ новый рабочий стол', action:()=>{ newWs(); moveWindowToWs(id, STATE.wsIndex); }});
    }
    if(w.menuCmds) cmds.push(...w.menuCmds);
    cmds.push({label:'Закрыть', action:()=>closeWindow(id)});
    const m=buildMenu(cmds);
    document.body.appendChild(m); m.style.display='block';
    m.style.left=Math.min(x,innerWidth-240)+'px'; m.style.top=Math.min(y,innerHeight-260)+'px';
    STATE.menus['win-'+id]=m; STATE.activeMenu=m;
  }

  // === B5. Персистентность раскладки окон (localStorage, debounce) ===
  let saveTimer=null;
  function saveLayout(){
    clearTimeout(saveTimer);
    saveTimer=setTimeout(()=>{
      const L={win:{}, order:STATE.activeApps.slice(), ws:STATE.ws.map(()=>0), wsIndex:STATE.wsIndex, wsCount:STATE.ws.length};
      Object.entries(STATE.win).forEach(([id,w])=>{ L.win[id]={x:w.x,y:w.y,w:w.w,h:w.h,minimized:!!w.minimized,maximized:!!w.maximized,shaded:!!w.shaded,ws:w.ws??0}; });
      try{ localStorage.setItem('w420-layout', JSON.stringify(L)); }catch(e){}
    },400);
  }
  function loadLayout(){ try{ return JSON.parse(localStorage.getItem('w420-layout')||'null'); }catch(e){ return null; } }

   // === Потеря фокуса окна на 5 секунд — закрыть все меню (трей, контекстные, tools) ===
  let blurTimer=null;
  window.addEventListener('blur',()=>{
    clearTimeout(blurTimer);
    blurTimer=setTimeout(()=>{ closeAllMenus(); },5000);
  });
  window.addEventListener('focus',()=>{ clearTimeout(blurTimer); blurTimer=null; });
  document.addEventListener('visibilitychange',()=>{ if(document.hidden){ clearTimeout(blurTimer); blurTimer=setTimeout(()=>closeAllMenus(),5000); } });

  // === Экспорт API ===
  window.Desktop={
    register, openWindow, closeWindow, minimizeWindow, maximizeWindow, startResize, focusWindow, toggleFullscreen, restoreWindow,
    openApp, renderTaskbar, notify, apps:()=>STATE.apps, win:()=>STATE.win, state:()=>STATE,
    initDesktopIcons, toggleShowDesktop, minimizeAll, cascadeWindows, tileWindows,
    openLauncher, closeLauncher, toggleNotifPanel, toggleCalendar, startClock,
    snapAt, snapFocused, showPreview, hidePreview, openTaskView, closeTaskView, shadeWindow, openWindowMenu, saveLayout, loadLayout,
    visibleApps, switchWs, newWs, closeWs, moveWindowToWs,
    WALLPAPERS, applyWallpaper, wallpaperMenu, themeMenu,
    startSysmon, sysmonText
  };

  // === Инициализация (регистрация 10 базовых приложений) ===
  document.addEventListener('DOMContentLoaded',()=>{
    document.addEventListener('click',e=>{ if(e.target.closest('[id="w420-tools-menu"]') || e.target.closest('[id="w420-taskbar"]')) return; closeAllMenus(); if(!e.target.closest('.w420-panel')){ closeNotifPanel(); closeCalendar(); } });
    renderTaskbar();
    startClock();
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
    initDesktopIcons(); // после регистрации всех приложений
    { const L=loadLayout(); if(L&&L.wsCount>1){ STATE.ws=Array.from({length:L.wsCount},()=>[]); STATE.wsIndex=Math.min(L.wsIndex||0,L.wsCount-1); renderTaskbar(); } }
    applyWallpaper(); // C1: обои при старте (свой выбор или дефолт темы)
    startSysmon(); // D1: инлайн-монитор в трее
    setTimeout(()=>{ window.Desktop.openWindow('term'); }, 300);
  });

  // === Fallbacks для tray-меню ===
  window.goAI=function(s){ notify('AI','goAI('+s+')'); };
  window.stopTask=function(why){ notify('AI','stopTask('+why+')'); };
  window.lockKeys=function(){ notify('AI','keys locked'); };
  window.inv=function(c,a){ return Promise.resolve(); };
})();

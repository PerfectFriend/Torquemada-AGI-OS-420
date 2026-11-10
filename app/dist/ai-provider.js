/* W420 AI CORE (native shell): gives the page a real language model when it runs outside the Claude artifact runtime.
   Providers: Ollama (local, no key) or Anthropic API (key kept in memory; optionally stored encrypted with a password).
   Implements the same sample(prompt, {tools, onText}) contract the page already uses, including the tool-use loop. */
(function () {
  var enc = new TextEncoder(), dec = new TextDecoder();
  var stripThink = function (t) { return String(t || '').replace(/<think>[\s\S]*?<\/think>/g, '').trim(); };
  var schema = function (t) { return t.inputSchema || { type: 'object', properties: {} }; };
  var toAnthropicTools = function (ts) { return (ts || []).map(function (t) { return { name: t.name, description: t.description || '', input_schema: schema(t) }; }); };
  var toOllamaTools = function (ts) { return (ts || []).map(function (t) { return { type: 'function', function: { name: t.name, description: t.description || '', parameters: schema(t) } }; }); };

  function guard(budget) {
    if (budget.calls >= budget.cap) throw new Error('Лимит запросов к ИИ за сессию исчерпан (' + budget.cap + '). Поднимите его во вкладке AI CORE.');
    budget.calls++;
  }
  async function post(http, url, init, who) {
    var r;
    try { r = await http(url, init); }
    catch (e) { throw new Error(who + ': нет соединения (' + (e && e.message || e) + ')'); }
    var j = {}; try { j = await r.json(); } catch (e) {}
    if (!r.ok) throw new Error(who + ': ' + ((j.error && (j.error.message || j.error)) || r.status));
    return j;
  }
  function anthropicAdapter(cfg, http, budget) {
    return {
      init: function (prompt, tools) { return { msgs: [{ role: 'user', content: prompt }], tools: toAnthropicTools(tools) }; },
      step: async function (st) {
        guard(budget);
        var body = { model: cfg.amodel, max_tokens: 1024, messages: st.msgs }; if (st.tools.length) body.tools = st.tools;
        var j = await post(http, 'https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': cfg.key, 'anthropic-version': '2023-06-01', 'anthropic-dangerous-direct-browser-access': 'true' }, body: JSON.stringify(body) }, 'Anthropic');
        if (j.usage) budget.tokens += (j.usage.input_tokens || 0) + (j.usage.output_tokens || 0);
        st.msgs.push({ role: 'assistant', content: j.content });
        return {
          text: j.content.filter(function (b) { return b.type === 'text'; }).map(function (b) { return b.text; }).join(''),
          calls: j.content.filter(function (b) { return b.type === 'tool_use'; }).map(function (b) { return { id: b.id, name: b.name, input: b.input }; })
        };
      },
      addResults: function (st, res) { st.msgs.push({ role: 'user', content: res.map(function (x) { return { type: 'tool_result', tool_use_id: x.id, content: x.output }; }) }); }
    };
  }
  function ollamaAdapter(cfg, http, budget) {
    return {
      init: function (prompt, tools) { return { msgs: [{ role: 'user', content: prompt }], tools: toOllamaTools(tools) }; },
      step: async function (st) {
        guard(budget);
        var body = { model: cfg.model, messages: st.msgs, stream: false }; if (st.tools.length) body.tools = st.tools;
        var j = await post(http, cfg.url.replace(/\/$/, '') + '/api/chat', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }, 'Ollama (' + cfg.url + ', запущен ли ollama serve?)');
        budget.tokens += (j.prompt_eval_count || 0) + (j.eval_count || 0);
        var m = j.message || { role: 'assistant', content: '' }; st.msgs.push(m);
        return { text: stripThink(m.content), calls: (m.tool_calls || []).map(function (c, i) { return { id: String(i), name: c.function.name, input: c.function.arguments || {} }; }) };
      },
      addResults: function (st, res) { res.forEach(function (x) { st.msgs.push({ role: 'tool', tool_name: x.name, content: x.output }); }); }
    };
  }
  function makeSampler(getCfg, http, budget) {
    return async function sample(prompt, opts) {
      opts = opts || {}; var cfg = getCfg(), tools = opts.tools || [];
      var ad = isDbProvider(cfg.provider) ? dbAdapter(cfg, budget) : (cfg.provider === 'anthropic' ? anthropicAdapter(cfg, http, budget) : ollamaAdapter(cfg, http, budget));
      var st = ad.init(prompt, tools), text = '';
      for (var i = 0; i < 6; i++) {
        var out = await ad.step(st); text = out.text;
        if (!out.calls.length) break;
        var res = [];
        for (var k = 0; k < out.calls.length; k++) {
          var c = out.calls[k], tool = tools.find(function (t) { return t.name === c.name; }), output;
          try { output = tool ? JSON.stringify(await tool.execute(c.input || {})) : 'unknown tool'; } catch (e) { output = 'error: ' + (e && e.message || e); }
          res.push({ id: c.id, name: c.name, output: String(output).slice(0, 6000) });
        }
        ad.addResults(st, res);
        if (i === 5 && !text) text = '(достигнут лимит шагов инструментов)';
      }
      if (opts.onText) opts.onText({ text: text });
      return { text: text };
    };
  }
  var b64 = function (u) { return btoa(String.fromCharCode.apply(null, Array.from(u))); };
  var unb64 = function (s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); };
  async function kdf(pw, salt, subtle) {
    var m = await subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: 200000, hash: 'SHA-256' }, m, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function encryptSecret(secret, pw, c) {
    var salt = c.getRandomValues(new Uint8Array(16)), iv = c.getRandomValues(new Uint8Array(12));
    var ct = await c.subtle.encrypt({ name: 'AES-GCM', iv: iv }, await kdf(pw, salt, c.subtle), enc.encode(secret));
    return { salt: b64(salt), iv: b64(iv), ct: b64(new Uint8Array(ct)) };
  }
  async function decryptSecret(o, pw, c) {
    return dec.decode(await c.subtle.decrypt({ name: 'AES-GCM', iv: unb64(o.iv) }, await kdf(pw, unb64(o.salt), c.subtle), unb64(o.ct)));
  }
  var Pure = { stripThink: stripThink, toAnthropicTools: toAnthropicTools, toOllamaTools: toOllamaTools, makeSampler: makeSampler, encryptSecret: encryptSecret, decryptSecret: decryptSecret };
  if (typeof window !== 'undefined') window.W420Crypto = { encryptSecret: encryptSecret, decryptSecret: decryptSecret };
  if (typeof module !== 'undefined' && module.exports) { module.exports = Pure; return; }
  if (!(window.__TAURI__)) return;

  /* ---------- native shell: settings + provider binding ---------- */
  var Q = function (s) { return document.querySelector(s); };
  var inv = function (c, a) { return window.__TAURI__.core.invoke(c, a || {}); };
  // Провайдеры из настоящей БД (~/.w420/ai_providers.db): NVIDIA NIM + ключи с ротацией.
  // Ключи не приходят в браузер — чат идёт через бэкенд-команду ai_chat.
  window.W420_DB_PROVIDERS = [];
  var LAST_OUTCOME = null;
  function isDbProvider(id) { return (window.W420_DB_PROVIDERS || []).some(function (p) { return p.id === id; }); }
  function dbAdapter(cfg, budget) {
    return {
      init: function (prompt) { return { msgs: [{ role: 'user', content: prompt }] }; },
      step: async function (st) {
        guard(budget);
        var r = await inv('ai_chat', { prompt: st.msgs.map(function (m) { return m.role + ': ' + m.content; }).join('\n'), model: cfg.model || null, provider_id: cfg.provider });
        LAST_OUTCOME = r; budget.tokens += r.tokens_used || 0;
        return { text: r.text, calls: [] };
      },
      addResults: function () {}
    };
  }
  var LS = { get: function (k, d) { try { var v = localStorage.getItem(k); return v == null ? d : v; } catch (e) { return d; } }, set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) {} }, del: function (k) { try { localStorage.removeItem(k); } catch (e) {} } };
  var saved = {}; try { saved = JSON.parse(LS.get('w420.ai', '{}')); } catch (e) {}
  var CFG = Object.assign({ provider: 'ollama', url: 'http://127.0.0.1:11434', model: 'qwen2.5:7b', amodel: 'claude-sonnet-5-5', key: '', enabled: false }, saved, { key: '' });
  var budget = { calls: 0, tokens: 0, cap: parseInt(LS.get('w420.ai.cap', '150'), 10) || 150 };
  var http = function (url, init) {
    var f = (window.__TAURI__.http && window.__TAURI__.http.fetch) || window.fetch.bind(window);
    if (window.W420Proxy && /^https:/.test(url) && window.__TAURI__.http) init = Object.assign({}, init, { proxy: { all: window.W420Proxy } });  // cloud requests through the bridge, if the user chose so
    return f(url, init);
  };
  var CURRENT = null, inner = makeSampler(function () { return CFG; }, http, budget);
  var sampler = async function (p, o) { try { return await inner(p, o); } finally { usage(); } };
  var aud = function (a, d) { try { if (typeof audit === 'function') audit('ai', a + (d ? ': ' + d : '')); } catch (e) {} };
  var note = function (t) { var e = Q('#aicstat'); if (e) e.textContent = t; };
  function usage() { var e = Q('#aicuse'); if (e) e.textContent = 'запросов: ' + budget.calls + ' / ' + budget.cap + ' · токенов: ~' + budget.tokens; }
  function persist() { LS.set('w420.ai', JSON.stringify({ provider: CFG.provider, url: CFG.url, model: CFG.model, amodel: CFG.amodel, enabled: CFG.enabled })); }
  window.claude = window.claude || { use: async function (n) { return n === 'sample' ? CURRENT : null; } };
  function apply() {
    var ready = CFG.enabled && (isDbProvider(CFG.provider) || CFG.provider === 'ollama' || !!CFG.key);
    CURRENT = ready ? sampler : null;
    var b = Q('#aicbadge'); if (b) { var pn = (window.W420_DB_PROVIDERS || []).find(function (p) { return p.id === CFG.provider; }); b.textContent = ready ? 'LIVE · ' + (pn ? pn.name : CFG.provider).toUpperCase() : 'OFF'; b.className = 'b ' + (ready ? 'live' : 'wip'); }
    if (typeof bindAI === 'function') bindAI();
  }
  async function connect() {
    CFG.provider = Q('#aicprov').value; CFG.url = Q('#aicurl').value.trim() || CFG.url; CFG.model = Q('#aicmodel').value.trim() || CFG.model; CFG.amodel = Q('#aicamodel').value.trim() || CFG.amodel;
    var dbp = (window.W420_DB_PROVIDERS || []).find(function (p) { return p.id === CFG.provider; });
    if (dbp && !CFG.model && dbp.models && dbp.models[0]) { CFG.model = dbp.models[0]; Q('#aicmodel').value = CFG.model; }
    budget.cap = Math.max(1, parseInt(Q('#aiccap').value, 10) || 150); LS.set('w420.ai.cap', String(budget.cap));
    if (!CFG.provider) { note('Нет провайдера: база ai_providers.db пуста.'); return; }
    if (CFG.provider === 'anthropic' && !CFG.key) { note('Сначала введите ключ API (кнопки ниже).'); return; }
    CFG.enabled = true; persist(); note('Проверяю связь…');
    try { var r = await sampler('Ответь одним словом: ок', {}); note('Связь есть: «' + String(r.text).slice(0, 60) + '»' + (LAST_OUTCOME ? ' · ключ ' + LAST_OUTCOME.key_mask + ' · попыток ключей: ' + LAST_OUTCOME.keys_tried + ' · ' + LAST_OUTCOME.latency_ms + ' мс · ' + LAST_OUTCOME.model : '')); aud('provider enabled', CFG.provider + ' ' + (dbp ? dbp.name : CFG.model)); }
    catch (e) { CFG.enabled = false; persist(); note(e.message); }
    apply();
  }
  function disconnect() { CFG.enabled = false; persist(); note('ИИ отключён: приложение работает на заглушках [SIM].'); apply(); }
  async function listModels() {
    try { var r = await http(Q('#aicurl').value.trim().replace(/\/$/, '') + '/api/tags'), j = await r.json(), dl = Q('#aicmodels'); dl.innerHTML = '';
      (j.models || []).forEach(function (m) { var o = document.createElement('option'); o.value = m.name; dl.appendChild(o); }); note('Моделей в Ollama: ' + (j.models || []).length); }
    catch (e) { note('Ollama недоступна: ' + (e && e.message || e)); }
  }
  var hasSaved = function () { return !!LS.get('w420.ai.key', ''); };
  function keyInfo() { var e = Q('#aickinfo'); if (e) e.textContent = CFG.key ? 'ключ в памяти (до закрытия приложения)' + (hasSaved() ? ' · зашифрованная копия сохранена' : '') : (hasSaved() ? 'сохранённый ключ зашифрован: введите пароль и нажмите «РАЗБЛОКИРОВАТЬ»' : 'ключа нет'); }
  async function keyAct(kind) {
    var key = Q('#aickey').value.trim(), pw = Q('#aicpw').value;
    try {
      if (kind === 'session') { if (!key) return note('Введите ключ.'); CFG.key = key; }
      else if (kind === 'save') { if (!key || !pw) return note('Нужны ключ и пароль.'); LS.set('w420.ai.key', JSON.stringify(await encryptSecret(key, pw, window.crypto))); CFG.key = key; }
      else if (kind === 'unlock') { if (!pw || !hasSaved()) return note('Нужен пароль и сохранённый ключ.'); CFG.key = await decryptSecret(JSON.parse(LS.get('w420.ai.key', '{}')), pw, window.crypto); }
      else if (kind === 'forget') { LS.del('w420.ai.key'); CFG.key = ''; }
    } catch (e) { return note(kind === 'unlock' ? 'Неверный пароль.' : 'Ошибка: ' + (e && e.message || e)); }
    Q('#aickey').value = ''; Q('#aicpw').value = ''; keyInfo(); note(kind === 'forget' ? 'Ключ удалён.' : 'Ключ принят. Нажмите «ПОДКЛЮЧИТЬ».');
  }
  function build() {
    if (Q('#v-aicore') || !Q('#v-radio') || !Q('nav')) return;
    var sec = document.createElement('section'); sec.className = 'view live'; sec.id = 'v-aicore';
    sec.innerHTML =
      '<h2>AI CORE <span class="b wip" id="aicbadge">OFF</span></h2>' +
      '<div class="mono" style="opacity:.8">Откуда берётся ум ассистента, радио, автономных задач и выпуска дня. Пока ИИ отключён, всё работает на красных заглушках [SIM].</div>' +
      '<div class="card"><div class="k">ПРОВАЙДЕР</div><div class="row"><select id="aicprov" style="width:auto"><option value="">— загрузка из базы…</option></select></div>' +
      '<div class="mono" style="margin-top:6px" id="aicwarn"></div></div>' +
      '<div class="card" id="aicbox-db" style="display:none"><div class="k">КЛЮЧИ · РОТАЦИЯ (бэкенд, ключи зашифрованы AES-256-GCM)</div>' +
      '<div class="mono" id="aicdbstat"></div><div id="aickeys" class="mono" style="max-height:170px;overflow:auto"></div>' +
      '<div class="row" style="margin-top:6px"><button class="a" id="aictest">ПРОТЕСТИРОВАТЬ КЛЮЧИ</button><button class="a" id="aicrefresh">ОБНОВИТЬ</button></div></div>' +
      '<div class="card" id="aicbox-mgmt"><div class="k">УПРАВЛЕНИЕ ПРОВАЙДЕРАМИ · ПОЛНЫЙ ЦИКЛ НАСТРОЙКИ</div>' +
      '<div class="row"><input id="mgName" placeholder="имя провайдера (напр. «NVIDIA NIM»)">' +
      '<select id="mgType" style="width:auto"><option>OpenAI</option><option>Anthropic</option><option>Google</option><option>Mistral AI</option><option>Groq</option><option>Together AI</option><option>OpenRouter</option><option>Ollama (локально)</option><option selected>NVIDIA NIM</option><option>Кастомный провайдер</option></select>' +
      '<input id="mgEndpoint" placeholder="эндпоинт (пусто = по умолчанию типа)">' +
      '<button class="a" id="mgAdd">ДОБАВИТЬ ПРОВАЙДЕРА</button></div>' +
      '<div class="row" style="margin-top:6px"><input id="mgKey" type="password" placeholder="API ключ (хранится AES-256-GCM, в браузер не уходит)"><input id="mgNick" placeholder="название ключа (необяз.)"><button class="a" id="mgAddKey">ДОБАВИТЬ КЛЮЧ</button></div>' +
      '<div class="row" style="margin-top:6px"><button class="a" id="mgTest">ТЕСТ ПРОВАЙДЕРА</button><button class="a" id="mgModels">СПИСОК МОДЕЛЕЙ</button><button class="a" id="mgTestSel">ТЕСТ ВЫБРАННЫХ МОДЕЛЕЙ</button><button class="a" id="mgSaveModels">СОХРАНИТЬ ВЫБОР</button></div>' +
      '<div class="mono" id="mgProvTest" style="margin-top:6px;white-space:pre-wrap"></div>' +
      '<div id="mgModelList" class="mono" style="max-height:150px;overflow:auto;margin-top:6px"></div>' +
      '<div class="row" style="margin-top:6px"><button class="a" id="mgSelAll">ОТМЕТИТЬ ВСЕ</button><span class="mono">статистика моделей, сортировка:</span><select id="mgSort" style="width:auto"><option value="name">по имени</option><option value="latency">по задержке отклика</option><option value="speed">по скорости генерации</option></select><button class="a" id="mgStats">ПОКАЗАТЬ РЕЗУЛЬТАТЫ</button></div>' +
      '<div id="mgModelResults" class="mono" style="max-height:180px;overflow:auto;margin-top:6px"></div>' +
      '<div class="row" style="margin-top:6px"><button class="a" id="mgToggle">ВКЛ/ВЫКЛ ПРОВАЙДЕРА</button><button class="a" id="mgDefault">СДЕЛАТЬ ПО УМОЛЧАНИЮ</button><button class="a" id="mgDel">УДАЛИТЬ ПРОВАЙДЕРА</button><button class="a" id="mgTestAll">ТЕСТ ВСЕХ КОНФИГУРАЦИЙ</button></div>' +
      '<div class="mono" id="mgLog" style="margin-top:6px;white-space:pre-wrap"></div></div>' +
      '<div class="card" id="aicbox-o"><div class="k">OLLAMA</div><div class="row"><input id="aicurl"><button class="a" id="aiclist">СПИСОК МОДЕЛЕЙ</button></div>' +
      '<div class="row" style="margin-top:6px"><input id="aicmodel" list="aicmodels" placeholder="модель"><datalist id="aicmodels"></datalist></div>' +
      '<div class="mono" style="opacity:.8">Нужна модель с поддержкой инструментов (tools), например qwen2.5, qwen3 или llama3.1. Установка: ollama pull qwen2.5:7b</div></div>' +
      '<div class="card" id="aicbox-a"><div class="k">ANTHROPIC API</div><div class="row"><input id="aicamodel" placeholder="модель"></div>' +
      '<div class="row" style="margin-top:6px"><input id="aickey" type="password" placeholder="ключ API (sk-ant-…)"><input id="aicpw" type="password" placeholder="пароль для ключа"></div>' +
      '<div class="row" style="margin-top:6px"><button class="a" id="aicsess">НА СЕССИЮ</button><button class="a" id="aicsave">СОХРАНИТЬ ЗАШИФРОВАННО</button><button class="a" id="aicunlock">РАЗБЛОКИРОВАТЬ</button><button class="a" id="aicforget">УДАЛИТЬ</button></div>' +
      '<div class="mono" id="aickinfo"></div><div class="mono" style="opacity:.8">Зашифрованный ключ хранится в этом приложении (AES-256-GCM, ключ из пароля). Расшифрованный ключ живёт только в памяти.</div></div>' +
      '<div class="card"><div class="row"><span class="mono">лимит запросов за сессию</span><input id="aiccap" type="number" min="1" style="max-width:90px"><button class="a" id="aicgo">ПОДКЛЮЧИТЬ</button><button class="a" id="aicoff">ОТКЛЮЧИТЬ</button></div>' +
      '<div class="mono" id="aicuse"></div><div class="mono" id="aicstat">—</div></div>';
    Q('#v-radio').parentNode.appendChild(sec);
    var btn = document.createElement('button'); btn.className = 'live'; btn.textContent = 'AI CORE'; btn.dataset.id = 'aicore'; btn.onclick = function () { show('aicore'); }; Q('nav').appendChild(btn);
    Q('#aicurl').value = CFG.url; Q('#aicmodel').value = CFG.model; Q('#aicamodel').value = CFG.amodel; Q('#aiccap').value = budget.cap;
    var sw = function () {
      var v = Q('#aicprov').value, a = v === 'anthropic', dbp = isDbProvider(v);
      Q('#aicbox-a').style.display = a ? '' : 'none';
      Q('#aicbox-o').style.display = (!a && !dbp) ? '' : 'none';
      Q('#aicbox-db').style.display = dbp ? '' : 'none';
      Q('#aicwarn').textContent = dbp
        ? 'Провайдер из базы ~/.w420/ai_providers.db. Ключи хранятся зашифрованно (AES-256-GCM) и не попадают в браузер: запросы идут с бэкенда через ротацию всех активных ключей.'
        : (a ? 'Запросы, включая состояние системы и отчёты агентов, отправляются в Anthropic (облако). Каждый запрос тратит токены вашего счёта: ограничивает лимит ниже.' : 'Всё остаётся на вашем компьютере. Ollama должна быть запущена (ollama serve).');
    };
    Q('#aicprov').onchange = sw; sw();
    Q('#aicgo').onclick = connect; Q('#aicoff').onclick = disconnect; Q('#aiclist').onclick = listModels;
    Q('#aictest').onclick = testKeys; Q('#aicrefresh').onclick = loadProviders;
    // панель управления провайдерами (полный цикл)
    Q('#mgAdd').onclick = mgAddProvider; Q('#mgAddKey').onclick = mgAddKey;
    Q('#mgTest').onclick = mgTestProvider; Q('#mgModels').onclick = mgListModels;
    Q('#mgTestSel').onclick = mgTestSelected; Q('#mgSaveModels').onclick = mgSaveModels;
    Q('#mgSelAll').onclick = function () { selAllModels(); };
    Q('#mgStats').onclick = mgShowStats; Q('#mgToggle').onclick = mgToggleProvider;
    Q('#mgDefault').onclick = mgSetDefault; Q('#mgDel').onclick = mgDelProvider;
    Q('#mgTestAll').onclick = mgTestAll;
    ['session', 'save', 'unlock', 'forget'].forEach(function (k, i) { Q(['#aicsess', '#aicsave', '#aicunlock', '#aicforget'][i]).onclick = function () { keyAct(k); }; });
    keyInfo(); usage();
    loadProviders().then(sw);
  }
  async function loadProviders() {
    var sel = Q('#aicprov'); if (!sel) return;
    try {
      var list = await inv('ai_providers_list');
      window.W420_DB_PROVIDERS = list || [];
      var st = await inv('ai_providers_status');
      sel.innerHTML = '';
      if (!list.length) { var o0 = document.createElement('option'); o0.value = ''; o0.textContent = '— в базе нет провайдеров —'; sel.appendChild(o0); }
      list.forEach(function (p) {
        var act = p.keys.filter(function (k) { return k.is_active; }).length;
        var o = document.createElement('option'); o.value = p.id;
        o.textContent = p.name + ' · ' + p.provider_type + ' · ключей: ' + act + (p.is_default ? ' · ПО УМОЛЧАНИЮ' : '');
        sel.appendChild(o);
        if (p.is_default) sel.value = p.id;
      });
      if (!sel.value && list.length) sel.value = list[0].id;
      var cur = list.find(function (p) { return p.id === sel.value; });
      if (cur) {
        CFG.provider = cur.id;
        var m = Q('#aicmodel'); if (m && !m.value && cur.models && cur.models[0]) m.value = cur.models[0];
        var dl = Q('#aicmodels'); if (dl) { dl.innerHTML = ''; (cur.models || []).forEach(function (mm) { var oo = document.createElement('option'); oo.value = mm; dl.appendChild(oo); }); }
        renderKeys(cur);
        renderModelChecks(cur.models || []);
      }
      var s = Q('#aicdbstat');
      if (s && st) s.textContent = 'ротация: ' + st.strategy + ' · ключей всего: ' + st.total_keys + ' · активных: ' + st.active_keys + ' · дефолт: ' + st.default_provider;
    } catch (e) { note('БД провайдеров недоступна: ' + (e && e.message || e)); }
  }
  function renderKeys(p) {
    var box = Q('#aickeys'); if (!box || !p) return;
    box.innerHTML = '';
    (p.keys || []).forEach(function (k) {
      var d = document.createElement('div');
      var lbl = document.createElement('span');
      lbl.textContent = (k.is_active ? '● ' : '○ ') + (k.nickname || '') + ' ' + k.mask +
        (k.avg_latency_ms ? ' · ~' + k.avg_latency_ms + ' мс' : '') +
        (k.error_count ? ' · ошибок: ' + k.error_count : '') +
        (k.blocked_until ? ' · блок до ' + k.blocked_until.slice(11, 19) : '') +
        (k.last_tested ? ' · тест ' + k.last_tested.slice(0, 19).replace('T', ' ') : '');
      d.appendChild(lbl);
      var tb = document.createElement('button'); tb.className = 'a'; tb.style.marginLeft = '6px'; tb.textContent = k.is_active ? 'ВЫКЛ' : 'ВКЛ';
      tb.onclick = async function () { try { await inv('ai_key_set_active', { key_id: k.id, is_active: !k.is_active }); mgLog('ключ ' + k.mask + ' → active=' + !k.is_active); loadProviders(); } catch (e) { mgLog('ошибка: ' + (e && e.message || e)); } };
      var db = document.createElement('button'); db.className = 'a'; db.style.marginLeft = '6px'; db.textContent = '✕';
      db.onclick = async function () { if (!confirm('Удалить ключ ' + k.mask + '?')) return; try { await inv('ai_key_remove', { key_id: k.id }); mgLog('ключ ' + k.mask + ' удалён'); loadProviders(); } catch (e) { mgLog('ошибка: ' + (e && e.message || e)); } };
      d.appendChild(tb); d.appendChild(db);
      box.appendChild(d);
    });
    if (!p.keys.length) box.textContent = '— у провайдера нет ключей —';
  }
  async function testKeys() {
    var p = (window.W420_DB_PROVIDERS || []).find(function (x) { return x.id === Q('#aicprov').value; });
    note('Тестирую ключи (это живые запросы к провайдеру)…');
    try {
      var res = await inv('ai_providers_test', { provider_id: p ? p.id : null });
      var box = Q('#aickeys'); box.innerHTML = '';
      res.forEach(function (r) {
        var d = document.createElement('div');
        d.textContent = (r.success ? '✓ ' : '✗ ') + r.mask + ' · ' + (r.success ? r.latency_ms + ' мс' : (r.error || 'ошибка'));
        box.appendChild(d);
      });
      var ok = res.filter(function (r) { return r.success; }).length;
      note('Готово: ' + ok + ' из ' + res.length + ' ключей отвечают.');
      loadProviders().then(sw);
    } catch (e) { note('Тест не удался: ' + (e && e.message || e)); }
  }
  /* ==================== ПАНЕЛЬ УПРАВЛЕНИЯ ПРОВАЙДЕРАМИ ==================== */
  function mgLog(t) { var e = Q('#mgLog'); if (e) e.textContent = '» ' + String(t) + '\n' + (e.textContent || ''); }
  function curProvider() { return (window.W420_DB_PROVIDERS || []).find(function (p) { return p.id === Q('#aicprov').value; }); }
  function selectedModels() { return Array.prototype.slice.call(document.querySelectorAll('#mgModelList input[type=checkbox]:checked')).map(function (c) { return c.value; }); }
  function renderModelChecks(models, saved) {
    var box = Q('#mgModelList'); if (!box) return;
    var p = curProvider();
    var active = saved || (p && p.models) || [];
    box.innerHTML = '';
    if (!models.length) { box.textContent = '— список пуст: нажмите «СПИСОК МОДЕЛЕЙ» —'; return; }
    models.forEach(function (m) {
      var l = document.createElement('label'); l.style.display = 'block';
      var c = document.createElement('input'); c.type = 'checkbox'; c.value = m; c.checked = active.indexOf(m) >= 0;
      l.appendChild(c); l.appendChild(document.createTextNode(' ' + m));
      box.appendChild(l);
    });
  }
  function selAllModels() { Array.prototype.forEach.call(document.querySelectorAll('#mgModelList input[type=checkbox]'), function (c) { c.checked = true; }); }
  function renderModelRows(el, rows) {
    el.innerHTML = '';
    if (!rows.length) { el.textContent = '— пока нет результатов —'; return; }
    rows.forEach(function (r) {
      var d = document.createElement('div');
      d.textContent = (r.success ? '✓' : '✗') + ' ' + r.model +
        ' · ' + r.latency_ms + ' мс' +
        (r.tokens_used != null ? ' · токенов: ' + r.tokens_used : '') +
        (r.tokens_per_sec != null ? ' · ' + r.tokens_per_sec.toFixed(1) + ' ток/с' : '') +
        (r.response_preview ? ' · «' + String(r.response_preview).slice(0, 40) + '»' : '') +
        (r.error_message || r.error ? ' · ОШИБКА: ' + (r.error_message || r.error) : '') +
        (r.tested_at ? ' · ' + r.tested_at.slice(0, 19).replace('T', ' ') : '');
      el.appendChild(d);
    });
  }
  async function mgAddProvider() {
    var name = Q('#mgName').value.trim(), type = Q('#mgType').value, ep = Q('#mgEndpoint').value.trim();
    if (!name) return mgLog('Введите имя провайдера');
    try {
      var r = await inv('ai_provider_add', { name: name, provider_type: type, endpoint: ep || null });
      mgLog('Провайдер добавлен: ' + r.name + ' (' + r.provider_type + ', ' + r.endpoint + ') id=' + r.id);
      Q('#mgName').value = ''; Q('#mgEndpoint').value = '';
      await loadProviders();
      Q('#aicprov').value = r.id; Q('#aicprov').onchange();
    } catch (e) { mgLog('ошибка добавления: ' + (e && e.message || e)); }
  }
  async function mgAddKey() {
    var p = curProvider(); if (!p) return mgLog('Сначала выберите провайдера');
    var key = Q('#mgKey').value.trim(), nick = Q('#mgNick').value.trim();
    if (!key) return mgLog('Введите API ключ');
    try {
      var r = await inv('ai_provider_add_key', { provider_id: p.id, api_key: key, nickname: nick || null });
      mgLog('Ключ добавлен к «' + p.name + '»: маска ' + r.mask + ' (полный ключ не покидал бэкенд)');
      Q('#mgKey').value = ''; Q('#mgNick').value = '';
      await loadProviders();
    } catch (e) { mgLog('ошибка: ' + (e && e.message || e)); }
  }
  async function mgTestProvider() {
    var p = curProvider(); if (!p) return mgLog('Сначала выберите провайдера');
    var box = Q('#mgProvTest'); box.textContent = 'Тестирую (живой запрос к ' + p.endpoint + ')…';
    try {
      var r = await inv('ai_provider_test', { provider_id: p.id });
      box.textContent = (r.success ? '✓ ПРОВАЙДЕР РАБОТАЕТ' : '✗ ОШИБКА') +
        '\nпровайдер: ' + r.provider_name + ' · ключ: ' + r.key_mask +
        '\nзадержка: ' + r.latency_ms + ' мс · моделей на эндпоинте: ' + r.models_available +
        (r.success ? '\nответ модели (первые 160 симв.): «' + r.response_text + '»' : '\nошибка: ' + (r.error || '—'));
      mgLog('тест «' + p.name + '»: ' + (r.success ? 'OK ' + r.latency_ms + ' мс, моделей ' + r.models_available : 'FAIL ' + r.error));
    } catch (e) { box.textContent = 'ошибка: ' + (e && e.message || e); mgLog(box.textContent); }
  }
  async function mgListModels() {
    var p = curProvider(); if (!p) return mgLog('Сначала выберите провайдера');
    mgLog('Запрашиваю список моделей у ' + p.endpoint + ' …');
    try {
      var models = await inv('ai_provider_list_models', { provider_id: p.id });
      renderModelChecks(models);
      mgLog('Получено моделей: ' + models.length + (models.length ? ' (первые: ' + models.slice(0, 3).join(', ') + '…)' : ''));
    } catch (e) { mgLog('ошибка списка моделей: ' + (e && e.message || e)); }
  }
  async function mgSaveModels() {
    var p = curProvider(); if (!p) return mgLog('Сначала выберите провайдера');
    var sel = selectedModels();
    try {
      var r = await inv('ai_provider_set_models', { provider_id: p.id, models: sel });
      mgLog('Конфигурация сохранена: у «' + r.name + '» выбрано моделей: ' + r.models.length);
      await loadProviders();
    } catch (e) { mgLog('ошибка сохранения: ' + (e && e.message || e)); }
  }
  async function mgTestSelected() {
    var p = curProvider(); if (!p) return mgLog('Сначала выберите провайдера');
    var sel = selectedModels();
    if (!sel.length) return mgLog('Отметьте модели чекбоксами (СПИСОК МОДЕЛЕЙ → чекбоксы)');
    var el = Q('#mgModelResults'); el.textContent = 'Тестирую ' + sel.length + ' моделей (живые запросы)…';
    try {
      var res = await inv('ai_provider_test_models', { provider_id: p.id, models: sel });
      renderModelRows(el, res);
      var ok = res.filter(function (r) { return r.success; }).length;
      mgLog('Тест моделей завершён: ' + ok + '/' + res.length + ' успешны. Результаты также в статистике (с сортировкой).');
    } catch (e) { el.textContent = 'ошибка: ' + (e && e.message || e); mgLog(el.textContent); }
  }
  async function mgShowStats() {
    var p = curProvider(); if (!p) return mgLog('Сначала выберите провайдера');
    var sort = Q('#mgSort').value;
    try {
      var st = await inv('ai_provider_model_stats', { provider_id: p.id, sort_by: sort });
      renderModelRows(Q('#mgModelResults'), st);
      mgLog('Статистика моделей «' + p.name + '» (сортировка: ' + sort + '), записей: ' + st.length);
    } catch (e) { mgLog('ошибка статистики: ' + (e && e.message || e)); }
  }
  async function mgToggleProvider() {
    var p = curProvider(); if (!p) return;
    try { var r = await inv('ai_provider_set_enabled', { provider_id: p.id, is_enabled: !p.is_enabled }); mgLog(r); await loadProviders(); } catch (e) { mgLog('ошибка: ' + (e && e.message || e)); }
  }
  async function mgSetDefault() {
    var p = curProvider(); if (!p) return;
    try { var r = await inv('ai_provider_set_default', { provider_id: p.id }); mgLog(r); await loadProviders(); } catch (e) { mgLog('ошибка: ' + (e && e.message || e)); }
  }
  async function mgDelProvider() {
    var p = curProvider(); if (!p) return;
    if (!confirm('Удалить провайдера «' + p.name + '» и ВСЕ его ключи?')) return;
    try { var r = await inv('ai_provider_remove', { provider_id: p.id }); mgLog(r); await loadProviders(); } catch (e) { mgLog('ошибка: ' + (e && e.message || e)); }
  }
  async function mgTestAll() {
    var el = Q('#mgModelResults'); el.textContent = 'Тестирую ВСЕ конфигурации (все провайдеры × активные ключи)…';
    try {
      var res = await inv('ai_providers_test_all');
      var rows = res.map(function (r) { return { model: r.provider + ' · ключ ' + r.mask, success: r.success, latency_ms: r.latency_ms, error: r.error, tokens_used: null, tokens_per_sec: null }; });
      renderModelRows(el, rows);
      var ok = res.filter(function (r) { return r.success; }).length;
      mgLog('Тест всех конфигураций: ' + ok + '/' + res.length + ' ключей отвечают. Результаты записаны в key_stats и статистику ключей.');
      await loadProviders();
    } catch (e) { el.textContent = 'ошибка: ' + (e && e.message || e); mgLog(el.textContent); }
  }
  build();
  apply();
  window.W420AI = { cfg: CFG, budget: budget, build: build };
})();

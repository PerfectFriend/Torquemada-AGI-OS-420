/* W420 VOICE: XTTS engine client, voice cloning (record / upload) and radio voice override.
   Runs only inside the native shell (needs the Tauri bridge and the local engine). */
(function () {
  var SR = 24000;

  /* ---------- pure helpers (unit-tested in node) ---------- */
  function chunkText(text, limit, first) {
    limit = limit || 170;
    var out = [], parts = String(text).trim().match(/[^.!?…]+[.!?…]*/g) || [];
    parts.forEach(function (p) {
      p = p.trim();
      while (p.length > limit) {
        var cut = Math.max(p.lastIndexOf(',', limit), p.lastIndexOf(' ', limit));
        if (cut < 20) cut = limit;
        out.push(p.slice(0, cut).trim());
        p = p.slice(cut).replace(/^[ ,]+/, '');
      }
      if (p) out.push(p);
    });
    if (first && out.length && out[0].length > first) {  // short first chunk = playback starts sooner
      var c = out[0], cut2 = Math.max(c.lastIndexOf(',', first), c.lastIndexOf(' ', first));
      if (cut2 > 20) out.splice(0, 1, c.slice(0, cut2).trim(), c.slice(cut2).replace(/^[ ,]+/, ''));
    }
    return out.filter(Boolean);
  }
  var dbfs = function (v) { return v > 0 ? 20 * Math.log10(v) : -120; };
  function analyze(x, sr) {
    var n = x.length, fr = Math.max(1, Math.round(sr * 0.02)), peak = 0, clip = 0, frames = [], i, j;
    for (i = 0; i < n; i++) { var a = Math.abs(x[i]); if (a > peak) peak = a; if (a >= 0.99) clip++; }
    for (i = 0; i + fr <= n; i += fr) { var s = 0; for (j = i; j < i + fr; j++) s += x[j] * x[j]; frames.push(dbfs(Math.sqrt(s / fr))); }
    var sorted = frames.slice().sort(function (p, q) { return p - q; });
    var noise = sorted.length ? sorted[Math.floor(sorted.length * 0.1)] : -120;
    var speech = frames.filter(function (d) { return d > -50; });
    var silentPct = frames.length ? (1 - speech.length / frames.length) * 100 : 100;
    var level = speech.length ? speech.reduce(function (p, q) { return p + q; }, 0) / speech.length : -120;
    var sec = n / sr, clipPct = clip / Math.max(1, n) * 100, v = [];
    if (sec < 6) v.push(['bad', 'Слишком коротко: ' + sec.toFixed(1) + ' с. Нужно хотя бы 6 с, лучше 20-30.']);
    else if (sec < 15) v.push(['warn', 'Коротковато (' + sec.toFixed(0) + ' с): клон будет точнее на 20-30 с.']);
    if (level < -38) v.push(['warn', 'Тихая запись: говорите ближе к микрофону.']);
    if (clipPct > 0.5) v.push(['warn', 'Перегруз звука (' + clipPct.toFixed(1) + '%): отодвиньте микрофон.']);
    if (noise > -45) v.push(['warn', 'Фоновый шум высоковат: найдите тихую комнату.']);
    if (silentPct > 45) v.push(['warn', 'Слишком много пауз (' + silentPct.toFixed(0) + '%).']);
    if (!v.length) v.push(['ok', 'Запись хорошая.']);
    return { sec: sec, level: level, peak: peak, clipPct: clipPct, noise: noise, silentPct: silentPct, verdicts: v };
  }
  function trimSilence(x, sr, thr, pad, maxSec) {
    thr = thr == null ? -45 : thr; pad = pad == null ? 0.15 : pad; maxSec = maxSec || 30;
    var fr = Math.round(sr * 0.02), first = -1, last = -1, i, j;
    for (i = 0; i + fr <= x.length; i += fr) {
      var s = 0; for (j = i; j < i + fr; j++) s += x[j] * x[j];
      if (dbfs(Math.sqrt(s / fr)) > thr) { if (first < 0) first = i; last = i + fr; }
    }
    if (first < 0) return x.slice(0, 0);
    var a = Math.max(0, first - Math.round(pad * sr)), b = Math.min(x.length, last + Math.round(pad * sr));
    return x.slice(a, Math.min(b, a + Math.round(maxSec * sr)));
  }
  function normalize(x, target, maxGainDb) {
    target = target || 0.9; var peak = 0, i;
    for (i = 0; i < x.length; i++) { var a = Math.abs(x[i]); if (a > peak) peak = a; }
    if (peak < 1e-4) return x;
    var g = Math.min(target / peak, Math.pow(10, (maxGainDb == null ? 12 : maxGainDb) / 20)), y = new Float32Array(x.length);
    for (i = 0; i < x.length; i++) y[i] = x[i] * g;
    return y;
  }
  function encodeWav16(x, sr) {
    var buf = new ArrayBuffer(44 + x.length * 2), d = new DataView(buf), i;
    var w = function (o, s) { for (var k = 0; k < s.length; k++) d.setUint8(o + k, s.charCodeAt(k)); };
    w(0, 'RIFF'); d.setUint32(4, 36 + x.length * 2, true); w(8, 'WAVE'); w(12, 'fmt ');
    d.setUint32(16, 16, true); d.setUint16(20, 1, true); d.setUint16(22, 1, true);
    d.setUint32(24, sr, true); d.setUint32(28, sr * 2, true); d.setUint16(32, 2, true); d.setUint16(34, 16, true);
    w(36, 'data'); d.setUint32(40, x.length * 2, true);
    for (i = 0; i < x.length; i++) d.setInt16(44 + i * 2, Math.max(-1, Math.min(1, x[i])) * 32767, true);
    return buf;
  }
  function monoMix(chs) {
    if (chs.length === 1) return chs[0];
    var out = new Float32Array(chs[0].length), c, i;
    for (c = 0; c < chs.length; c++) for (i = 0; i < out.length; i++) out[i] += chs[c][i] / chs.length;
    return out;
  }
  var Pure = { chunkText: chunkText, analyze: analyze, trimSilence: trimSilence, normalize: normalize, encodeWav16: encodeWav16, monoMix: monoMix };
  if (typeof module !== 'undefined' && module.exports) { module.exports = Pure; return; }
  if (!(window.__TAURI__ && window.__TAURI__.core)) return;

  /* ---------- state ---------- */
  var inv = window.__TAURI__.core.invoke, Q = function (s) { return document.querySelector(s); };
  var ENG = { port: 0, token: '', ready: false }, VOICES = [], pending = null, recState = null;
  var LS = { get: function (k, d) { try { var v = localStorage.getItem(k); return v == null ? d : v; } catch (e) { return d; } }, set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) {} } };
  var ACTIVE = LS.get('w420.voice.active', ''), LANG = LS.get('w420.voice.lang', 'ru'), SPEED = parseFloat(LS.get('w420.voice.speed', '1')) || 1;
  var note = function (t) { var e = Q('#vcstat'); if (e) e.textContent = t; };
  var aud = function (a, d) { try { if (typeof audit === 'function') audit('voice', a + (d ? ': ' + d : '')); } catch (e) {} };
  var READ = 'Сегодня вечером я расскажу, как устроена моя система. Утром она проверяет сеть, днём помогает с задачами, а ночью спокойно ждёт. Если что-то идёт не так, я говорю об этом прямо и без паники. А ещё я люблю хорошие шутки, особенно те, над которыми не стыдно посмеяться вместе. Вот, например: почему программисты путают Хэллоуин и Рождество? Потому что тридцать первое октября в восьмеричной системе равно двадцать пятому декабря. Спасибо, что слушаете, и до новых встреч в эфире!';

  /* ---------- engine API ---------- */
  function api(path, opt) {
    opt = opt || {}; opt.headers = Object.assign({ 'X-W420-Token': ENG.token }, opt.headers || {});
    return fetch('http://127.0.0.1:' + ENG.port + path, opt).then(function (r) {
      if (r.ok) return r;
      return r.json().catch(function () { return {}; }).then(function (j) { throw new Error(j.detail || r.statusText); });
    });
  }
  function health() { return fetch('http://127.0.0.1:' + ENG.port + '/health').then(function (r) { return r.json(); }); }
  function setBadge(txt, cls) { var b = Q('#vcbadge'); if (b) { b.textContent = txt; b.className = 'b ' + cls; } }
  async function startEngine() {
    if (!Q('#vclic').checked) { note('Сначала подтвердите лицензию модели.'); return; }
    LS.set('w420.xtts.tos', '1'); Q('#vcgo').disabled = true; setBadge('STARTING', 'wip');
    try {
      var info = await inv('tts_start', { acceptLicense: true }); ENG.port = info.port; ENG.token = info.token; aud('engine start');
      for (var i = 0; i < 900; i++) {
        var h; try { h = await health(); } catch (e) { h = { status: 'starting', msg: '' }; }
        note('Движок: ' + h.status + (h.msg ? ' · ' + h.msg : '') + (h.device ? ' · ' + h.device : ''));
        if (h.status === 'ready') { ENG.ready = true; setBadge('ENGINE ON', 'live'); await refreshVoices(); return; }
        if (h.status === 'error') { setBadge('ERROR', 'wip'); break; }
        await new Promise(function (r) { setTimeout(r, 2000); });
      }
    } catch (e) { note(String(e && e.message || e)); setBadge('ENGINE OFF', 'wip'); }
    Q('#vcgo').disabled = false;
  }
  async function stopEngine() { try { await inv('tts_stop'); } catch (e) {} ENG.ready = false; setBadge('ENGINE OFF', 'wip'); Q('#vcgo').disabled = false; note('Движок остановлен.'); }

  /* ---------- playback ---------- */
  var spk = 0, curAudio = null, curRes = null;
  function stopAudio() { if (curAudio) { try { curAudio.pause(); } catch (e) {} } if (curRes) { var r = curRes; curRes = null; r(); } curAudio = null; }
  function duck(on) { try { if (typeof R !== 'undefined' && R.master) R.master.gain.setTargetAtTime(on ? R.vol * 0.3 : R.vol, R.ctx.currentTime, 0.2); } catch (e) {} }
  function fetchChunk(t, vid) {
    return api('/speak', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: t, voice_id: vid, lang: LANG, speed: SPEED }) })
      .then(function (r) { return r.blob(); });
  }
  function playBlob(blob) {
    return new Promise(function (res) {
      var a = new Audio(URL.createObjectURL(blob)); curAudio = a; curRes = res;
      a.onended = a.onerror = function () { curRes = null; res(); };
      a.play().catch(function () { curRes = null; res(); });
    });
  }
  async function ttsSpeak(text, vid) {
    var my = ++spk; stopAudio(); vid = vid || ACTIVE;
    var chunks = chunkText(text, LANG === 'ru' ? 170 : 230, 90); if (!chunks.length) return;
    var next = fetchChunk(chunks[0], vid); next.catch(function () {});
    duck(true);
    try {
      for (var i = 0; i < chunks.length; i++) {
        var blob = await next; if (my !== spk) return;
        if (i + 1 < chunks.length) { next = fetchChunk(chunks[i + 1], vid); next.catch(function () {}); }
        await playBlob(blob); if (my !== spk) return;
      }
    } finally { if (my === spk) duck(false); }
  }

  /* ---------- voices ---------- */
  async function refreshVoices() {
    try { VOICES = await (await api('/voices')).json(); } catch (e) { VOICES = []; note(String(e.message)); }
    if (ACTIVE && !VOICES.some(function (v) { return v.id === ACTIVE; })) { ACTIVE = ''; LS.set('w420.voice.active', ''); }
    renderVoices();
  }
  function renderVoices() {
    var box = Q('#vclist'); if (!box) return; box.innerHTML = '';
    if (!VOICES.length) { box.textContent = 'Голосов пока нет: запишите или загрузите образец ниже.'; return; }
    VOICES.forEach(function (v) {
      var row = document.createElement('div'); row.className = 'item';
      var name = document.createElement('span'); name.textContent = (v.id === ACTIVE ? '● ' : '○ ') + v.name + ' · ' + v.seconds + ' с';
      var mk = function (label, fn) { var b = document.createElement('button'); b.className = 'a'; b.textContent = label; b.onclick = fn; return b; };
      var del = mk('УДАЛИТЬ', function () {
        if (del.dataset.sure !== '1') { del.dataset.sure = '1'; del.textContent = 'ТОЧНО?'; setTimeout(function () { del.dataset.sure = '0'; del.textContent = 'УДАЛИТЬ'; }, 4000); return; }
        api('/voices/' + v.id, { method: 'DELETE' }).then(function () { aud('voice deleted', v.name); return refreshVoices(); }).catch(function (e) { note(e.message); });
      });
      row.append(name,
        mk('ПРОБА', function () { ttsSpeak('Привет! Это мой голос. Как вам звучание?', v.id).catch(function (e) { note(e.message); }); }),
        mk('ВЕДУЩИЙ', function () { ACTIVE = v.id; LS.set('w420.voice.active', v.id); renderVoices(); aud('active voice set', v.name); }),
        del);
      box.appendChild(row);
    });
  }

  /* ---------- capture: record or upload -> 24 kHz mono WAV ---------- */
  async function toRate(mono, rate) {
    if (rate === SR) return mono;
    var OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    var ac = new OAC(1, Math.ceil(mono.length * SR / rate), SR), b = ac.createBuffer(1, mono.length, rate);
    b.copyToChannel(mono, 0); var s = ac.createBufferSource(); s.buffer = b; s.connect(ac.destination); s.start();
    return (await ac.startRendering()).getChannelData(0);
  }
  async function preparePending(mono, rate) {
    var x = normalize(trimSilence(mono, rate)); x = await toRate(x, rate);
    var rep = analyze(x, SR), wav = new Blob([encodeWav16(x, SR)], { type: 'audio/wav' });
    pending = { wav: wav, rep: rep };
    var p = Q('#vcprev'); if (p) p.src = URL.createObjectURL(wav);
    var r = Q('#vcrep'); r.innerHTML = '';
    var head = document.createElement('div'); head.textContent = 'Длина ' + rep.sec.toFixed(1) + ' с · уровень ' + rep.level.toFixed(0) + ' дБ · шум ' + rep.noise.toFixed(0) + ' дБ'; r.appendChild(head);
    rep.verdicts.forEach(function (vd) { var d = document.createElement('div'); d.style.color = vd[0] === 'ok' ? 'var(--live)' : 'var(--wip)'; d.textContent = (vd[0] === 'ok' ? '✓ ' : '⚠ ') + vd[1]; r.appendChild(d); });
    updateSave();
  }
  function updateSave() { var b = Q('#vcsave'); if (b) b.disabled = !(pending && Q('#vcconsent').checked && Q('#vcname').value.trim() && ENG.ready); }
  async function startRec() {
    if (recState) return;
    var stream;
    try { stream = await navigator.mediaDevices.getUserMedia({ audio: { channelCount: 1, echoCancellation: false, noiseSuppression: false, autoGainControl: false } }); }
    catch (e) { note('Микрофон недоступен: ' + (e.message || e) + '. Загрузите готовый файл.'); return; }
    var AC = window.AudioContext || window.webkitAudioContext, ac = new AC(), src = ac.createMediaStreamSource(stream);
    var proc = ac.createScriptProcessor(4096, 1, 1), mute = ac.createGain(), chunks = [], t0 = Date.now(); mute.gain.value = 0;
    proc.onaudioprocess = function (e) {
      var d = e.inputBuffer.getChannelData(0), m = 0; chunks.push(new Float32Array(d));
      for (var i = 0; i < d.length; i += 16) m = Math.max(m, Math.abs(d[i]));
      var meter = Q('#vcmeter'); if (meter) meter.style.width = Math.min(100, m * 140) + '%';
      var el = (Date.now() - t0) / 1000; Q('#vctime').textContent = el.toFixed(0) + ' / 30 с'; if (el >= 30) stopRec();
    };
    src.connect(proc); proc.connect(mute); mute.connect(ac.destination);
    recState = { ac: ac, stream: stream, proc: proc, chunks: chunks }; Q('#vcrec').textContent = '■ СТОП'; note('Идёт запись: читайте текст выше обычным голосом.');
  }
  async function stopRec() {
    if (!recState) return; var s = recState; recState = null;
    s.proc.disconnect(); s.stream.getTracks().forEach(function (t) { t.stop(); }); var rate = s.ac.sampleRate; s.ac.close();
    var n = s.chunks.reduce(function (a, c) { return a + c.length; }, 0), all = new Float32Array(n), o = 0;
    s.chunks.forEach(function (c) { all.set(c, o); o += c.length; });
    Q('#vcrec').textContent = '● ЗАПИСАТЬ 30 с'; Q('#vcmeter').style.width = '0%'; note('Запись готова, проверьте качество ниже.');
    await preparePending(all, rate);
  }
  async function onFile(e) {
    var f = e.target.files[0]; if (!f) return;
    try {
      var AC = window.AudioContext || window.webkitAudioContext, ac = new AC(), buf = await ac.decodeAudioData(await f.arrayBuffer());
      var chs = []; for (var c = 0; c < buf.numberOfChannels; c++) chs.push(buf.getChannelData(c));
      var rate = buf.sampleRate; ac.close(); note('Файл «' + f.name + '» прочитан.'); await preparePending(monoMix(chs), rate);
    } catch (err) { note('Этот формат не открывается в системе. Конвертируйте в WAV или MP3 и попробуйте снова.'); }
    e.target.value = '';
  }
  async function saveVoice() {
    if (!pending) return; var name = Q('#vcname').value.trim();
    try {
      var r = await api('/voices', { method: 'POST', headers: { 'X-Voice-Name': encodeURIComponent(name), 'X-Consent': '1', 'Content-Type': 'audio/wav' }, body: pending.wav });
      var item = await r.json(); aud('voice added', name); pending = null; Q('#vcrep').textContent = ''; Q('#vcname').value = '';
      if (!ACTIVE) { ACTIVE = item.id; LS.set('w420.voice.active', item.id); }
      await refreshVoices(); note('Голос «' + name + '» сохранён на этом компьютере.');
    } catch (e) { note(e.message); }
    updateSave();
  }

  /* ---------- UI ---------- */
  function build() {
    if (Q('#v-voice') || !Q('#v-radio') || !Q('nav')) return;
    var sec = document.createElement('section'); sec.className = 'view live'; sec.id = 'v-voice';
    sec.innerHTML =
      '<h2>VOICE · XTTS <span class="b wip" id="vcbadge">ENGINE OFF</span></h2>' +
      '<div class="mono" style="opacity:.8">Локальный синтез речи XTTS-v2 и клонирование голоса. Всё работает на этом компьютере: записи не отправляются в сеть и лежат в ~/.w420/voices.</div>' +
      '<div class="card"><div class="k">ДВИЖОК</div>' +
      '<label class="mono"><input type="checkbox" id="vclic" style="width:auto"> Принимаю лицензию модели XTTS-v2 (CPML): использование только некоммерческое</label>' +
      '<div class="row" style="margin-top:6px"><button class="a" id="vcgo">ЗАПУСТИТЬ ДВИЖОК</button><button class="a" id="vcoff">ОСТАНОВИТЬ</button></div>' +
      '<div class="mono" id="vcstat">Движок выключен. Запуск поднимет локальный сервер (espeak-ng TTS + faster-whisper STT, модель ~150 МБ скачивается один раз).</div></div>' +
      '<div class="card"><div class="k">ГОЛОСОВЫЕ КОМАНДЫ <span class="b live">LIVE</span></div>' +
      '<div class="mono" style="opacity:.85">Скажите команду: «тревога» / «отбой», «статус», «сканируй сеть», «заблокируй 10.0.0.5», «мониторинг включи», «мониторинг выключи», «список хостов». Система ответит голосом.</div>' +
      '<div class="row" style="margin-top:6px"><button class="a" id="vcmd">🎤 СКАЗАТЬ КОМАНДУ</button><span class="mono" id="vcmdstat">—</span></div>' +
      '<div class="mono" id="vcmdtext" style="margin-top:4px"></div></div>' +
      '<div class="card"><div class="k">МОИ ГОЛОСА</div><div id="vclist" class="mono">—</div>' +
      '<div class="row" style="margin-top:6px"><select id="vclang" style="width:auto"><option value="ru">русский</option><option value="en">English</option></select>' +
      '<label class="mono">скорость <input type="range" id="vcspeed" min="0.8" max="1.2" step="0.05" style="width:110px"></label></div></div>' +
      '<div class="card"><div class="k">ДОБАВИТЬ ГОЛОС</div>' +
      '<div class="mono" style="opacity:.85">Прочитайте вслух текст (около 30 с) или загрузите файл с чистой речью одного человека: без музыки и фоновых голосов.</div>' +
      '<div class="mono" style="border-left:2px solid var(--live);padding-left:8px;margin:6px 0" id="vcread"></div>' +
      '<div class="row"><button class="a" id="vcrec">● ЗАПИСАТЬ 30 с</button><span class="mono" id="vctime">0 / 30 с</span><span style="flex:1;max-width:160px;height:8px;border:1px solid var(--live)"><span id="vcmeter" style="display:block;height:100%;width:0;background:var(--live)"></span></span></div>' +
      '<div class="row" style="margin-top:6px"><input type="file" id="vcfile" accept="audio/*"></div>' +
      '<audio id="vcprev" controls style="width:100%;margin-top:6px"></audio><div class="mono" id="vcrep"></div>' +
      '<div class="row" style="margin-top:6px"><input id="vcname" placeholder="имя голоса, например: Мама"></div>' +
      '<label class="mono"><input type="checkbox" id="vcconsent" style="width:auto"> Это мой голос, либо у меня есть согласие человека, чей это голос. Я не буду использовать клон, чтобы вводить кого-то в заблуждение или выдавать себя за другого.</label>' +
      '<div class="row" style="margin-top:6px"><button class="a" id="vcsave" disabled>СОХРАНИТЬ ГОЛОС</button></div></div>';
    Q('#v-radio').parentNode.appendChild(sec);
    var btn = document.createElement('button'); btn.className = 'live'; btn.textContent = 'VOICE'; btn.dataset.id = 'voice';
    btn.onclick = function () { show('voice'); }; Q('nav').appendChild(btn);
    Q('#vcread').textContent = READ; Q('#vclang').value = LANG; Q('#vcspeed').value = SPEED;
    Q('#vclic').checked = LS.get('w420.xtts.tos', '') === '1';
    Q('#vcgo').onclick = startEngine; Q('#vcoff').onclick = stopEngine;
    Q('#vcrec').onclick = function () { recState ? stopRec() : startRec(); };
    Q('#vcfile').onchange = onFile; Q('#vcsave').onclick = saveVoice;
    ['#vcname', '#vcconsent'].forEach(function (s) { Q(s).addEventListener('input', updateSave); Q(s).addEventListener('change', updateSave); });
    Q('#vclang').onchange = function (e) { LANG = e.target.value; LS.set('w420.voice.lang', LANG); };
    Q('#vcspeed').oninput = function (e) { SPEED = parseFloat(e.target.value); LS.set('w420.voice.speed', String(SPEED)); };
    Q('#vcmd').onclick = voiceCmd;
    renderVoices();
  }

  /* ---------- голосовые команды: запись -> STT -> voice_command -> голосовой ответ ---------- */
  var cmdRec = null, cmdChunks = [];
  function b64encode(buf) {
    var bin = '', u8 = new Uint8Array(buf);
    for (var i = 0; i < u8.length; i += 0x8000) bin += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    return btoa(bin);
  }
  async function voiceCmd() {
    var st = Q('#vcmdstat'), tx = Q('#vcmdtext'), btn = Q('#vcmd');
    if (cmdRec) { try { cmdRec.stop(); } catch (e) {} return; }
    try {
      var stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      cmdChunks = [];
      cmdRec = new MediaRecorder(stream);
      cmdRec.ondataavailable = function (e) { if (e.data && e.data.size) cmdChunks.push(e.data); };
      cmdRec.onstop = async function () {
        stream.getTracks().forEach(function (t) { t.stop(); });
        cmdRec = null; btn.textContent = '🎤 СКАЗАТЬ КОМАНДУ'; st.textContent = 'распознаю речь…';
        try {
          var buf = await new Blob(cmdChunks).arrayBuffer();
          var h = await inv('voice_hear_b64', { b64: b64encode(buf) });
          var text = (h && h.text) || '';
          st.textContent = 'распознано: «' + text + '»';
          var r = await inv('voice_command', { text: text });
          tx.textContent = '→ ' + r.action + ': ' + r.reply;
          st.textContent = r.ok ? 'выполнено' : 'не выполнено';
          // голосовой ответ: своим движком, если он поднят, иначе через voice_say напрямую
          if (ENG.ready && ACTIVE) ttsSpeak(r.reply).catch(function () {});
          else inv('voice_say', { text: r.reply, voiceId: ACTIVE || null, lang: LANG || 'ru' })
            .then(function (res) { if (res && res.ok) new Audio('data:audio/wav;base64,' + res.b64).play().catch(function () {}); })
            .catch(function () {});
        } catch (e) { st.textContent = 'ошибка: ' + e.message; }
      };
      cmdRec.start();
      btn.textContent = '■ СТОП'; st.textContent = 'слушаю… нажмите ещё раз, чтобы остановить';
    } catch (e) { st.textContent = 'нет доступа к микрофону: ' + e.message; }
  }

  /* ---------- radio / episode voice: XTTS when ready, browser voice as fallback ---------- */
  var origSay = window.radioSay;
  window.radioSay = function (t) {
    if (typeof R !== 'undefined' && R.voice === false) return;
    if (ENG.ready && ACTIVE) ttsSpeak(t).catch(function (e) { note('XTTS: ' + e.message + ' (читаю голосом браузера)'); if (origSay) origSay(t); });
    else if (origSay) origSay(t);
  };
  if (typeof R !== 'undefined') { var rv = Q('#rvoice'); if (rv) rv.addEventListener('change', function () { if (!rv.checked) { spk++; stopAudio(); duck(false); } }); }
  build();
  window.W420VOICE = { speak: ttsSpeak, state: ENG, build: build };
})();

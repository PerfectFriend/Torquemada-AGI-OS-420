/* W420 i18n + глобальные настройки.
   Механизм: словарь ключится по ИСХОДНОМУ (русскому) тексту. applyLang() обходит все
   текстовые узлы и placeholder'ы, запоминает оригинал в node.__ru / el.__ph и подставляет
   перевод. MutationObserver повторяет проход при появлении нового текста (JS-модули),
   поэтому локализуется и динамически сгенерированный контент без правки их кода.
   Поиск по ключу — точное совпадение или префикс (чтобы ловить 'Добавлено профилей: 3').
   Если перевода нет — остаётся исходный русский текст (fallback).
   Настройки (язык, тема, радио) хранятся в ~/.w420/settings.json через Tauri-команды
   settings_get/settings_set; вне Tauri — в localStorage. */
(function () {
  'use strict';
  var Q = function (s) { return document.querySelector(s); };
  var store = {
    get: function (k, d) { try { var v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch (e) { return d; } },
    set: function (k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} }
  };

  // Словари подключаются отдельными файлами: window.I18N_EN, window.I18N_ES (ключ = русская строка)
  var DICTS = { ru: {}, en: window.I18N_EN || {}, es: window.I18N_ES || {} };
  var LANGS = ['ru', 'en', 'es'];
  var LANG = 'ru';
  var SETTINGS = { lang: 'ru', theme: 'matrix', radio_voice: true, radio_volume: 50 };

  var tauriInvoke = function (cmd, args) {
    if (window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke) {
      return window.__TAURI__.core.invoke(cmd, args || {});
    }
    return Promise.reject(new Error('no tauri'));
  };

  // --- перевод одной строки (для JS-кода: t('русская строка')) ---
  window.t = function (s) {
    if (LANG === 'ru') return s;
    var d = DICTS[LANG] || {};
    return d[s] !== undefined ? d[s] : s;
  };

  // кэш префиксного поиска: для языка — массив [ключ, перевод], по убыванию длины ключа
  var prefixCache = {};
  function prefixList(lang) {
    if (prefixCache[lang]) return prefixCache[lang];
    var d = DICTS[lang] || {}, arr = [];
    for (var k in d) { if (d.hasOwnProperty(k) && k.length >= 3) arr.push([k, d[k]]); }
    arr.sort(function (a, b) { return b[0].length - a[0].length; });
    prefixCache[lang] = arr;
    return arr;
  }

  // меняет leading/trailing whitespace исходного узла, подставляя перевод середины
  function swapMid(orig, translated) {
    var lead = orig.match(/^\s*/)[0], trail = orig.match(/\s*$/)[0];
    return lead + translated + trail;
  }

  // переводит один текстовый узел
  function translateNode(node, lang) {
    if (node.__ru === undefined) node.__ru = node.nodeValue; // запоминаем оригинал один раз
    var orig = node.__ru;
    if (lang === 'ru') { if (node.nodeValue !== orig) node.nodeValue = orig; return; }
    var d = DICTS[lang] || {};
    var core = orig.replace(/^\s+|\s+$/g, '');
    var val = null;
    if (d[core] !== undefined) val = d[core];
    else {
      var list = prefixList(lang);
      for (var i = 0; i < list.length; i++) {
        var k = list[i][0];
        if (core.length > k.length && core.indexOf(k) === 0) { val = list[i][1] + core.slice(k.length); break; }
      }
    }
    if (val === null) val = orig; // fallback: русский
    var next = swapMid(orig, val);
    if (node.nodeValue !== next) node.nodeValue = next;
  }

  function translatePlaceholder(el, lang) {
    if (el.__ph === undefined) el.__ph = el.getAttribute('placeholder') || '';
    var orig = el.__ph;
    var d = DICTS[lang] || {};
    var val = (lang === 'ru' || d[orig] === undefined) ? orig : d[orig];
    if (el.getAttribute('placeholder') !== val) el.setAttribute('placeholder', val);
  }

  // проход по поддереву: текстовые узлы (кроме script/style) + placeholder + title
  function applyLang(lang, root) {
    LANG = lang;
    document.documentElement.lang = lang;
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: function (n) {
        var p = n.parentNode;
        if (!p || !p.tagName) return NodeFilter.FILTER_REJECT;
        var tag = p.tagName.toLowerCase();
        if (tag === 'script' || tag === 'style') return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    var nodes = [], n;
    while ((n = walker.nextNode())) nodes.push(n);
    for (var i = 0; i < nodes.length; i++) translateNode(nodes[i], lang);
    var ph = (root || document).querySelectorAll ? (root || document).querySelectorAll('[placeholder]') : [];
    for (var j = 0; j < ph.length; j++) translatePlaceholder(ph[j], lang);
    var ti = (root || document).querySelectorAll ? (root || document).querySelectorAll('[title]') : [];
    for (var m = 0; m < ti.length; m++) {
      var el = ti[m];
      if (el.__ti === undefined) el.__ti = el.getAttribute('title') || '';
      var d = DICTS[lang] || {};
      var tv = (lang === 'ru' || d[el.__ti] === undefined) ? el.__ti : d[el.__ti];
      if (el.getAttribute('title') !== tv) el.setAttribute('title', tv);
    }
  }

  // --- MutationObserver: локализуем и динамически добавленный текст ---
  var applying = false, moTimer = 0;
  function scheduleApply() {
    if (applying) return;
    clearTimeout(moTimer);
    moTimer = setTimeout(function () {
      applying = true;
      try { applyLang(LANG, document.body); } catch (e) {}
      applying = false;
    }, 100);
  }

  // --- тема ---
  // dark — легаси-алиас matrix; остальные темы перечислены в CSS (:root[data-theme=...])
  function applyTheme(theme) {
    if (theme === 'dark') theme = 'matrix';
    document.documentElement.setAttribute('data-theme', theme || 'matrix');
    // C1: если обои не выбраны вручную — подхватить дефолт новой темы
    try { if ((localStorage.getItem('w420-wallpaper') || 'theme') === 'theme' && window.Desktop && Desktop.applyWallpaper) Desktop.applyWallpaper('theme'); } catch (e) {}
  }

  // --- применение настроек к живым контролам ---
  function applySettingsToControls() {
    var v = Q('#rvoice'); if (v) v.checked = !!SETTINGS.radio_voice;
    var vol = Q('#rvol'); if (vol) vol.value = String(SETTINGS.radio_volume);
  }

  // --- загрузка/сохранение настроек ---
  function loadSettings() {
    return tauriInvoke('settings_get').then(function (s) {
      if (s && typeof s === 'object') SETTINGS = Object.assign({}, SETTINGS, s);
      return SETTINGS;
    }).catch(function () {
      var s = store.get('w420.settings', null);
      if (s) SETTINGS = Object.assign({}, SETTINGS, s);
      return SETTINGS;
    });
  }

  function saveSettings(patch) {
    SETTINGS = Object.assign({}, SETTINGS, patch);
    store.set('w420.settings', SETTINGS);
    return tauriInvoke('settings_set', { patch: patch }).catch(function () { return null; })
      .then(function () { applyAll(); });
  }

  function applyAll() {
    applyTheme(SETTINGS.theme);
    applyLang(SETTINGS.lang || 'ru', document.body);
    applySettingsToControls();
    syncPanel();
  }

  // --- панель настроек (шестерёнка в шапке) ---
  function buildPanel() {
    var gear = Q('#gear');
    var panel = Q('#spanel');
    if (!gear || !panel) return;
    gear.addEventListener('click', function () {
      panel.hidden = !panel.hidden;
      if (!panel.hidden) syncPanel();
    });
    panel.addEventListener('click', function (e) { if (e.target === panel) panel.hidden = true; });
    var close = Q('#s-close'); if (close) close.addEventListener('click', function () { panel.hidden = true; });
    var lang = Q('#s-lang');
    if (lang) lang.addEventListener('change', function () { saveSettings({ lang: lang.value }); });
    var theme = Q('#s-theme');
    if (theme) theme.addEventListener('change', function () { saveSettings({ theme: theme.value }); });
    var voice = Q('#s-voice');
    if (voice) voice.addEventListener('change', function () { saveSettings({ radio_voice: voice.checked }); });
    var vol = Q('#s-vol');
    if (vol) vol.addEventListener('input', function () { saveSettings({ radio_volume: Number(vol.value) }); });
    var reset = Q('#s-reset');
    if (reset) reset.addEventListener('click', function () {
      SETTINGS = { lang: 'ru', theme: 'matrix', radio_voice: true, radio_volume: 50 };
      store.set('w420.settings', SETTINGS);
      tauriInvoke('settings_set', { patch: SETTINGS }).catch(function () {});
      applyAll();
    });
  }

  // синхронизирует контролы панели с текущими настройками
  function syncPanel() {
    var lang = Q('#s-lang'); if (lang) lang.value = SETTINGS.lang || 'ru';
    var theme = Q('#s-theme'); if (theme) theme.value = (SETTINGS.theme === 'dark' ? 'matrix' : (SETTINGS.theme || 'matrix'));
    var voice = Q('#s-voice'); if (voice) voice.checked = !!SETTINGS.radio_voice;
    var vol = Q('#s-vol'); if (vol) vol.value = String(SETTINGS.radio_volume);
  }

  // --- старт ---
  function init() {
    buildPanel();
    loadSettings().then(function () {
      applyAll();
      if (window.MutationObserver) {
        new MutationObserver(scheduleApply).observe(document.body, {
          childList: true, subtree: true, characterData: true,
          attributes: true, attributeFilter: ['placeholder', 'title']
        });
      }
      // повторный проход после полной отрисовки модулей
      setTimeout(function () { applyLang(LANG, document.body); }, 300);
      setTimeout(function () { applyLang(LANG, document.body); }, 1500);
    });
  }

  window.W420I18N = {
    t: window.t,
    applyLang: function (l) { if (LANGS.indexOf(l) >= 0) { prefixCache = {}; applyAllWith(l); } },
    getLang: function () { return LANG; },
    getSettings: function () { return SETTINGS; },
    saveSettings: saveSettings
  };
  function applyAllWith(l) { SETTINGS.lang = l; applyAll(); }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();

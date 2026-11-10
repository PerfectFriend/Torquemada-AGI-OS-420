/* did.js — Этап 22: DIGITAL ID через Rust keyring (did.rs), native-only.
   Персистентный did:w420:… (ECDSA P-256, приватный ключ — AES-256-GCM в
   ~/.w420/did/keyring.json, 0600). В браузере без Tauri — прежнее поведение. */
(function(){
  const NATIVE = !!(window.__TAURI__ && window.__TAURI__.core);
  if(!NATIVE) return;
  const inv = window.__TAURI__.core.invoke;
  let curDid = null;

  /* Пароль DID — динамическое поле в карточке (HTML тонкий клиент не меняем) */
  const card = document.querySelector('#v-id .card');
  const pwIn = document.createElement('input');
  pwIn.type = 'password'; pwIn.placeholder = 'пароль DID keyring (мин. 8)';
  pwIn.style.cssText = 'width:100%;margin-top:6px';
  if(card) card.appendChild(pwIn);
  const pw = () => pwIn.value.trim();

  /* Снять плашку WIP, загрузить последний DID */
  (async()=>{
    try{
      const badges = document.querySelectorAll('#v-id .b.wip');
      badges.forEach(b => { b.textContent = 'DID: LIVE'; b.className = 'b live'; });
      const note = document.querySelector('#v-id > div.mono');
      if(note) note.textContent = 'ECDSA P-256 в Rust: приватный ключ шифруется AES-256-GCM (PBKDF2 600k) в ~/.w420/did/keyring.json и переживает перезапуск. DID = did:w420: + HEX(SHA-256(pubkey))[..20].';
      const list = await inv('did_list');
      if(list.dids && list.dids.length){
        curDid = list.dids[list.dids.length-1].did;
        $('#idv').textContent = curDid + '\nECDSA P-256 · ключ в зашифрованном keyring · персистентный';
      }
    }catch(e){}
  })();

  $('#idgen').onclick = async ()=>{
    const p = pw();
    if(p.length < 8) return $('#idv').textContent = 'введите пароль DID (мин. 8 символов) в поле под ID';
    try{
      const r = await inv('did_create', {password:p, label:'w420'});
      curDid = r.did;
      pwIn.value = '';
      $('#idv').textContent = r.did + '\n' + r.scheme;
      say('DID создан: ' + r.did, 'var(--live)');
      audit('did', 'create ' + r.did);
    }catch(e){ $('#idv').textContent = 'ошибка: ' + (e.message || e); }
  };

  $('#idsign').onclick = async ()=>{
    if(!curDid) return $('#idsig').textContent = 'сначала GENERATE IDENTITY';
    const p = pw();
    if(p.length < 8) return $('#idsig').textContent = 'введите пароль DID';
    try{
      const ch = [...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,'0')).join('');
      const s = await inv('did_sign_challenge', {did:curDid, password:p, challenge:ch});
      const v = await inv('did_verify', {did:curDid, challenge:ch, sigHex:s.sig_hex});
      $('#idsig').textContent = 'challenge: ' + ch + '\nsig: ' + s.sig_hex.slice(0,48) + '…\nverify: ' + (v.valid ? '✓ VALID' : '✗ INVALID');
      audit('did', 'sign+verify ' + curDid.slice(0,24));
    }catch(e){ $('#idsig').textContent = 'ошибка: ' + (e.message || e); }
  };
})();

/* pqc.js — Этап 21: постквантовый слой QFS Vault (pqc.rs).
   Native-only. Классический AES-GCM путь (vput/vget) остаётся без изменений;
   здесь добавляется гибрид ML-KEM-768 + AES-256-GCM через Rust-команды:
   keygen → seal → open, конверт (kem_ct, nonce, ct) выводится в vmsg. */
(function(){
  const NATIVE = !!(window.__TAURI__ && window.__TAURI__.core);
  if(!NATIVE) return;
  const inv = window.__TAURI__.core.invoke;
  // say/audit — глобальные биндинги inline-скрипта
  let lastEnv = null; // последний запечатанный конверт

  /* Бейдж PQC TAG: SIM → LIVE (в нативной оболочке схемы реальны) */
  (async()=>{
    try{
      const st = await inv('vault_pqc_status');
      const badges = document.querySelectorAll('#v-vault .b.sim');
      badges.forEach(b => { b.textContent = 'PQC TAG: LIVE'; b.className = 'b live'; });
      const note = document.querySelector('#v-vault > div.mono');
      if(note) note.textContent = 'Реальное шифрование: AES-256-GCM, ключ из PBKDF2 (200k итераций) через Web Crypto. ' +
        'Постквантовый слой: ' + st.scheme + ' (NIST Level 3) — команды ниже считаются в Rust.';
    }catch(e){}
  })();

  /* Панель PQC-инструментов внутрь карточки vault */
  const card = document.querySelector('#v-vault');
  if(card){
    const row = document.createElement('div'); row.className = 'row'; row.style.marginTop = '6px';
    const gen = document.createElement('button'); gen.className = 'a'; gen.textContent = 'PQC KEYGEN';
    gen.title = 'vault_pqc_keygen — пара ключей ML-KEM-768; sk показывается один раз';
    const pkIn = document.createElement('input'); pkIn.placeholder = 'pubkey hex (1184 б)'; pkIn.style.flex = '1';
    const skIn = document.createElement('input'); skIn.placeholder = 'privkey hex (2400 б)'; skIn.style.flex = '1';
    const row2 = document.createElement('div'); row2.className = 'row'; row2.style.marginTop = '6px';
    const seal = document.createElement('button'); seal.className = 'a'; seal.textContent = 'PQC SEAL';
    seal.title = 'vault_pqc_seal — текст из vt шифруется для владельца pubkey';
    const open = document.createElement('button'); open.className = 'a'; open.textContent = 'PQC OPEN';
    open.title = 'vault_pqc_open — расшифровать последний конверт privkey';
    const ktIn = document.createElement('input'); ktIn.placeholder = 'kem_ct hex (конверт)'; ktIn.style.flex = '1';

    gen.onclick = async ()=>{
      try{
        const r = await inv('vault_pqc_keygen');
        pkIn.value = r.pk_hex; skIn.value = r.sk_hex;
        $('#vmsg').textContent = 'Пара PQC создана (' + r.scheme + '). Приватный ключ — в поле privkey, сохраните его.';
        say('PQC KEYGEN: pk ' + r.pk_hex.slice(0, 24) + '…', 'var(--live)');
        audit('pqc', 'keygen');
      }catch(e){ $('#vmsg').textContent = 'ошибка keygen: ' + (e.message || e); }
    };
    seal.onclick = async ()=>{
      const text = $('#vt').value;
      if(!text || !pkIn.value.trim()) return $('#vmsg').textContent = 'нужны текст (vt) и pubkey';
      try{
        const r = await inv('vault_pqc_seal', {pkHex:pkIn.value.trim(), text});
        lastEnv = r;
        ktIn.value = r.kem_ct;
        $('#vmsg').textContent = 'Конверт (' + r.scheme + '): kem_ct ' + r.kem_ct.slice(0, 32) + '… nonce ' + r.nonce + ' ct ' + r.ct.slice(0, 32) + '…';
        say('PQC SEAL: ' + r.ct.slice(0, 24) + '…', 'var(--live)');
        audit('pqc', 'seal ' + r.ct.length + ' hex');
      }catch(e){ $('#vmsg').textContent = 'ошибка seal: ' + (e.message || e); }
    };
    open.onclick = async ()=>{
      if(!lastEnv || !skIn.value.trim()) return $('#vmsg').textContent = 'сначала PQC SEAL и укажите privkey';
      try{
        const r = await inv('vault_pqc_open', {
          skHex:skIn.value.trim(), kemCt:lastEnv.kem_ct, nonce:lastEnv.nonce, ct:lastEnv.ct,
        });
        $('#vmsg').textContent = 'Расшифровано: ' + r.text.slice(0, 80);
        say('PQC OPEN: ' + r.text.slice(0, 40), 'var(--live)');
        audit('pqc', 'open ok');
      }catch(e){ $('#vmsg').textContent = 'ошибка open: ' + (e.message || e); }
    };
    row.append(gen, pkIn, skIn);
    row2.append(seal, open, ktIn);
    card.appendChild(row); card.appendChild(row2);
  }
})();

/* wallet.js — Этап 20: REAL-кошелёк через Rust keyring (wallet.rs).
   Native-only: в браузере без Tauri ничего не трогаем (ethers-путь как был).
   Keyring ~/.w420/wallet/keyring.json: мнемоники шифруются AES-256-GCM,
   наружу (во фронтенд) уходят только адреса и подписи — ключи не покидают Rust. */
(function(){
  const NATIVE = !!(window.__TAURI__ && window.__TAURI__.core);
  if(!NATIVE) return;
  const inv = window.__TAURI__.core.invoke;
  // $, say, audit — глобальные биндинги inline-скрипта index.html
  let curAddr = null; // выбранный кошелёк keyring
  const CHAIN = 11155111; // Sepolia testnet first

  const pw = () => $('#kpw').value.trim();
  const err = (e, where) => { say('⚠ ' + where + ': ' + (e && e.message ? e.message : String(e)), 'var(--wip)'); audit('wallet', where + ' error'); };

  /* Проверка keyring при старте: адрес первого кошелька в v-key и v-wallet */
  (async()=>{
    try{
      const note = document.querySelector('#v-key > div.mono');
      if(note) note.textContent = 'Keyring в Rust (мнемоника — AES-256-GCM на диске): NEW/IMPORT/REVEAL/SIGN работают нативно. ' +
        'Баланс и отправка — реальные, JSON-RPC Sepolia, кнопки на вкладке CRYPTO · WALLET. Мнемоника показывается один раз при создании/импорте.';
      const st = await inv('wallet_status');
      const list = await inv('wallet_list');
      if(list.length){
        curAddr = list[0].address;
        $('#kaddr').textContent = list[0].address + '  [' + list[0].label + ']';
        $('#waddr').textContent = list[0].address + '  · keyring ' + st.count + ' · chain ' + st.default_chain_id;
      }else{
        $('#kaddr').textContent = '— keyring пуст: NEW WALLET или IMPORT —';
      }
    }catch(e){ err(e, 'wallet_status'); }
  })();

  /* NEW WALLET: генерирует 24-словную мнемонику, шифрует в keyring */
  $('#kgen').onclick = async ()=>{
    const p = pw();
    if(p.length < 8) return err({message:'пароль минимум 8 символов'}, 'wallet_create');
    try{
      const r = await inv('wallet_create', {password:p, label:'w420'});
      curAddr = r.address;
      $('#kaddr').textContent = r.address;
      $('#kphr').textContent = 'МНЕМОНИКА (один раз!): ' + r.phrase + ' — записышите; в keyring хранится зашифрованной';
      say('кошелёк создан: ' + r.address, 'var(--live)');
      audit('wallet', 'create ' + r.address);
    }catch(e){ err(e, 'wallet_create'); }
  };

  /* IMPORT: существующая мнемоника в keyring */
  $('#kload').onclick = async ()=>{
    const p = pw(), phrase = $('#kimp').value.trim();
    if(!phrase) return err({message:'вставь мнемонику'}, 'wallet_import');
    if(p.length < 8) return err({message:'пароль минимум 8 символов'}, 'wallet_import');
    try{
      const r = await inv('wallet_import', {phrase, password:p, label:'imported'});
      curAddr = r.address;
      $('#kimp').value = '';
      $('#kaddr').textContent = r.address;
      $('#kphr').textContent = 'импортирован: ' + r.address;
      say('импортирован кошелёк: ' + r.address, 'var(--live)');
      audit('wallet', 'import ' + r.address);
    }catch(e){ err(e, 'wallet_import'); }
  };

  /* REVEAL PHRASE: показать мнемонику (нужен пароль keyring) */
  $('#kshow').onclick = async ()=>{
    if(!curAddr) return err({message:'сначала NEW WALLET или IMPORT'}, 'wallet_reveal');
    try{
      const r = await inv('wallet_reveal', {address:curAddr, password:pw()});
      $('#kphr').textContent = 'МНЕМОНИКА: ' + r.phrase;
      audit('wallet', 'reveal ' + curAddr);
    }catch(e){ err(e, 'wallet_reveal'); }
  };

  /* ENCRYPT → VAULT: мнемоника ещё раз шифруется паролем vault (AES-GCM, WebCrypto-путь UI) */
  $('#kvault').onclick = async ()=>{
    if(!curAddr) return err({message:'нет кошелька'}, 'wallet_reveal');
    try{
      const r = await inv('wallet_reveal', {address:curAddr, password:pw()});
      $('#vn').value = 'wallet-mnemonic-' + curAddr.slice(2,8);
      $('#vt').value = r.phrase;
      $('#vp').value = pw();
      $('#vput').click();
      $('#vp').value = '';
      $('#kphr').textContent = 'зашифровано в QFS Vault (AES-GCM) · keyring уже шифрует на диске';
      audit('wallet', 'vault export ' + curAddr);
    }catch(e){ err(e, 'vault export'); }
  };

  /* SIGN: офлайн-подпись legacy-транзакции (EIP-155) в Rust */
  $('#ksign').onclick = async ()=>{
    if(!curAddr) return err({message:'нет кошелька'}, 'wallet_sign_tx');
    const to = $('#kto').value.trim(), value = $('#kval').value.trim() || '0';
    if(!to) return err({message:'укажи to 0x…'}, 'wallet_sign_tx');
    try{
      const r = await inv('wallet_sign_tx', {
        address:curAddr, password:pw(), to, valueEth:value,
        nonce:+$('#knon').value || 0, gasLimit:21000,
        gasPriceGwei:$('#kgas').value || '20', chainId:CHAIN,
      });
      $('#ktx').textContent = 'raw: ' + r.raw + '\nhash: ' + r.hash + '\nНЕ отправлено в сеть (офлайн-подпись).';
      say('подписано: ' + r.hash.slice(0,18) + '…', 'var(--live)');
      audit('wallet', 'sign ' + curAddr + ' → ' + to.slice(0,12));
    }catch(e){ err(e, 'wallet_sign_tx'); }
  };

  /* v-wallet: REAL-контролы сети (testnet) — добавляем кнопки в карточку [SIM] */
  (()=>{
    const card = document.querySelector('#v-wallet .card.sim');
    if(!card) return;
    const row = document.createElement('div'); row.className = 'row'; row.style.marginTop = '6px';
    const bal = document.createElement('button'); bal.className = 'a'; bal.textContent = 'БАЛАНС (RPC)';
    bal.title = 'wallet_balance через JSON-RPC Sepolia';
    bal.onclick = async ()=>{
      if(!curAddr) return $('#wbal').textContent = 'нет ключа — создайте в WALLET · OFFLINE KEYS';
      try{
        const r = await inv('wallet_balance', {address:curAddr});
        $('#wbal').textContent = r.eth + ' ETH  (' + r.wei + ' wei)';
        say('баланс ' + curAddr.slice(0,10) + '…: ' + r.eth + ' ETH', 'var(--live)');
        audit('wallet', 'balance ' + curAddr);
      }catch(e){ $('#wbal').textContent = 'RPC-ошибка: ' + (e.message || e); }
    };
    const snd = document.createElement('button'); snd.className = 'a'; snd.textContent = 'ОТПРАВИТЬ (testnet)';
    snd.title = 'wallet_send — реальная транзакция в Sepolia, нужен пароль keyring';
    snd.onclick = async ()=>{
      if(!curAddr) return $('#wbal').textContent = 'нет ключа';
      const to = $('#wto').value.trim(), val = $('#wamt').value.trim();
      if(!to || !val) return $('#wbal').textContent = 'укажите адрес и сумму';
      if(!confirm('Подтвердите отправку ' + val + ' ETH в ' + to + ' (Sepolia testnet, chain 11155111)')) return;
      try{
        const r = await inv('wallet_send', {address:curAddr, password:pw(), to, valueEth:val, chainId:CHAIN});
        $('#wbal').textContent = 'отправлено: tx ' + r.tx_hash;
        say('tx ' + r.tx_hash.slice(0,18) + '… отправлена', 'var(--live)');
        audit('wallet', 'send ' + val + ' → ' + to.slice(0,12) + ' tx ' + r.tx_hash);
      }catch(e){ $('#wbal').textContent = 'ошибка отправки: ' + (e.message || e); }
    };
    row.append(bal, snd);
    card.appendChild(row);
  })();
})();

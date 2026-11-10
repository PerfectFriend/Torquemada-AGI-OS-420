// Run through tools/tests/run.sh (it prepares /tmp/bt with certificates, keys and a tiny web server root).
const fs=require('fs'),cp=require('child_process');
const C=require(require('path').join(__dirname,'../../app/dist/bridge-config.js'));
const SB=process.env.SINGBOX||require('path').join(__dirname,'../../app/src-tauri/binaries/sing-box-x86_64-unknown-linux-gnu');
const rk=Object.fromEntries(fs.readFileSync('rk.txt','utf8').split('\n').filter(Boolean).map(l=>l.split(': ')));
const wk=f=>Object.fromEntries(fs.readFileSync(f,'utf8').split('\n').filter(Boolean).map(l=>l.split(': ')));
const w1=wk('wk1.txt'),w2=wk('wk2.txt');
const hex=()=>Array.from({length:16},()=>Array.from({length:32},()=>'0123456789abcdef'[Math.floor(Math.random()*16)]).join('')).join('\n');
const uuid='b831381d-6324-4d53-ad4f-8cda48b30811';
const vmessJson=Buffer.from(JSON.stringify({v:'2',ps:'vmess-ws',add:'v.example.com',port:'443',id:uuid,aid:'0',scy:'auto',net:'ws',type:'none',host:'cdn.example.com',path:'/ws',tls:'tls',sni:'cdn.example.com'})).toString('base64');
const ssUser=Buffer.from('aes-256-gcm:pa55word').toString('base64');
const ssLegacy=Buffer.from('chacha20-ietf-poly1305:secret@203.0.113.5:8388').toString('base64');
const links={
 'vless-reality':`vless://${uuid}@203.0.113.1:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=${rk.PublicKey}&sid=6ba85179e30d4fc2&type=tcp&flow=xtls-rprx-vision#Reality`,
 'vless-ws-tls':`vless://${uuid}@v.example.com:443?security=tls&sni=v.example.com&type=ws&path=%2Fvl&host=v.example.com#VLESS-WS`,
 'vless-grpc':`vless://${uuid}@v.example.com:443?security=tls&type=grpc&serviceName=svc#gRPC`,
 'vmess-ws':`vmess://${vmessJson}`,
 'trojan':`trojan://secretpw@203.0.113.2:443?sni=t.example.com&type=ws&path=%2Ftr&host=t.example.com#Trojan-WS`,
 'ss-sip002':`ss://${ssUser}@203.0.113.3:8388#SS`,
 'ss-legacy':`ss://${ssLegacy}#SSlegacy`,
 'hy2':`hysteria2://hy2pass@203.0.113.4:443?sni=h.example.com&obfs=salamander&obfs-password=obfspw#Hy2`,
 'tuic':`tuic://${uuid}:tuicpw@203.0.113.6:443?sni=tu.example.com&congestion_control=bbr&alpn=h3#TUIC`,
 'anytls':`anytls://atpw@203.0.113.7:443?sni=a.example.com#AnyTLS`,
 'socks5':`socks5://user:pw@203.0.113.8:1080#SOCKS`,
};
const wg=`[Interface]\nPrivateKey = ${w1.PrivateKey}\nAddress = 10.7.0.2/32, fd00::2/128\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = ${w2.PublicKey}\nEndpoint = 203.0.113.9:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;
const ovpn=`client\ndev tun\nproto udp\nremote 203.0.113.10 1194\nremote 203.0.113.11 443 tcp\ncipher AES-256-GCM\nauth SHA256\nremote-cert-tls server\nauth-user-pass\nkey-direction 1\n<ca>\n${fs.readFileSync('ca.crt','utf8')}</ca>\n<cert>\n${fs.readFileSync('cl.crt','utf8')}</cert>\n<key>\n${fs.readFileSync('cl.key','utf8')}</key>\n<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\n${hex()}\n-----END OpenVPN Static key V1-----\n</tls-auth>\n`;
let pass=0,fail=0;const ok=(c,m)=>{console.log((c?'PASS ':'FAIL ')+m);c?pass++:fail++};
function check(cfg,label){fs.writeFileSync('/tmp/bt/cfg.json',JSON.stringify(cfg,null,1));const r=cp.spawnSync(SB,['check','-c','/tmp/bt/cfg.json'],{encoding:'utf8'});ok(r.status===0,'sing-box check: '+label+(r.status?'\n   '+(r.stderr||r.stdout).trim().split('\n').slice(0,3).join('\n   '):''));return r.status===0}
const profiles={};
for(const [k,l] of Object.entries(links)){try{profiles[k]=C.parseLink(l)}catch(e){ok(false,'parse '+k+': '+e.message)}}
profiles.wg=C.parseWireGuardConf(wg,'WG');
profiles.ovpn=C.parseOvpn(ovpn,'OVPN',{username:'u',password:'p'});
ok(profiles.ovpn.needsAuth===false&&profiles['ovpn'].singbox.servers.length===2,'ovpn: 2 remotes -> servers[], creds applied');
ok(C.parseOvpn(ovpn,'x').needsAuth===true,'ovpn: auth-user-pass without creds -> needsAuth');
ok(profiles.ovpn.singbox.tls.control_wrap.direction==='client'&&profiles.ovpn.singbox.tls.control_wrap.type==='tls_auth','ovpn: key-direction 1 -> tls_auth client');
ok(profiles['ss-legacy'].singbox.server==='203.0.113.5'&&profiles['ss-legacy'].singbox.method==='chacha20-ietf-poly1305','ss legacy base64(all) parsed');
ok(profiles['vless-reality'].singbox.tls.reality.public_key===rk.PublicKey&&profiles['vless-reality'].singbox.packet_encoding==='xudp','vless reality fields');
// every single profile in proxy mode
for(const [k,p] of Object.entries(profiles)) check(C.buildConfig([p],{mode:'proxy'}),'proxy mode / '+k);
// all together, each mode
const all=Object.values(profiles);
check(C.buildConfig(all,{mode:'proxy'}),'ALL profiles (urltest) proxy mode');
check(C.buildConfig(all,{mode:'tun'}),'ALL profiles TUN mode (kill-switch)');
check(C.buildConfig(all,{mode:'proxy',failover:'selector'}),'ALL profiles selector');
check(C.buildConfig(all.filter(p=>p.kind==='outbound'),{mode:'tun',via:'tor'}),'outbounds chained through Tor (VPN over Tor), TUN');
check(C.buildConfig([],{mode:'tun',via:'tor'}),'Tor only, TUN (fakeip DNS)');
check(C.buildConfig([],{mode:'proxy',via:'tor'}),'Tor only, proxy');
let err='';try{C.buildConfig([],{mode:'proxy'})}catch(e){err=e.message}ok(/Нет ни одного профиля/.test(err),'no profiles -> readable error');
// subscription base64 + bad lines
const sub=Buffer.from(Object.values(links).slice(0,4).join('\n')+'\nnonsense\n').toString('base64');
const ps=C.parseProfiles(sub);ok(ps.ok.length===4&&ps.bad.length===1,'subscription (base64): 4 ok, 1 bad reported');
err='';try{C.parseLink('ss://'+ssUser+'@h:1?plugin=obfs-local')}catch(e){err=e.message}ok(/plugin/.test(err),'ss plugin -> explicit unsupported error');
console.log(`\n${pass}/${pass+fail} passed`);process.exit(fail?1:0);

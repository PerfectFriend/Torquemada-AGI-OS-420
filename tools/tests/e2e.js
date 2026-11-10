// Run through tools/tests/run.sh (it prepares /tmp/bt with certificates, keys and a tiny web server root).
const fs=require('fs'),cp=require('child_process'),net=require('net');
const C=require(require('path').join(__dirname,'../../app/dist/bridge-config.js'));
const SB=process.env.SINGBOX||require('path').join(__dirname,'../../app/src-tauri/binaries/sing-box-x86_64-unknown-linux-gnu');
const uuid='b831381d-6324-4d53-ad4f-8cda48b30811',expect=fs.readFileSync('www/index.html','utf8');
const kp=()=>Object.fromEntries(cp.execFileSync(SB,['generate','wg-keypair'],{encoding:'utf8'}).split('\n').filter(Boolean).map(l=>l.split(': ')));
const wgS=kp(),wgC=kp();
const tls={enabled:true,certificate_path:'/tmp/bt/srv.crt',key_path:'/tmp/bt/srv.key'};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const waitPort=async(p,udp)=>{for(let i=0;i<40;i++){if(udp){await sleep(250);if(i>3)return true;continue}const ok=await new Promise(r=>{const s=net.connect(p,'127.0.0.1');s.on('connect',()=>{s.destroy();r(true)});s.on('error',()=>r(false))});if(ok)return true;await sleep(100)}return false};
const cases=[
 {n:'shadowsocks aes-256-gcm',srv:{type:'shadowsocks',listen:'127.0.0.1',method:'aes-256-gcm',password:'pw'},link:p=>`ss://${Buffer.from('aes-256-gcm:pw').toString('base64')}@127.0.0.1:${p}#ss`},
 {n:'vmess tcp',srv:{type:'vmess',listen:'127.0.0.1',users:[{uuid}]},link:p=>'vmess://'+Buffer.from(JSON.stringify({ps:'vm',add:'127.0.0.1',port:String(p),id:uuid,aid:'0',net:'tcp'})).toString('base64')},
 {n:'vless over websocket',srv:{type:'vless',listen:'127.0.0.1',users:[{uuid}],transport:{type:'ws',path:'/vl'}},link:p=>`vless://${uuid}@127.0.0.1:${p}?type=ws&path=%2Fvl&security=none#vl`},
 {n:'trojan over TLS',srv:{type:'trojan',listen:'127.0.0.1',users:[{password:'pw'}],tls},link:p=>`trojan://pw@127.0.0.1:${p}?sni=localhost&allowInsecure=1#tj`},
 {n:'hysteria2 (QUIC/UDP)',udp:1,srv:{type:'hysteria2',listen:'127.0.0.1',users:[{password:'pw'}],tls:{...tls,alpn:['h3']}},link:p=>`hysteria2://pw@127.0.0.1:${p}?sni=localhost&insecure=1#hy2`},
 {n:'tuic (QUIC/UDP)',udp:1,srv:{type:'tuic',listen:'127.0.0.1',users:[{uuid,password:'pw'}],congestion_control:'bbr',tls:{...tls,alpn:['h3']}},link:p=>`tuic://${uuid}:pw@127.0.0.1:${p}?sni=localhost&allow_insecure=1#tuic`},
 {n:'anytls',srv:{type:'anytls',listen:'127.0.0.1',users:[{password:'pw'}],tls},link:p=>`anytls://pw@127.0.0.1:${p}?sni=localhost&insecure=1#at`},
 {n:'socks5 upstream',srv:{type:'socks',listen:'127.0.0.1',users:[{username:'u',password:'p'}]},link:p=>`socks5://u:p@127.0.0.1:${p}#s5`},
];
let pass=0,fail=0;const ok=(c,m)=>{console.log((c?'PASS ':'FAIL ')+m);c?pass++:fail++};
const procs=[];const spawn=(cfg,name)=>{fs.writeFileSync(`/tmp/bt/${name}.json`,JSON.stringify(cfg));const p=cp.spawn(SB,['run','-c',`/tmp/bt/${name}.json`],{stdio:['ignore','pipe','pipe']});let log='';p.stdout.on('data',d=>log+=d);p.stderr.on('data',d=>log+=d);p.getLog=()=>log;procs.push(p);return p};
const curl=(proxy,url)=>{const r=cp.spawnSync('curl',['-s','-m','6','--socks5-hostname',proxy,url],{encoding:'utf8'});return r.stdout};
(async()=>{
 const web=cp.spawn('python3',['-m','http.server','8099','--bind','127.0.0.1','--directory','/tmp/bt/www'],{stdio:'ignore'});procs.push(web);await waitPort(8099);
 ok(cp.spawnSync('curl',['-s','-m','4','http://127.0.0.1:8099/'],{encoding:'utf8'}).stdout===expect,'test web server up');
 let base=21000;
 for(const c of cases){const sp=base++,cp_=base++;
  const srv=spawn({log:{level:'warn'},inbounds:[{...c.srv,tag:'in',listen_port:sp}],outbounds:[{type:'direct'}]},'srv');
  await waitPort(sp,c.udp);
  let prof;try{prof=C.parseLink(c.link(sp))}catch(e){ok(false,c.n+': parse '+e.message);srv.kill();continue}
  const cfg=C.buildConfig([prof],{mode:'proxy',port:cp_,bypassPrivate:false,logLevel:'warn'});
  const cli=spawn(cfg,'cli');await waitPort(cp_);await sleep(c.udp?800:200);
  const got=curl(`127.0.0.1:${cp_}`,'http://127.0.0.1:8099/');
  ok(got===expect,c.n+': traffic passed through the tunnel'+(got===expect?'':' (got '+JSON.stringify(got.slice(0,40))+'; '+(cli.getLog()||srv.getLog()).trim().split('\n').slice(-2).join(' | ').slice(0,200)+')'));
  if(got===expect){srv.kill('SIGKILL');await sleep(400);const dead=curl(`127.0.0.1:${cp_}`,'http://127.0.0.1:8099/');ok(dead!==expect,c.n+': server killed -> no direct leak (request fails)')}
  cli.kill('SIGKILL');srv.kill('SIGKILL');await sleep(300);
 }
 // WireGuard has its own test (wg.js): it needs a tunnel-internal destination address.
 procs.forEach(p=>{try{p.kill('SIGKILL')}catch{}});
 console.log(`\n${pass}/${pass+fail} passed`);process.exit(fail?1:0);
})();

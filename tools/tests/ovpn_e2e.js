// Run through tools/tests/run.sh (it prepares /tmp/bt with certificates, keys and a tiny web server root).
const fs=require('fs'),cp=require('child_process');
const C=require(require('path').join(__dirname,'../../app/dist/bridge-config.js'));
const SB=process.env.SINGBOX||require('path').join(__dirname,'../../app/src-tauri/binaries/sing-box-x86_64-unknown-linux-gnu');
const expect=fs.readFileSync('www/index.html','utf8'),sleep=ms=>new Promise(r=>setTimeout(r,ms));
const rd=f=>fs.readFileSync(f,'utf8').trim();
const hex=()=>'-----BEGIN OpenVPN Static key V1-----\n'+Array.from({length:16},()=>Array.from({length:32},()=>'0123456789abcdef'[Math.floor(Math.random()*16)]).join('')).join('\n')+'\n-----END OpenVPN Static key V1-----';
const key=hex(),lines=s=>s.split('\n');
const run=(cfg,n)=>{fs.writeFileSync(`/tmp/bt/${n}.json`,JSON.stringify(cfg));const p=cp.spawn(SB,['run','-c',`/tmp/bt/${n}.json`]);let l='';p.stdout.on('data',d=>l+=d);p.stderr.on('data',d=>l+=d);p.log=()=>l.replace(/\x1b\[[0-9;]*m/g,'');return p};
(async()=>{
 const web=cp.spawn('python3',['-m','http.server','8099','--bind','127.0.0.1','--directory','/tmp/bt/www'],{stdio:'ignore'});await sleep(500);
 const srv=run({log:{level:'debug'},endpoints:[{type:'openvpn-server',tag:'ovpn-in',listen:'127.0.0.1',listen_port:23001,network:'udp',address:['10.8.0.1/24'],
   tls:{certificate:lines(rd('ov_s.crt')),key:lines(rd('ov_s.key')),client_certificate:lines(rd('ca.crt')),control_wrap:{type:'tls_crypt',key:lines(key)}},
   data_ciphers:['AES-256-GCM']}],outbounds:[{type:'direct',tag:'direct'}],route:{rules:[{ip_cidr:['10.8.0.1/32'],action:'route-options',override_address:'127.0.0.1'}],final:'direct'}},'srv');
 await sleep(1500);
 const ovpn=`client\ndev tun\nproto udp\nremote 127.0.0.1 23001\ncipher AES-256-GCM\nremote-cert-tls server\n<ca>\n${rd('ca.crt')}\n</ca>\n<cert>\n${rd('ov_c.crt')}\n</cert>\n<key>\n${rd('ov_c.key')}\n</key>\n<tls-crypt>\n${key}\n</tls-crypt>\n`;
 const prof=C.parseOvpn(ovpn,'ovpn');
 const cfg=C.buildConfig([prof],{mode:'proxy',port:23002,bypassPrivate:false,logLevel:'debug'});cfg.route.auto_detect_interface=false;
 const cli=run(cfg,'cli');await sleep(3500);
 const got=cp.spawnSync('curl',['-s','-m','8','--socks5-hostname','127.0.0.1:23002','http://10.8.0.1:8099/'],{encoding:'utf8'}).stdout;
 console.log(got===expect?'PASS openvpn (.ovpn -> sing-box openvpn-client): traffic passed through the tunnel':'FAIL openvpn, got: '+JSON.stringify(got.slice(0,50)));
 if(got!==expect){console.log('--- client ---\n'+cli.log().split('\n').filter(l=>/openvpn|error|fail|tls|auth/i.test(l)).slice(-8).join('\n'));console.log('--- server ---\n'+srv.log().split('\n').filter(l=>/openvpn|error|fail|tls|auth/i.test(l)).slice(-8).join('\n'))}
 [cli,srv,web].forEach(p=>p.kill('SIGKILL'));process.exit(got===expect?0:1);
})();

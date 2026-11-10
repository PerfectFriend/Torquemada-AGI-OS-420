// Run through tools/tests/run.sh (it prepares /tmp/bt with certificates, keys and a tiny web server root).
const fs=require('fs'),cp=require('child_process');
const C=require(require('path').join(__dirname,'../../app/dist/bridge-config.js'));
const SB=process.env.SINGBOX||require('path').join(__dirname,'../../app/src-tauri/binaries/sing-box-x86_64-unknown-linux-gnu'),sleep=ms=>new Promise(r=>setTimeout(r,ms)),rd=f=>fs.readFileSync(f,'utf8').trim();
const key='-----BEGIN OpenVPN Static key V1-----\n'+Array.from({length:16},()=>Array.from({length:32},()=>'0123456789abcdef'[Math.floor(Math.random()*16)]).join('')).join('\n')+'\n-----END OpenVPN Static key V1-----';
fs.writeFileSync('/tmp/bt/tc.key',key+'\n');
(async()=>{
 const base=['--local','127.0.0.1','--port','23101','--proto','udp','--ca','/tmp/bt/ca.crt','--cert','/tmp/bt/ov_s.crt','--key','/tmp/bt/ov_s.key','--dh','none','--tls-crypt','/tmp/bt/tc.key','--data-ciphers','AES-256-GCM','--verb','4','--dev','tun','--server','10.8.0.0','255.255.255.0','--ifconfig-noexec','--route-noexec','--verify-client-cert','require','--remote-cert-tls','client'];
 const srv=cp.spawn('openvpn',base);let sl='';srv.stdout.on('data',d=>sl+=d);srv.stderr.on('data',d=>sl+=d);await sleep(1500);
 console.log('openvpn server up:',/Initialization Sequence Completed/.test(sl)?'yes':'check log: '+sl.trim().split('\n').slice(-2).join(' | '));
 const ovpn=`client\ndev tun\nproto udp\nremote 127.0.0.1 23101\ncipher AES-256-GCM\nremote-cert-tls server\n<ca>\n${rd('ca.crt')}\n</ca>\n<cert>\n${rd('ov_c.crt')}\n</cert>\n<key>\n${rd('ov_c.key')}\n</key>\n<tls-crypt>\n${key}\n</tls-crypt>\n`;
 const cfg=C.buildConfig([C.parseOvpn(ovpn,'real')],{mode:'proxy',port:23102,bypassPrivate:false,logLevel:'debug'});cfg.route.auto_detect_interface=false;
 fs.writeFileSync('/tmp/bt/cli.json',JSON.stringify(cfg));const cli=cp.spawn(SB,['run','-c','/tmp/bt/cli.json']);let cl='';cli.stdout.on('data',d=>cl+=d);cli.stderr.on('data',d=>cl+=d);
 await sleep(5000);
 const ok1=/Peer Connection Initiated with \[AF_INET\]127\.0\.0\.1/.test(sl),ok2=/PUSH_REQUEST|SENT CONTROL \[client1\].*PUSH_REPLY|PUSH_REPLY/.test(sl),ok3=/Data Channel: cipher 'AES-256-GCM'/.test(sl);
 console.log((ok1?'PASS':'FAIL')+' real openvpn server: TLS handshake with sing-box client, peer connection initiated');
 console.log((ok2?'PASS':'FAIL')+' real openvpn server: client got PUSH_REPLY (config negotiated)');
 console.log((ok3?'PASS':'FAIL')+' real openvpn server: data channel cipher AES-256-GCM negotiated');
 if(!(ok1&&ok2&&ok3)){console.log('--- server log tail ---\n'+sl.trim().split('\n').slice(-10).join('\n'));console.log('--- client log tail ---\n'+cl.replace(/\x1b\[[0-9;]*m/g,'').trim().split('\n').slice(-6).join('\n'))}
 cli.kill('SIGKILL');srv.kill('SIGKILL');process.exit(ok1&&ok2&&ok3?0:1);
})();

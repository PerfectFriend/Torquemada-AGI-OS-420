// Run through tools/tests/run.sh (it prepares /tmp/bt with certificates, keys and a tiny web server root).
const fs=require('fs'),cp=require('child_process'),net=require('net');
const C=require(require('path').join(__dirname,'../../app/dist/bridge-config.js'));
const SB=process.env.SINGBOX||require('path').join(__dirname,'../../app/src-tauri/binaries/sing-box-x86_64-unknown-linux-gnu');
const expect=fs.readFileSync('www/index.html','utf8');
const kp=()=>Object.fromEntries(cp.execFileSync(SB,['generate','wg-keypair'],{encoding:'utf8'}).split('\n').filter(Boolean).map(l=>l.split(': ')));
const S=kp(),K=kp(),sleep=ms=>new Promise(r=>setTimeout(r,ms));
const run=(cfg,n)=>{fs.writeFileSync(`/tmp/bt/${n}.json`,JSON.stringify(cfg));const p=cp.spawn(SB,['run','-c',`/tmp/bt/${n}.json`]);let l='';p.stdout.on('data',d=>l+=d);p.stderr.on('data',d=>l+=d);p.log=()=>l.replace(/\x1b\[[0-9;]*m/g,'');return p};
(async()=>{
 const web=cp.spawn('python3',['-m','http.server','8099','--bind','127.0.0.1','--directory','/tmp/bt/www'],{stdio:'ignore'});await sleep(500);
 // client talks to the server's tunnel address; the server rewrites it to the local web server
 const srv=run({log:{level:'debug'},endpoints:[{type:'wireguard',tag:'wg-in',address:['10.7.0.1/32'],private_key:S.PrivateKey,listen_port:22001,peers:[{public_key:K.PublicKey,allowed_ips:['10.7.0.2/32']}]}],outbounds:[{type:'direct',tag:'direct'}],route:{rules:[{ip_cidr:['10.7.0.1/32'],action:'route-options',override_address:'127.0.0.1'}],final:'direct'}},'srv');
 await sleep(1200);
 const conf=`[Interface]\nPrivateKey = ${K.PrivateKey}\nAddress = 10.7.0.2/32\n[Peer]\nPublicKey = ${S.PublicKey}\nEndpoint = 127.0.0.1:22001\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 5\n`;
 const cfg=C.buildConfig([C.parseWireGuardConf(conf,'wg')],{mode:'proxy',port:22002,bypassPrivate:false,logLevel:'debug'});
 cfg.route.auto_detect_interface=false;const cli=run(cfg,'cli');await sleep(2000);
 const vr=cp.spawnSync('curl',['-sv','-m','8','--socks5-hostname','127.0.0.1:22002','http://10.7.0.1:8099/'],{encoding:'utf8'});console.log('curl -v tail:',(vr.stderr||'').trim().split('\n').slice(-4).join(' | '));
 const got=cp.spawnSync('curl',['-s','-m','8','--socks5-hostname','127.0.0.1:22002','http://10.7.0.1:8099/'],{encoding:'utf8'}).stdout;
 console.log(got===expect?'PASS wireguard (userspace): traffic passed through the tunnel':'FAIL wireguard, got: '+JSON.stringify(got.slice(0,50)));
 if(got!==expect){console.log('--- client log ---\n'+cli.log().split('\n').slice(-8).join('\n'));console.log('--- server log ---\n'+srv.log().split('\n').slice(-8).join('\n'))}
 [cli,srv,web].forEach(p=>p.kill('SIGKILL'));process.exit(got===expect?0:1);
})();

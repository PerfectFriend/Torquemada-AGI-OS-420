/* W420 BRIDGE config generator: share links / WireGuard / OpenVPN files -> sing-box 1.14 config.
   Pure functions (unit-tested in node against the real sing-box binary). */
(function () {
  var te = typeof TextDecoder !== 'undefined' ? new TextDecoder() : null;
  function b64dec(s) {
    s = String(s).trim().replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '=';
    var bin = typeof atob === 'function' ? atob(s) : Buffer.from(s, 'base64').toString('binary');
    var u = Uint8Array.from(bin, function (c) { return c.charCodeAt(0); });
    return te ? te.decode(u) : Buffer.from(u).toString('utf8');
  }
  var q = function (u, k, d) { var v = u.searchParams.get(k); return v == null || v === '' ? d : v; };
  var truthy = function (v) { return v === '1' || v === 'true' || v === 'True'; };
  var nameOf = function (u, d) { return u.hash ? decodeURIComponent(u.hash.slice(1)) : d; };
  var port = function (u, d) { return parseInt(u.port, 10) || d; };

  function tlsFrom(u, host, opts) {
    var sec = q(u, 'security', opts.defaultSec || 'none');
    if (sec === 'none' && !opts.force) return undefined;
    var t = { enabled: true, server_name: q(u, 'sni', q(u, 'peer', q(u, 'host', host))) };
    if (truthy(q(u, 'allowInsecure', q(u, 'insecure', '0')))) t.insecure = true;
    var alpn = q(u, 'alpn'); if (alpn) t.alpn = alpn.split(',');
    var fp = q(u, 'fp'); if (fp || sec === 'reality') t.utls = { enabled: true, fingerprint: fp || 'chrome' };
    if (sec === 'reality') t.reality = { enabled: true, public_key: q(u, 'pbk', ''), short_id: q(u, 'sid', '') };
    return t;
  }
  function transportFrom(u) {
    var type = q(u, 'type', 'tcp'), path = q(u, 'path', '/'), host = q(u, 'host');
    if (type === 'ws') { var w = { type: 'ws', path: path }; if (host) w.headers = { Host: host }; return w; }
    if (type === 'grpc') return { type: 'grpc', service_name: q(u, 'serviceName', '') };
    if (type === 'http' || type === 'h2') { var h = { type: 'http', path: path }; if (host) h.host = host.split(','); return h; }
    if (type === 'httpupgrade') { var g = { type: 'httpupgrade', path: path }; if (host) g.host = host; return g; }
    return undefined;
  }
  function clean(o) { Object.keys(o).forEach(function (k) { if (o[k] === undefined) delete o[k]; }); return o; }

  function parseLink(link) {
    link = String(link).trim(); var m = /^([a-z0-9+.-]+):\/\//i.exec(link); if (!m) throw new Error('Не похоже на ссылку профиля');
    var scheme = m[1].toLowerCase();
    if (scheme === 'vmess') {
      var j = JSON.parse(b64dec(link.slice(8))), net = j.net || 'tcp', tr;
      if (net === 'ws') { tr = { type: 'ws', path: j.path || '/' }; if (j.host) tr.headers = { Host: j.host }; }
      else if (net === 'grpc') tr = { type: 'grpc', service_name: j.path || '' };
      else if (net === 'h2') tr = clean({ type: 'http', path: j.path || '/', host: j.host ? j.host.split(',') : undefined });
      else if (net === 'httpupgrade') tr = clean({ type: 'httpupgrade', path: j.path || '/', host: j.host || undefined });
      var tls; if (j.tls === 'tls') { tls = { enabled: true, server_name: j.sni || j.host || j.add }; if (j.alpn) tls.alpn = String(j.alpn).split(','); if (j.fp) tls.utls = { enabled: true, fingerprint: j.fp }; }
      return { name: j.ps || j.add, kind: 'outbound', singbox: clean({ type: 'vmess', server: j.add, server_port: parseInt(j.port, 10), uuid: j.id, alter_id: parseInt(j.aid, 10) || 0, security: j.scy || 'auto', tls: tls, transport: tr }) };
    }
    var u = new URL(link), host = u.hostname.replace(/^\[|\]$/g, ''), user = decodeURIComponent(u.username), pass = decodeURIComponent(u.password);
    if (scheme === 'vless') {
      var o = { type: 'vless', server: host, server_port: port(u, 443), uuid: user, flow: q(u, 'flow'), tls: tlsFrom(u, host, {}), transport: transportFrom(u) };
      if (o.tls && o.tls.reality || q(u, 'packetEncoding') === 'xudp') o.packet_encoding = 'xudp';
      return { name: nameOf(u, host), kind: 'outbound', singbox: clean(o) };
    }
    if (scheme === 'trojan') return { name: nameOf(u, host), kind: 'outbound', singbox: clean({ type: 'trojan', server: host, server_port: port(u, 443), password: user, tls: tlsFrom(u, host, { defaultSec: 'tls' }), transport: transportFrom(u) }) };
    if (scheme === 'ss') {
      var rest = link.slice(5).split('#')[0], method, password, srv, sp;
      if (rest.indexOf('@') < 0) { var d = b64dec(rest.split('?')[0]); var at = d.lastIndexOf('@'); var mp = d.slice(0, at), hp = d.slice(at + 1); method = mp.slice(0, mp.indexOf(':')); password = mp.slice(mp.indexOf(':') + 1); srv = hp.slice(0, hp.lastIndexOf(':')); sp = hp.slice(hp.lastIndexOf(':') + 1); }
      else { var ui = decodeURIComponent(u.username), dec = ui.indexOf(':') >= 0 ? ui : b64dec(ui); method = dec.slice(0, dec.indexOf(':')); password = dec.slice(dec.indexOf(':') + 1) || pass; srv = host; sp = u.port; }
      if (q(u, 'plugin')) throw new Error('Shadowsocks с plugin (obfs/v2ray-plugin) не поддерживается: используйте VLESS/Trojan с TLS или Hysteria2');
      return { name: nameOf(u, srv), kind: 'outbound', singbox: { type: 'shadowsocks', server: srv, server_port: parseInt(sp, 10), method: method, password: password } };
    }
    if (scheme === 'hysteria2' || scheme === 'hy2') {
      var h2 = { type: 'hysteria2', server: host, server_port: port(u, 443), password: pass ? user + ':' + pass : user, tls: { enabled: true, server_name: q(u, 'sni', host), alpn: ['h3'] } };
      if (truthy(q(u, 'insecure', '0'))) h2.tls.insecure = true;
      if (q(u, 'obfs')) h2.obfs = { type: q(u, 'obfs'), password: q(u, 'obfs-password', '') };
      return { name: nameOf(u, host), kind: 'outbound', singbox: h2 };
    }
    if (scheme === 'tuic') return { name: nameOf(u, host), kind: 'outbound', singbox: clean({ type: 'tuic', server: host, server_port: port(u, 443), uuid: user, password: pass, congestion_control: q(u, 'congestion_control', 'bbr'), udp_relay_mode: q(u, 'udp_relay_mode', 'native'), tls: { enabled: true, server_name: q(u, 'sni', host), alpn: (q(u, 'alpn', 'h3')).split(','), insecure: truthy(q(u, 'allow_insecure', '0')) || undefined } }) };
    if (scheme === 'anytls') return { name: nameOf(u, host), kind: 'outbound', singbox: { type: 'anytls', server: host, server_port: port(u, 443), password: user, tls: { enabled: true, server_name: q(u, 'sni', host), insecure: truthy(q(u, 'insecure', '0')) || undefined } } };
    if (scheme === 'socks5' || scheme === 'socks') return { name: nameOf(u, host), kind: 'outbound', singbox: clean({ type: 'socks', server: host, server_port: port(u, 1080), username: user || undefined, password: pass || undefined, version: '5' }) };
    if (scheme === 'http' || scheme === 'https') return { name: nameOf(u, host), kind: 'outbound', singbox: clean({ type: 'http', server: host, server_port: port(u, scheme === 'https' ? 443 : 8080), username: user || undefined, password: pass || undefined, tls: scheme === 'https' ? { enabled: true, server_name: host } : undefined }) };
    throw new Error('Неизвестная схема: ' + scheme + '://');
  }

  function parseWireGuardConf(text, name) {
    var sec = null, I = {}, peers = [], P = null;
    String(text).split(/\r?\n/).forEach(function (raw) {
      var l = raw.replace(/[#;].*$/, '').trim(); if (!l) return;
      var h = /^\[(\w+)\]$/.exec(l); if (h) { sec = h[1].toLowerCase(); if (sec === 'peer') { P = {}; peers.push(P); } return; }
      var i = l.indexOf('='); if (i < 0) return; var k = l.slice(0, i).trim().toLowerCase(), v = l.slice(i + 1).trim();
      (sec === 'interface' ? I : P || {})[k] = v;
    });
    if (!I.privatekey || !peers.length) throw new Error('В конфиге WireGuard нет PrivateKey или Peer');
    var list = function (v) { return String(v || '').split(',').map(function (x) { return x.trim(); }).filter(Boolean); };
    var ep = {
      type: 'wireguard', address: list(I.address), private_key: I.privatekey, mtu: I.mtu ? parseInt(I.mtu, 10) : undefined,
      peers: peers.map(function (p) {
        var e = p.endpoint || '', i = e.lastIndexOf(':');
        return clean({ address: e.slice(0, i).replace(/^\[|\]$/g, ''), port: parseInt(e.slice(i + 1), 10), public_key: p.publickey, pre_shared_key: p.presharedkey, allowed_ips: list(p.allowedips).length ? list(p.allowedips) : ['0.0.0.0/0', '::/0'], persistent_keepalive_interval: p.persistentkeepalive ? parseInt(p.persistentkeepalive, 10) : undefined });
      })
    };
    return { name: name || 'WireGuard', kind: 'endpoint', singbox: clean(ep) };
  }

  function parseOvpn(text, name, creds) {
    var blocks = {}; var body = String(text).replace(/<(ca|cert|key|tls-auth|tls-crypt|tls-crypt-v2|secret)>([\s\S]*?)<\/\1>/g, function (_, t, c) { blocks[t] = c.trim().split(/\r?\n/).map(function (x) { return x.trim(); }).filter(Boolean); return ''; });
    var remotes = [], opt = {};
    body.split(/\r?\n/).forEach(function (raw) {
      var l = raw.replace(/^\s*[#;].*$/, '').trim(); if (!l) return; var t = l.split(/\s+/), k = t[0];
      if (k === 'remote') remotes.push({ server: t[1], server_port: parseInt(t[2], 10) || 1194, proto: t[3] });
      else opt[k] = t.slice(1);
    });
    if (!remotes.length) throw new Error('В .ovpn нет строки remote');
    var proto = (opt.proto && opt.proto[0] || 'udp').replace(/[46]?(-client)?$/, ''); proto = proto.indexOf('tcp') === 0 ? 'tcp' : 'udp';
    var ep = { type: 'openvpn-client', mode: 'tls', network: proto, tls: {} };
    var srv = remotes.map(function (r) { var n = r.proto ? (r.proto.indexOf('tcp') === 0 ? 'tcp' : 'udp') : proto; return { server: r.server, server_port: r.server_port, network: n }; });
    if (srv.length === 1) { ep.server = srv[0].server; ep.server_port = srv[0].server_port; } else ep.servers = srv;
    if (!blocks.ca) throw new Error('В .ovpn нет блока <ca>: вложите сертификат в файл или укажите отпечаток вручную');
    ep.tls.certificate = blocks.ca; if (blocks.cert) ep.tls.client_certificate = blocks.cert; if (blocks.key) ep.tls.client_key = blocks.key;
    var kd = opt['key-direction'] ? opt['key-direction'][0] : undefined;
    ['tls-auth', 'tls-crypt', 'tls-crypt-v2'].forEach(function (w) { if (blocks[w]) { ep.tls.control_wrap = { type: w.replace(/-/g, '_'), key: blocks[w] }; if (w === 'tls-auth' && kd !== undefined) ep.tls.control_wrap.direction = kd === '0' ? 'server' : 'client'; } });
    if (opt['remote-cert-tls']) ep.tls.remote_certificate_tls = opt['remote-cert-tls'][0];
    var dc = opt['data-ciphers'] || opt['ncp-ciphers']; if (dc) ep.data_ciphers = dc[0].split(':');
    if (opt.cipher) { ep.data_ciphers_fallback = opt.cipher[0]; if (!ep.data_ciphers && /GCM|CHACHA/i.test(opt.cipher[0])) ep.data_ciphers = [opt.cipher[0]]; }  // TLS mode: `cipher` is only the fallback
    if (opt.auth) ep.auth = opt.auth[0];
    if (opt.compress) ep.compression = opt.compress[0] || 'stub-v2'; if (opt['comp-lzo']) ep.compression_lzo = opt['comp-lzo'][0] || 'adaptive';
    if (opt['tun-mtu']) ep.mtu = parseInt(opt['tun-mtu'][0], 10);
    var needsAuth = !!opt['auth-user-pass'];
    if (needsAuth && creds && creds.username) { ep.username = creds.username; ep.password = creds.password || ''; }
    return { name: name || remotes[0].server, kind: 'endpoint', singbox: ep, needsAuth: needsAuth && !(creds && creds.username) };
  }

  function parseProfiles(text) { // many links at once, or a base64 subscription
    var t = String(text).trim(), lines = t.split(/\r?\n/).map(function (x) { return x.trim(); }).filter(Boolean);
    if (lines.length === 1 && !/^[a-z0-9+.-]+:\/\//i.test(lines[0]) && !/[\[\s]/.test(lines[0])) { try { lines = b64dec(lines[0]).split(/\r?\n/).map(function (x) { return x.trim(); }).filter(Boolean); } catch (e) {} }
    var ok = [], bad = [];
    lines.forEach(function (l) { try { ok.push(parseLink(l)); } catch (e) { bad.push({ line: l.slice(0, 40), error: e.message }); } });
    return { ok: ok, bad: bad };
  }

  /* opts: mode 'proxy'|'tun', via 'direct'|'tor', port, torPort, failover 'urltest'|'selector', bypassPrivate, strict, bootstrap, remoteDns, logLevel */
  function buildConfig(profiles, o) {
    o = Object.assign({ mode: 'proxy', via: 'direct', port: 2080, torPort: 9150, failover: 'urltest', bypassPrivate: true, strict: true, bootstrap: '1.1.1.1', remoteDns: '1.1.1.1', logLevel: 'warn' }, o || {});
    var outbounds = [], endpoints = [], tags = [], used = {};
    profiles.forEach(function (p, i) {
      var base = (p.name || p.singbox.type).replace(/[^\w.\- ]+/g, '').slice(0, 30) || p.singbox.type, tag = base, n = 1;
      while (used[tag]) tag = base + '-' + (++n); used[tag] = 1;
      var cfg = Object.assign({}, p.singbox, { tag: tag });
      if (o.via === 'tor' && p.kind === 'outbound') cfg.detour = 'tor';
      (p.kind === 'endpoint' ? endpoints : outbounds).push(cfg); tags.push(tag);
    });
    var torOnly = o.via === 'tor' && !tags.length;
    outbounds.push({ type: 'direct', tag: 'direct' });
    if (o.via === 'tor') outbounds.push({ type: 'socks', tag: 'tor', server: '127.0.0.1', server_port: o.torPort, version: '5' });
    var finalTag;
    if (torOnly) finalTag = 'tor';
    else if (!tags.length) throw new Error('Нет ни одного профиля: добавьте ссылку, WireGuard или OpenVPN файл');
    else { outbounds.push(o.failover === 'selector' || tags.length === 1 ? { type: 'selector', tag: 'proxy', outbounds: tags, default: tags[0] } : { type: 'urltest', tag: 'proxy', outbounds: tags, url: 'https://www.gstatic.com/generate_204', interval: '3m', tolerance: 100 }); finalTag = 'proxy'; }
    var tor = o.via === 'tor';
    var dns = { servers: [{ type: 'https', tag: 'dns-bootstrap', server: o.bootstrap, server_port: 443, path: '/dns-query' }], rules: [], final: 'dns-bootstrap' };
    if (tor) { dns.servers.push({ type: 'fakeip', tag: 'dns-fake', inet4_range: '198.18.0.0/15', inet6_range: 'fc00::/18' }, { type: 'https', tag: 'dns-remote', server: o.remoteDns, server_port: 443, path: '/dns-query', detour: 'tor' }); dns.rules.push({ query_type: ['A', 'AAAA'], action: 'route', server: 'dns-fake' }); dns.final = 'dns-remote'; }  // names go to Tor as domains (fake IPs); other queries only through Tor
    else { dns.servers.push({ type: 'https', tag: 'dns-remote', server: o.remoteDns, server_port: 443, path: '/dns-query', detour: finalTag }); dns.final = 'dns-remote'; }
    var inbounds = o.mode === 'tun'
      ? [{ type: 'tun', tag: 'tun-in', address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'], auto_route: true, strict_route: !!o.strict, stack: 'system' }]
      : [{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: o.port }];
    var rules = [{ action: 'sniff' }, { protocol: 'dns', action: 'hijack-dns' }];
    if (o.bypassPrivate) rules.push({ ip_is_private: true, outbound: 'direct' });
    var cfg = { log: { level: o.logLevel, timestamp: true }, dns: dns, inbounds: inbounds, outbounds: outbounds, route: { rules: rules, final: finalTag, auto_detect_interface: true, default_domain_resolver: { server: 'dns-bootstrap' } } };
    if (endpoints.length) cfg.endpoints = endpoints;
    return cfg;
  }

  var API = { parseLink: parseLink, parseProfiles: parseProfiles, parseWireGuardConf: parseWireGuardConf, parseOvpn: parseOvpn, buildConfig: buildConfig, b64dec: b64dec };
  if (typeof module !== 'undefined' && module.exports) module.exports = API; else window.W420BridgeConfig = API;
})();

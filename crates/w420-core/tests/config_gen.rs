//! Unit tests for w420-core config generation (port of tools/tests/check_test.js case'ы).
//! Run: cargo test -p w420-core --test config_gen

use w420_core::{build_config, parse_link, parse_ovpn, parse_profiles, parse_wireguard_conf, BuildOpts, VpnCreds};

fn serde_value(v: &serde_json::Value) -> serde_json::Value { v.clone() }

#[test]
fn parse_vless_reality() {
    let link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.1:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=testpubkey&sid=6ba85179e30d4fc2&type=tcp&flow=xtls-rprx-vision#Reality";
    let p = parse_link(link).expect("vless reality parse");
    assert_eq!(p.kind, w420_core::ProxyKind::Vless);
    assert_eq!(p.server, "203.0.113.1");
    assert_eq!(p.port, 443);
    let tls = p.config.get("tls").unwrap();
    assert_eq!(tls.get("reality").and_then(|r| r.get("public_key")).and_then(|v| v.as_str()).unwrap(), "testpubkey");
    assert_eq!(p.config.get("packet_encoding").and_then(|v| v.as_str()).unwrap(), "xudp");
}

#[test]
fn parse_vless_ws_tls() {
    let link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@v.example.com:443?security=tls&sni=v.example.com&type=ws&path=%2Fvl&host=v.example.com#VLESS-WS";
    let p = parse_link(link).expect("vless ws parse");
    assert_eq!(p.kind, w420_core::ProxyKind::Vless);
    let tr = p.config.get("transport").unwrap();
    assert_eq!(tr.get("type").and_then(|v| v.as_str()).unwrap(), "ws");
    assert_eq!(tr.get("path").and_then(|v| v.as_str()).unwrap(), "/vl");
    let headers = tr.get("headers").and_then(|v| v.get("Host")).and_then(|v| v.as_str()).unwrap();
    assert_eq!(headers, "v.example.com");
}

#[test]
fn parse_vmess_ws() {
    let json = serde_json::json!({
        "v": "2", "ps": "vmess-ws", "add": "v.example.com", "port": "443",
        "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "0", "scy": "auto",
        "net": "ws", "type": "none", "host": "cdn.example.com", "path": "/ws",
        "tls": "tls", "sni": "cdn.example.com"
    });
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, serde_json::to_string(&json).unwrap().as_bytes());
    let link = format!("vmess://{b64}");
    let p = parse_link(&link).expect("vmess parse");
    assert_eq!(p.kind, w420_core::ProxyKind::Vmess);
    assert_eq!(p.config.get("type").and_then(|v| v.as_str()).unwrap(), "vmess");
    assert_eq!(p.config.get("uuid").and_then(|v| v.as_str()).unwrap(), "b831381d-6324-4d53-ad4f-8cda48b30811");
    let tls = p.config.get("tls").unwrap();
    assert!(tls.get("enabled").and_then(|v| v.as_bool()).unwrap());
}

#[test]
fn parse_trojan() {
    let link = "trojan://secretpw@203.0.113.2:443?sni=t.example.com&type=ws&path=%2Ftr&host=t.example.com#Trojan-WS";
    let p = parse_link(link).expect("trojan parse");
    assert_eq!(p.kind, w420_core::ProxyKind::Trojan);
    assert_eq!(p.config.get("password").and_then(|v| v.as_str()).unwrap(), "secretpw");
    let tls = p.config.get("tls").unwrap();
    assert!(tls.get("enabled").and_then(|v| v.as_bool()).unwrap());
}

#[test]
fn parse_shadowsocks() {
    let user = base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, b"aes-256-gcm:pa55word");
    let link = format!("ss://{user}@203.0.113.3:8388#SS");
    let p = parse_link(&link).expect("ss parse");
    assert_eq!(p.kind, w420_core::ProxyKind::Shadowsocks);
    assert_eq!(p.config.get("method").and_then(|v| v.as_str()).unwrap(), "aes-256-gcm");
    assert_eq!(p.config.get("password").and_then(|v| v.as_str()).unwrap(), "pa55word");
    assert_eq!(p.config.get("server_port").and_then(|v| v.as_u64()).unwrap(), 8388);
}

#[test]
fn parse_shadowsocks_legacy() {
    let link = "ss://chacha20-ietf-poly1305:secret@203.0.113.5:8388#SSlegacy";
    let p = parse_link(link).expect("ss legacy parse");
    assert_eq!(p.config.get("server").and_then(|v| v.as_str()).unwrap(), "203.0.113.5");
    assert_eq!(p.config.get("method").and_then(|v| v.as_str()).unwrap(), "chacha20-ietf-poly1305");
}

#[test]
fn parse_hysteria2() {
    let link = "hysteria2://hy2pass@203.0.113.4:443?sni=h.example.com&obfs=salamander&obfs-password=obfspw#Hy2";
    let p = parse_link(link).expect("hy2 parse");
    assert_eq!(p.kind, w420_core::ProxyKind::Hysteria2);
    assert_eq!(p.config.get("obfs").and_then(|v| v.get("type")).and_then(|v| v.as_str()).unwrap(), "salamander");
}

#[test]
fn parse_tuic() {
    let link = "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:tuicpw@203.0.113.6:443?sni=tu.example.com&congestion_control=bbr&alpn=h3#TUIC";
    let p = parse_link(link).expect("tuic parse");
    assert_eq!(p.kind, w420_core::ProxyKind::Tuic);
    assert_eq!(p.config.get("congestion_control").and_then(|v| v.as_str()).unwrap(), "bbr");
}

#[test]
fn parse_anytls() {
    let link = "anytls://atpw@203.0.113.7:443?sni=a.example.com#AnyTLS";
    let p = parse_link(link).expect("anytls parse");
    assert_eq!(p.kind, w420_core::ProxyKind::AnyTls);
    assert_eq!(p.config.get("password").and_then(|v| v.as_str()).unwrap(), "atpw");
}

#[test]
fn parse_socks5() {
    let link = "socks5://user:pw@203.0.113.8:1080#SOCKS";
    let p = parse_link(link).expect("socks5 parse");
    assert_eq!(p.kind, w420_core::ProxyKind::Socks5);
    assert_eq!(p.config.get("username").and_then(|v| v.as_str()).unwrap(), "user");
    assert_eq!(p.config.get("password").and_then(|v| v.as_str()).unwrap(), "pw");
}

#[test]
fn test_parse_wireguard_conf() {
    let conf = "[Interface]\nPrivateKey = testprivatekeybase64==\nAddress = 10.7.0.2/32, fd00::2/128\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = testpublickeybase64==\nEndpoint = 203.0.113.9:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n";
    let p = w420_core::parse_wireguard_conf(&conf, Some("WG")).expect("wg parse");
    assert_eq!(p.kind, w420_core::ProxyKind::WireGuard);
    assert_eq!(p.server, "203.0.113.9");
    assert_eq!(p.port, 51820);
    let peers = p.config.get("peers").and_then(|v| v.as_array()).unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].get("allowed_ips").and_then(|v| v.as_array()).unwrap().len(), 2);
}

#[test]
fn test_parse_ovpn() {
    let ovpn = "client\ndev tun\nproto udp\nremote 203.0.113.10 1194\nremote 203.0.113.11 443 tcp\ncipher AES-256-GCM\nauth SHA256\nremote-cert-tls server\nauth-user-pass\nkey-direction 1\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n<cert>\n-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n</cert>\n<key>\n-----BEGIN PRIVATE KEY-----\nMIID\n-----END PRIVATE KEY-----\n</key>\n<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\ntestkey\n-----END OpenVPN Static key V1-----\n</tls-auth>\n";
    let creds = VpnCreds { username: "u".into(), password: "p".into() };
    let (p, needs_auth) = w420_core::parse_ovpn(&ovpn, Some("OVPN"), Some(&creds)).expect("ovpn parse");
    assert_eq!(p.kind, w420_core::ProxyKind::OpenVpn);
    assert_eq!(needs_auth, false);
    assert_eq!(p.config.get("servers").and_then(|v| v.as_array()).unwrap().len(), 2);
}

#[test]
fn parse_ovpn_needs_auth_without_creds() {
    let ovpn = "client\nproto udp\nremote 127.0.0.1 1194\nauth-user-pass\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n";
    let (p, needs_auth) = w420_core::parse_ovpn(&ovpn, Some("x"), None).expect("ovpn no-creds parse");
    assert_eq!(needs_auth, true);
    let _ = p;
}

#[test]
fn parse_ss_plugin_unsupported() {
    let link = "ss://YWVzLTI1Ni1nY206cHc=@h:1?plugin=obfs-local";
    let err = parse_link(link).unwrap_err();
    assert!(err.to_string().contains("plugin"));
}

#[test]
fn parse_unknown_scheme() {
    let err = parse_link("custom://example.com").unwrap_err();
    assert!(err.to_string().contains("Неизвестная схема"));
}

#[test]
fn parse_profiles_subscription() {
    let vmess_link = "vmess://".to_owned() + &base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, serde_json::json!({"v":"2","ps":"m","add":"v.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto","net":"tcp"}).to_string().as_bytes());
    let links = vec![
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.1:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=testpubkey&sid=6ba85179e30d4fc2&type=tcp#R",
        vmess_link.as_str(),
        "trojan://pw@203.0.113.2:443#T",
        "socks5://u:p@203.0.113.8:1080#S",
        "nonsense",
    ];
    let sub = base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, links.join("\n").as_bytes());
    let parsed = parse_profiles(&sub).expect("subscription parse");
    assert_eq!(parsed.ok.len(), 4);
    assert_eq!(parsed.bad.len(), 1);
    assert!(parsed.bad[0].error.contains("Неизвестная схема") || parsed.bad[0].error.contains("Не похоже"));
}

#[test]
fn build_config_proxy_mode() {
    let p = parse_link("socks5://user:pw@203.0.113.8:1080#SOCKS").unwrap();
    let cfg = build_config(&[p], &BuildOpts::default()).expect("build proxy");
    assert_eq!(
        cfg.get("route")
            .and_then(|r| r.get("final"))
            .and_then(|v| v.as_str())
            .unwrap(),
        "proxy"
    );
    assert!(cfg.get("outbounds").and_then(|v| v.as_array()).unwrap().len() >= 2); // proxy + direct
    let inbound = cfg.get("inbounds").and_then(|v| v.as_array()).unwrap()[0].clone();
    assert_eq!(inbound.get("type").and_then(|v| v.as_str()).unwrap(), "mixed");
}

#[test]
fn build_config_tun_mode() {
    let p = parse_link("socks5://user:pw@203.0.113.8:1080#SOCKS").unwrap();
    let mut opts = BuildOpts::default();
    opts.mode = "tun".into();
    let cfg = build_config(&[p], &opts).expect("build tun");
    assert_eq!(
        cfg.get("route")
            .and_then(|r| r.get("final"))
            .and_then(|v| v.as_str())
            .unwrap(),
        "proxy"
    );
    let inbound = cfg.get("inbounds").and_then(|v| v.as_array()).unwrap()[0].clone();
    assert_eq!(inbound.get("type").and_then(|v| v.as_str()).unwrap(), "tun");
}

#[test]
fn build_config_no_profiles_error() {
    let err = build_config(&[], &BuildOpts::default()).unwrap_err();
    assert!(err.to_string().contains("Нет ни одного профиля"));
}

#[test]
fn build_config_tor_only() {
    let mut opts = BuildOpts::default();
    opts.via = "tor".into();
    let err = build_config(&[], &opts).unwrap_err();
    assert!(err.to_string().contains("Нет ни одного профиля"));
}

//! W420 Bridge config generation: proxy links / WireGuard / OpenVPN -> sing-box config.
//!
//! Pure Rust port of `app/dist/bridge-config.js`. Zero Tauri dependency — can be
//! unit-tested standalone and reused by the installer, TTS service, or any future crate.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use url::Url;
use uuid::Uuid;

use crate::{ProxyKind, ProxyProfile, W420Error};

/// Result of parsing many links (or a base64 subscription) at once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedProfiles {
    pub ok: Vec<ProxyProfile>,
    pub bad: Vec<BadLine>,
}

/// A line that failed to parse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadLine {
    pub line: String,
    pub error: String,
}

/// Options for `build_config`, mirroring the JS `buildConfig(profiles, o)` signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildOpts {
    pub mode: String,           // "proxy" | "tun"
    pub via: String,            // "direct" | "tor"
    pub port: u16,              // mixed-in listen port (proxy mode)
    pub tor_port: u16,          // Tor SOCKS port
    pub failover: String,       // "urltest" | "selector"
    pub bypass_private: bool,
    pub strict: bool,
    pub bootstrap: String,      // bootstrap DNS
    pub remote_dns: String,     // remote DNS
    pub log_level: String,
}

impl Default for BuildOpts {
    fn default() -> Self {
        Self {
            mode: "proxy".into(),
            via: "direct".into(),
            port: 2080,
            tor_port: 9150,
            failover: "urltest".into(),
            bypass_private: true,
            strict: true,
            bootstrap: "1.1.1.1".into(),
            remote_dns: "1.1.1.1".into(),
            log_level: "warn".into(),
        }
    }
}

/// Optional credentials for OpenVPN `auth-user-pass`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnCreds {
    pub username: String,
    pub password: String,
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn base64_decode_urlsafe(input: &str) -> Result<String, W420Error> {
    let s = input.trim().replace('-', "+").replace('_', "/");
    let padded = format!("{}{}", s, "=".repeat((4 - s.len() % 4) % 4));
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &padded)
        .map_err(|e| W420Error::InvalidProxyLink(format!("base64 decode failed: {e}")))?;
    String::from_utf8(bytes).map_err(|e| W420Error::InvalidProxyLink(format!("utf-8 decode failed: {e}")))
}

fn query(url: &Url, key: &str, default: &str) -> String {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.to_string())
        .unwrap_or_else(|| default.to_string())
}

fn truthy(v: &str) -> bool {
    v == "1" || v == "true" || v == "True"
}

fn name_of(url: &Url, default: &str) -> String {
    url.fragment()
        .map(|f| percent_decode(f).unwrap_or_else(|| default.to_string()))
        .unwrap_or_else(|| default.to_string())
}

fn port_of(url: &Url, default: u16) -> u16 {
    url.port().unwrap_or(default)
}

fn percent_decode(s: &str) -> Option<String> {
    percent_encoding::percent_decode_str(s).decode_utf8().ok().map(|s| s.to_string())
}

fn clean_map(mut map: serde_json::Map<String, serde_json::Value>) -> serde_json::Value {
    map.retain(|_, v| !v.is_null());
    serde_json::Value::Object(map)
}

fn tls_from(url: &Url, host: &str, default_sec: &str, force: bool) -> Option<serde_json::Value> {
    let sec = query(url, "security", default_sec);
    if sec == "none" && !force {
        return None;
    }
    let peer = query(url, "peer", host);
    let mut tls = serde_json::json!({
        "enabled": true,
        "server_name": query(url, "sni", &peer),
    });
    let insecure_default = query(url, "insecure", "0");
    if truthy(&query(url, "allowInsecure", &insecure_default)) {
        tls.as_object_mut().unwrap().insert("insecure".into(), true.into());
    }
    if let Some(alpn) = query(url, "alpn", "").split(',').next() {
        if !alpn.is_empty() {
            tls.as_object_mut().unwrap().insert(
                "alpn".into(),
                serde_json::json!(alpn.split(',').collect::<Vec<&str>>()),
            );
        }
    }
    let fp = query(url, "fp", "");
    if !fp.is_empty() || sec == "reality" {
        tls.as_object_mut().unwrap().insert(
            "utls".into(),
            serde_json::json!({ "enabled": true, "fingerprint": fp }),
        );
    }
    if sec == "reality" {
        tls.as_object_mut().unwrap().insert(
            "reality".into(),
            serde_json::json!({
                "enabled": true,
                "public_key": query(url, "pbk", ""),
                "short_id": query(url, "sid", ""),
            }),
        );
    }
    Some(tls)
}

fn transport_from(url: &Url) -> Option<serde_json::Value> {
    let r#type = query(url, "type", "tcp");
    let path = query(url, "path", "/");
    let host = query(url, "host", "");
    match r#type.as_str() {
        "ws" => {
            let mut w = serde_json::json!({ "type": "ws", "path": path });
            if !host.is_empty() {
                w.as_object_mut().unwrap().insert(
                    "headers".into(),
                    serde_json::json!({ "Host": host }),
                );
            }
            Some(w)
        }
        "grpc" => Some(serde_json::json!({ "type": "grpc", "service_name": query(url, "serviceName", "") })),
        "http" | "h2" => {
            let mut h = serde_json::json!({ "type": "http", "path": path });
            if !host.is_empty() {
                h.as_object_mut().unwrap().insert("host".into(), serde_json::json!(host.split(',').collect::<Vec<&str>>()));
            }
            Some(h)
        }
        "httpupgrade" => {
            let mut g = serde_json::json!({ "type": "httpupgrade", "path": path });
            if !host.is_empty() {
                g.as_object_mut().unwrap().insert("host".into(), serde_json::json!(host));
            }
            Some(g)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// parseLink
// ---------------------------------------------------------------------------

/// Parses a single proxy / VPN subscription link into a [`ProxyProfile`].
pub fn parse_link(link: &str) -> Result<ProxyProfile, W420Error> {
    let link = link.trim();
    let scheme_re = Regex::new(r"^([a-z0-9+.-]+)://").unwrap();
    let caps = scheme_re
        .captures(link)
        .ok_or_else(|| W420Error::InvalidProxyLink("Не похоже на ссылку профиля".into()))?;
    let scheme = caps.get(1).unwrap().as_str().to_lowercase();

    if scheme == "vmess" {
        let payload = link.strip_prefix("vmess://").ok_or_else(|| {
            W420Error::InvalidProxyLink("bad vmess prefix".into())
        })?;
        let decoded = base64_decode_urlsafe(payload)?;
        let j: serde_json::Value = serde_json::from_str(&decoded).map_err(|e| {
            W420Error::InvalidProxyLink(format!("vmess json decode failed: {e}"))
        })?;
        let net = j.get("net").and_then(|v| v.as_str()).unwrap_or("tcp");
        let mut tr: Option<serde_json::Value> = None;
        if net == "ws" {
            tr = Some(serde_json::json!({ "type": "ws", "path": j.get("path").and_then(|v| v.as_str()).unwrap_or("/") }));
            if let Some(h) = j.get("host").and_then(|v| v.as_str()) {
                if !h.is_empty() {
                    tr.as_mut().unwrap().as_object_mut().unwrap().insert("headers".into(), serde_json::json!({ "Host": h }));
                }
            }
        } else if net == "grpc" {
            tr = Some(serde_json::json!({ "type": "grpc", "service_name": j.get("path").and_then(|v| v.as_str()).unwrap_or("") }));
        } else if net == "h2" {
            let mut h2map = serde_json::Map::new();
            h2map.insert("type".into(), serde_json::json!("http"));
            h2map.insert("path".into(), serde_json::json!(j.get("path").and_then(|v| v.as_str()).unwrap_or("/")));
            if let Some(h) = j.get("host").and_then(|v| v.as_str()) {
                if !h.is_empty() {
                    h2map.insert("host".into(), serde_json::json!(h.split(',').collect::<Vec<&str>>()));
                }
            }
            tr = Some(serde_json::Value::Object(h2map));
        } else if net == "httpupgrade" {
            let mut gmap = serde_json::Map::new();
            gmap.insert("type".into(), serde_json::json!("httpupgrade"));
            gmap.insert("path".into(), serde_json::json!(j.get("path").and_then(|v| v.as_str()).unwrap_or("/")));
            if let Some(h) = j.get("host").and_then(|v| v.as_str()) {
                if !h.is_empty() {
                    gmap.insert("host".into(), serde_json::json!(h));
                }
            }
            tr = Some(serde_json::Value::Object(gmap));
        }
        let mut tls = None;
        if j.get("tls").and_then(|v| v.as_str()) == Some("tls") {
            let mut t = serde_json::json!({
                "enabled": true,
                "server_name": j.get("sni").or_else(|| j.get("host")).or_else(|| j.get("add")).and_then(|v| v.as_str()).unwrap_or("")
            });
            if let Some(a) = j.get("alpn").and_then(|v| v.as_str()) {
                t.as_object_mut().unwrap().insert("alpn".into(), serde_json::json!(a.split(',').collect::<Vec<&str>>()));
            }
            if let Some(f) = j.get("fp").and_then(|v| v.as_str()) {
                t.as_object_mut().unwrap().insert("utls".into(), serde_json::json!({ "enabled": true, "fingerprint": f }));
            }
            tls = Some(t);
        }
        let mut singbox = serde_json::json!({
            "type": "vmess",
            "server": j.get("add").and_then(|v| v.as_str()).unwrap_or(""),
            "server_port": j.get("port").and_then(|v| v.as_str()).and_then(|v| v.parse::<u16>().ok()).unwrap_or(0),
            "uuid": j.get("id").and_then(|v| v.as_str()).unwrap_or(""),
            "alter_id": j.get("aid").and_then(|v| v.as_str()).and_then(|v| v.parse::<u16>().ok()).unwrap_or(0),
            "security": j.get("scy").and_then(|v| v.as_str()).unwrap_or("auto"),
            "tls": tls,
            "transport": tr,
        });
        clean_outbound(&mut singbox);
        return Ok(ProxyProfile {
            id: Uuid::new_v4(),
            kind: ProxyKind::Vmess,
            tag: j.get("ps").or_else(|| j.get("add")).and_then(|v| v.as_str()).unwrap_or("vmess").to_string(),
            server: j.get("add").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            port: j.get("port").and_then(|v| v.as_str()).and_then(|v| v.parse::<u16>().ok()).unwrap_or(0),
            config: singbox,
        });
    }

    let url = Url::parse(link).map_err(|e| W420Error::InvalidProxyLink(format!("URL parse failed: {e}")))?;
    let host = url.host_str().unwrap_or("").replace(['[', ']'], "");
    let user = percent_decode(url.username()).unwrap_or_default();
    let pass = percent_decode(url.password().unwrap_or("")).unwrap_or_default();

    if scheme == "vless" {
        let mut o = serde_json::json!({
            "type": "vless",
            "server": host,
            "server_port": port_of(&url, 443),
            "uuid": user,
            "flow": query(&url, "flow", ""),
            "tls": tls_from(&url, &host, "none", false),
            "transport": transport_from(&url),
        });
        let has_reality = o.get("tls").and_then(|t| t.get("reality")).is_some();
        let packet_encoding = query(&url, "packetEncoding", "");
        if has_reality || packet_encoding == "xudp" {
            o.as_object_mut().unwrap().insert("packet_encoding".into(), "xudp".into());
        }
        clean_outbound(&mut o);
        return Ok(ProxyProfile {
            id: Uuid::new_v4(),
            kind: ProxyKind::Vless,
            tag: name_of(&url, &host),
            server: host,
            port: port_of(&url, 443),
            config: o,
        });
    }

    if scheme == "trojan" {
        let o = serde_json::json!({
            "type": "trojan",
            "server": host,
            "server_port": port_of(&url, 443),
            "password": user,
            "tls": tls_from(&url, &host, "tls", true),
            "transport": transport_from(&url),
        });
        return Ok(ProxyProfile {
            id: Uuid::new_v4(),
            kind: ProxyKind::Trojan,
            tag: name_of(&url, &host),
            server: host,
            port: port_of(&url, 443),
            config: o,
        });
    }

    if scheme == "ss" {
        let rest = link.strip_prefix("ss://").unwrap_or(link).split('#').next().unwrap_or("");
        let (method, password, srv, sp) = if rest.contains('@') {
            let decoded = rest.split('?').next().unwrap_or("");
            let at = decoded.rfind('@').unwrap_or(0);
            let mp = &decoded[..at];
            let hp = &decoded[at + 1..];
            // userinfo может быть base64 (метод:пароль) или открытым текстом
            let up = base64_decode_urlsafe(mp).unwrap_or_else(|_| mp.to_string());
            let method = up.split(':').next().unwrap_or("").to_string();
            let password = up.split(':').nth(1).unwrap_or("").to_string();
            let srv = hp[..hp.rfind(':').unwrap_or(0)].to_string();
            let sp = hp[hp.rfind(':').unwrap_or(0) + 1..].to_string();
            (method, password, srv, sp)
        } else {
            let ui = percent_decode(url.username()).unwrap_or_default();
            let dec = if ui.contains(':') { ui } else { base64_decode_urlsafe(&ui)? };
            let method = dec.split(':').next().unwrap_or("").to_string();
            let password = dec.split(':').nth(1).unwrap_or(pass.as_str()).to_string();
            let srv = host.clone();
            let sp = port_of(&url, 0).to_string();
            (method, password, srv, sp)
        };
        if !query(&url, "plugin", "").is_empty() {
            return Err(W420Error::UnsupportedProtocol(
                "Shadowsocks с plugin (obfs/v2ray-plugin) не поддерживается: используйте VLESS/Trojan с TLS или Hysteria2".into(),
            ));
        }
        let sp_port: u16 = sp.parse().unwrap_or(0);
        return Ok(ProxyProfile {
            id: Uuid::new_v4(),
            kind: ProxyKind::Shadowsocks,
            tag: name_of(&url, &srv),
            server: srv.clone(),
            port: sp_port,
            config: serde_json::json!({
                "type": "shadowsocks",
                "server": srv.clone(),
                "server_port": sp_port,
                "method": method,
                "password": password,
            }),
        });
    }

    if scheme == "hysteria2" || scheme == "hy2" {
        let password = if !pass.is_empty() { format!("{user}:{pass}") } else { user.clone() };
        let mut h2 = serde_json::json!({
            "type": "hysteria2",
            "server": host,
            "server_port": port_of(&url, 443),
            "password": password,
            "tls": {
                "enabled": true,
                "server_name": query(&url, "sni", &host),
                "alpn": ["h3"],
            },
        });
        if truthy(&query(&url, "insecure", "0")) {
            h2.as_object_mut().unwrap().get_mut("tls").unwrap().as_object_mut().unwrap().insert("insecure".into(), true.into());
        }
        if let Some(obfs) = query(&url, "obfs", "").split(',').next() {
            if !obfs.is_empty() {
                h2.as_object_mut().unwrap().insert(
                    "obfs".into(),
                    serde_json::json!({ "type": obfs, "password": query(&url, "obfs-password", "") }),
                );
            }
        }
        return Ok(ProxyProfile {
            id: Uuid::new_v4(),
            kind: ProxyKind::Hysteria2,
            tag: name_of(&url, &host),
            server: host,
            port: port_of(&url, 443),
            config: h2,
        });
    }

    if scheme == "tuic" {
        let mut o = serde_json::json!({
            "type": "tuic",
            "server": host,
            "server_port": port_of(&url, 443),
            "uuid": user,
            "password": pass,
            "congestion_control": query(&url, "congestion_control", "bbr"),
            "udp_relay_mode": query(&url, "udp_relay_mode", "native"),
            "tls": {
                "enabled": true,
                "server_name": query(&url, "sni", &host),
                "alpn": query(&url, "alpn", "h3").split(',').collect::<Vec<&str>>(),
                "insecure": truthy(&query(&url, "allow_insecure", "0")),
            },
        });
        if !truthy(&query(&url, "allow_insecure", "0")) {
            o.as_object_mut().unwrap().get_mut("tls").unwrap().as_object_mut().unwrap().remove("insecure");
        }
        clean_outbound(&mut o);
        return Ok(ProxyProfile {
            id: Uuid::new_v4(),
            kind: ProxyKind::Tuic,
            tag: name_of(&url, &host),
            server: host,
            port: port_of(&url, 443),
            config: o,
        });
    }

    if scheme == "anytls" {
        let o = serde_json::json!({
            "type": "anytls",
            "server": host,
            "server_port": port_of(&url, 443),
            "password": user,
            "tls": {
                "enabled": true,
                "server_name": query(&url, "sni", &host),
                "insecure": truthy(&query(&url, "insecure", "0")),
            },
        });
        return Ok(ProxyProfile {
            id: Uuid::new_v4(),
            kind: ProxyKind::AnyTls,
            tag: name_of(&url, &host),
            server: host,
            port: port_of(&url, 443),
            config: o,
        });
    }

    if scheme == "socks5" || scheme == "socks" {
        let mut o = serde_json::json!({
            "type": "socks",
            "server": host,
            "server_port": port_of(&url, 1080),
            "version": "5",
        });
        if !user.is_empty() {
            o.as_object_mut().unwrap().insert("username".into(), serde_json::json!(user));
        }
        if !pass.is_empty() {
            o.as_object_mut().unwrap().insert("password".into(), serde_json::json!(pass));
        }
        clean_outbound(&mut o);
        return Ok(ProxyProfile {
            id: Uuid::new_v4(),
            kind: ProxyKind::Socks5,
            tag: name_of(&url, &host),
            server: host,
            port: port_of(&url, 1080),
            config: o,
        });
    }

    if scheme == "http" || scheme == "https" {
        let mut o = serde_json::json!({
            "type": "http",
            "server": host,
            "server_port": if scheme == "https" { 443 } else { 8080 },
        });
        if !user.is_empty() {
            o.as_object_mut().unwrap().insert("username".into(), serde_json::json!(user));
        }
        if !pass.is_empty() {
            o.as_object_mut().unwrap().insert("password".into(), serde_json::json!(pass));
        }
        if scheme == "https" {
            o.as_object_mut().unwrap().insert(
                "tls".into(),
                serde_json::json!({ "enabled": true, "server_name": host }),
            );
        }
        clean_outbound(&mut o);
        return Ok(ProxyProfile {
            id: Uuid::new_v4(),
            kind: ProxyKind::Socks5,
            tag: name_of(&url, &host),
            server: host,
            port: if scheme == "https" { 443 } else { 8080 },
            config: o,
        });
    }

    Err(W420Error::UnsupportedProtocol(format!("Неизвестная схема: {scheme}://")))
}

fn clean_outbound(map: &mut serde_json::Value) {
    if let Some(obj) = map.as_object_mut() {
        obj.retain(|_, v| !v.is_null());
        // remove empty strings too, mirroring JS clean()
        obj.retain(|_, v| match v {
            serde_json::Value::String(s) => !s.is_empty(),
            _ => true,
        });
    }
}

// ---------------------------------------------------------------------------
// parseWireGuardConf
// ---------------------------------------------------------------------------

/// Parses a WireGuard `.conf` file into a [`ProxyProfile`] (kind: endpoint).
pub fn parse_wireguard_conf(text: &str, name: Option<&str>) -> Result<ProxyProfile, W420Error> {
    let mut section: Option<String> = None;
    let mut iface: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    let mut peers: Vec<serde_json::Map<String, serde_json::Value>> = Vec::new();
    let mut current_peer: Option<&mut serde_json::Map<String, serde_json::Value>> = None;

    for raw in text.lines() {
        let l = raw.split(['#', ';']).next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        if let Some(h) = l.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = Some(h.to_lowercase());
            if section.as_deref() == Some("peer") {
                peers.push(serde_json::Map::new());
                current_peer = peers.last_mut();
            } else {
                current_peer = None;
            }
            continue;
        }
        let i = l.find('=').ok_or_else(|| W420Error::InvalidProxyLink(format!("bad wireguard line: {l}")))?;
        let k = l[..i].trim().to_lowercase();
        let v = l[i + 1..].trim();
        let target = if section.as_deref() == Some("peer") {
            current_peer.as_mut().unwrap()
        } else {
            &mut iface
        };
        target.insert(k, serde_json::json!(v));
    }

    if !iface.contains_key("privatekey") || peers.is_empty() {
        return Err(W420Error::InvalidProxyLink(
            "В конфиге WireGuard нет PrivateKey или Peer".into(),
        ));
    }

    let list = |v: Option<&serde_json::Value>| -> Vec<String> {
        v.and_then(|v| v.as_str())
            .unwrap_or("")
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    };

    let mut peer_outbounds = Vec::new();
    for p in &peers {
        let ep = p.get("endpoint").and_then(|v| v.as_str()).unwrap_or("");
        let i = ep.rfind(':').unwrap_or(0);
        let address = ep[..i].replace(['[', ']'], "");
        let port: u16 = ep[i + 1..].parse().unwrap_or(0);
        let allowed = list(p.get("allowed_ips"));
        let allowed_ips = if allowed.is_empty() {
            vec!["0.0.0.0/0".into(), "::/0".into()]
        } else {
            allowed
        };
        let mut peer_obj = serde_json::Map::new();
        peer_obj.insert("address".into(), serde_json::json!(address));
        peer_obj.insert("port".into(), serde_json::json!(port));
        peer_obj.insert("public_key".into(), serde_json::json!(p.get("publickey").and_then(|v| v.as_str()).unwrap_or("")));
        if let Some(psk) = p.get("presharedkey").and_then(|v| v.as_str()) {
            if !psk.is_empty() {
                peer_obj.insert("pre_shared_key".into(), serde_json::json!(psk));
            }
        }
        peer_obj.insert("allowed_ips".into(), serde_json::json!(allowed_ips));
        if let Some(pka) = p.get("persistentkeepalive").and_then(|v| v.as_str()) {
            if let Ok(pka) = pka.parse::<u16>() {
                peer_obj.insert("persistent_keepalive_interval".into(), serde_json::json!(pka));
            }
        }
        peer_outbounds.push(clean_map(peer_obj));
    }

    let mut ep = serde_json::json!({
        "type": "wireguard",
        "address": list(iface.get("address")),
        "private_key": iface.get("privatekey").and_then(|v| v.as_str()).unwrap_or(""),
    });
    if let Some(mtu) = iface.get("mtu").and_then(|v| v.as_str()) {
        if let Ok(mtu) = mtu.parse::<u16>() {
            ep.as_object_mut().unwrap().insert("mtu".into(), serde_json::json!(mtu));
        }
    }
    ep.as_object_mut().unwrap().insert("peers".into(), serde_json::json!(peer_outbounds));

    return Ok(ProxyProfile {
        id: Uuid::new_v4(),
        kind: ProxyKind::WireGuard,
        tag: name.unwrap_or("WireGuard").to_string(),
        server: host_from_peer(&peers),
        port: port_from_peer(&peers),
        config: ep,
    });
}

fn host_from_peer(peers: &[serde_json::Map<String, serde_json::Value>]) -> String {
    peers
        .first()
        .and_then(|p| p.get("endpoint").and_then(|v| v.as_str()))
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .replace(['[', ']'], "")
        .to_string()
}

fn port_from_peer(peers: &[serde_json::Map<String, serde_json::Value>]) -> u16 {
    peers
        .first()
        .and_then(|p| p.get("endpoint").and_then(|v| v.as_str()))
        .unwrap_or("")
        .rsplit(':')
        .next()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// parseOvpn
// ---------------------------------------------------------------------------

/// Parses an OpenVPN `.ovpn` file into a [`ProxyProfile`] (kind: endpoint).
pub fn parse_ovpn(
    text: &str,
    name: Option<&str>,
    creds: Option<&VpnCreds>,
) -> Result<(ProxyProfile, bool), W420Error> {
    // извлечь блоки <ca>, <cert>, <key>, <tls-auth>, <tls-crypt>, <tls-crypt-v2>, <secret> (без backreferences)
    let mut blocks: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for tag in ["ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "secret"] {
        let pattern = format!(r"<{tag}>[\s\S]*?</{tag}>");
        let re = Regex::new(&pattern).unwrap();
        let mut vals = Vec::new();
        for cap in re.captures_iter(text) {
            let m = cap.get(0).unwrap().as_str();
            let inner = m
                .strip_prefix(&format!("<{tag}>"))
                .unwrap_or(m)
                .strip_suffix(&format!("</{tag}>"))
                .unwrap_or(m);
            vals.extend(inner.lines().map(|l| l.to_string()));
        }
        if !vals.is_empty() {
            blocks.insert(tag.to_string(), vals);
        }
    }
    // убрать блоки из тела конфига (остальные строки — директивы)
    let mut body = text.to_string();
    for tag in ["ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "secret"] {
        body = Regex::new(&format!(r"<{tag}>[\s\S]*?</{tag}>"))
            .unwrap()
            .replace_all(&body, "")
            .to_string();
    }
    for tag in ["ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "secret"] {
        let pattern = format!(r"<{tag}>[\s\S]*?</{tag}>");
        let re = Regex::new(&pattern).unwrap();
        let mut vals = Vec::new();
        for cap in re.captures_iter(text) {
            let m = cap.get(0).unwrap().as_str();
            let inner = m
                .strip_prefix(&format!("<{tag}>"))
                .unwrap_or(m)
                .strip_suffix(&format!("</{tag}>"))
                .unwrap_or(m);
            let lines: Vec<String> = inner
                .split('\n')
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
            vals.extend(lines);
        }
        blocks.insert(tag.to_string(), vals);
    }

    let mut remotes: Vec<(String, u16, String)> = Vec::new();
    let mut opt: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for raw in body.lines() {
        let l = raw.split(['#', ';']).next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        let parts: Vec<&str> = l.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let k = parts[0];
        if k == "remote" {
            if parts.len() >= 2 {
                let server = parts[1].to_string();
                let port: u16 = parts.get(2).and_then(|v| v.parse().ok()).unwrap_or(1194);
                let proto = parts.get(3).copied().unwrap_or("").to_string();
                remotes.push((server, port, proto));
            }
        } else {
            opt.entry(k.to_string())
                .or_default()
                .extend(parts[1..].iter().map(|s| s.to_string()));
        }
    }

    if remotes.is_empty() {
        return Err(W420Error::InvalidProxyLink("В .ovpn нет строки remote".into()));
    }

    let proto_opt = opt.get("proto").and_then(|v| v.first()).cloned().unwrap_or_default();
    let mut proto = proto_opt.replace(&['4', '6'][..], "").replace("-client", "");
    if !proto.starts_with("tcp") {
        proto = "udp".into();
    }

    let mut servers = Vec::new();
    for (s, p, pr) in &remotes {
        let n = if !pr.is_empty() {
            if pr.starts_with("tcp") { "tcp" } else { "udp" }
        } else {
            proto.as_str()
        };
        servers.push(serde_json::json!({ "server": s, "server_port": p, "network": n }));
    }

    let mut ep = serde_json::json!({
        "type": "openvpn-client",
        "mode": "tls",
        "network": proto,
        "tls": {},
    });
    if servers.len() == 1 {
        ep.as_object_mut().unwrap().insert("server".into(), serde_json::json!(servers[0].get("server").unwrap()));
        ep.as_object_mut().unwrap().insert("server_port".into(), serde_json::json!(servers[0].get("server_port").unwrap()));
    } else {
        ep.as_object_mut().unwrap().insert("servers".into(), serde_json::json!(servers));
    }

    let ca = blocks.get("ca").map(|v| v.clone());
    if ca.is_none() {
        return Err(W420Error::InvalidProxyLink(
            "В .ovpn нет блока <ca>: вложите сертификат в файл или укажите отпечаток вручную".into(),
        ));
    }
    ep.as_object_mut().unwrap()
        .get_mut("tls")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("certificate".into(), serde_json::json!(ca.unwrap()));
    if let Some(cert) = blocks.get("cert") {
        ep.get_mut("tls").unwrap().as_object_mut().unwrap().insert("client_certificate".into(), serde_json::json!(cert));
    }
    if let Some(key) = blocks.get("key") {
        ep.get_mut("tls").unwrap().as_object_mut().unwrap().insert("client_key".into(), serde_json::json!(key));
    }

    let kd = opt.get("key-direction").and_then(|v| v.first()).cloned();
    for w in ["tls-auth", "tls-crypt", "tls-crypt-v2"] {
        if let Some(vals) = blocks.get(w) {
            let w_type = w.replace('-', "_");
            let mut cw = serde_json::json!({ "type": w_type, "key": vals });
            if w == "tls-auth" {
                let dir = if kd.as_deref() == Some("0") { "server" } else { "client" };
                cw.as_object_mut().unwrap().insert("direction".into(), serde_json::json!(dir));
            }
            ep.get_mut("tls").unwrap().as_object_mut().unwrap().insert("control_wrap".into(), cw);
        }
    }
    if let Some(v) = opt.get("remote-cert-tls").and_then(|v| v.first()) {
        ep.get_mut("tls").unwrap().as_object_mut().unwrap().insert("remote_certificate_tls".into(), serde_json::json!(v));
    }
    if let Some(dc) = opt.get("data-ciphers").or_else(|| opt.get("ncp-ciphers")) {
        if let Some(first) = dc.first() {
            ep.as_object_mut().unwrap().insert("data_ciphers".into(), serde_json::json!(first.split(':').collect::<Vec<&str>>()));
        }
    }
    if let Some(cipher) = opt.get("cipher").and_then(|v| v.first()) {
        ep.as_object_mut().unwrap().insert("data_ciphers_fallback".into(), serde_json::json!(cipher));
        if ep.get("data_ciphers").is_none() && cipher.contains(|c| matches!(c, 'G'|'C'|'H')) {
            ep.as_object_mut().unwrap().insert("data_ciphers".into(), serde_json::json!([cipher]));
        }
    }
    if let Some(auth) = opt.get("auth").and_then(|v| v.first()) {
        ep.as_object_mut().unwrap().insert("auth".into(), serde_json::json!(auth));
    }
    if let Some(comp) = opt.get("compress").or_else(|| opt.get("comp-lzo")) {
        if let Some(first) = comp.first() {
            if first == "comp-lzo" {
                ep.as_object_mut().unwrap().insert("compression_lzo".into(), serde_json::json!("adaptive"));
            } else {
                ep.as_object_mut().unwrap().insert("compression".into(), serde_json::json!(first));
            }
        }
    }
    if let Some(mtu) = opt.get("tun-mtu").and_then(|v| v.first()) {
        if let Ok(mtu) = mtu.parse::<u16>() {
            ep.as_object_mut().unwrap().insert("mtu".into(), serde_json::json!(mtu));
        }
    }

    let needs_auth = opt.contains_key("auth-user-pass");
    let mut needs_auth_unfilled = needs_auth;
    if needs_auth {
        if let Some(c) = creds {
            if !c.username.is_empty() {
                ep.as_object_mut().unwrap().insert("username".into(), serde_json::json!(&c.username));
                ep.as_object_mut().unwrap().insert("password".into(), serde_json::json!(&c.password));
                needs_auth_unfilled = false;
            }
        }
    }

    Ok((
        ProxyProfile {
            id: Uuid::new_v4(),
            kind: ProxyKind::OpenVpn,
            tag: name.unwrap_or_else(|| remotes[0].0.as_str()).to_string(),
            server: remotes[0].0.clone(),
            port: remotes[0].1,
            config: ep,
        },
        needs_auth_unfilled,
    ))
}

// ---------------------------------------------------------------------------
// parseProfiles
// ---------------------------------------------------------------------------

/// Parses many links at once, or a single base64 subscription.
pub fn parse_profiles(text: &str) -> Result<ParsedProfiles, W420Error> {
    let t = text.trim();
    let mut lines: Vec<String> = t
        .split('\n')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect();
    if lines.len() == 1
        && !Regex::new(r"^[a-z0-9+.-]+://").unwrap().is_match(&lines[0])
        && !Regex::new(r"[\[\s]").unwrap().is_match(&lines[0])
    {
        if let Ok(decoded) = base64_decode_urlsafe(&lines[0]) {
            lines = decoded
                .split('\n')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect();
        }
    }
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for l in &lines {
        match parse_link(l) {
            Ok(p) => ok.push(p),
            Err(e) => bad.push(BadLine { line: l[..l.len().min(40)].to_string(), error: e.to_string() }),
        }
    }
    Ok(ParsedProfiles { ok, bad })
}

// ---------------------------------------------------------------------------
// buildConfig
// ---------------------------------------------------------------------------

/// Builds a complete sing-box configuration from parsed profiles.
pub fn build_config(profiles: &[ProxyProfile], opts: &BuildOpts) -> Result<serde_json::Value, W420Error> {
    if profiles.is_empty() {
        return Err(W420Error::InvalidProxyLink(
            "Нет ни одного профиля: добавьте ссылку, WireGuard или OpenVPN файл".into(),
        ));
    }
    let mut outbounds: Vec<serde_json::Value> = Vec::new();
    let mut endpoints: Vec<serde_json::Value> = Vec::new();
    let mut tags: Vec<String> = Vec::new();
    let mut used: std::collections::BTreeMap<String, u16> = std::collections::BTreeMap::new();

    for p in profiles {
        let base = p
            .tag
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == ' ')
            .take(30)
            .collect::<String>();
        let base = if base.is_empty() { p.config.get("type").and_then(|v| v.as_str()).unwrap_or("profile").to_string() } else { base };
        let mut tag = base.clone();
        let mut n = 0u16;
        while used.contains_key(&tag) {
            n += 1;
            tag = format!("{base}-{n}");
        }
        used.insert(tag.clone(), n);

        let mut cfg = p.config.clone();
        cfg.as_object_mut().unwrap().insert("tag".into(), serde_json::json!(tag));

        if opts.via == "tor" && p.kind != ProxyKind::WireGuard && p.kind != ProxyKind::OpenVpn {
            cfg.as_object_mut().unwrap().insert("detour".into(), serde_json::json!("tor"));
        }

        if p.kind == ProxyKind::WireGuard || p.kind == ProxyKind::OpenVpn {
            endpoints.push(cfg);
        } else {
            outbounds.push(cfg);
        }
        tags.push(tag);
    }

    let tor_only = opts.via == "tor" && tags.is_empty();
    outbounds.push(serde_json::json!({ "type": "direct", "tag": "direct" }));
    if opts.via == "tor" {
        outbounds.push(serde_json::json!({ "type": "socks", "tag": "tor", "server": "127.0.0.1", "server_port": opts.tor_port, "version": "5" }));
    }

    let final_tag = if tor_only {
        "tor".to_string()
    } else if tags.is_empty() {
        return Err(W420Error::InvalidProxyLink(
            "Нет ни одного профиля: добавьте ссылку, WireGuard или OpenVPN файл".into(),
        ));
    } else if opts.failover == "selector" || tags.len() == 1 {
        outbounds.push(serde_json::json!({
            "type": "selector",
            "tag": "proxy",
            "outbounds": tags,
            "default": tags[0],
        }));
        "proxy".to_string()
    } else {
        outbounds.push(serde_json::json!({
            "type": "urltest",
            "tag": "proxy",
            "outbounds": tags,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "3m",
            "tolerance": 100,
        }));
        "proxy".to_string()
    };

    let tor = opts.via == "tor";
    let mut dns = serde_json::json!({
        "servers": [
            { "type": "https", "tag": "dns-bootstrap", "server": opts.bootstrap, "server_port": 443, "path": "/dns-query" }
        ],
        "rules": [],
        "final": "dns-bootstrap",
    });
    if tor {
        dns.as_object_mut().unwrap().get_mut("servers").unwrap().as_array_mut().unwrap().push(serde_json::json!({
            "type": "fakeip",
            "tag": "dns-fake",
            "inet4_range": "198.18.0.0/15",
            "inet6_range": "fc00::/18",
        }));
        dns.as_object_mut().unwrap().get_mut("servers").unwrap().as_array_mut().unwrap().push(serde_json::json!({
            "type": "https",
            "tag": "dns-remote",
            "server": opts.remote_dns,
            "server_port": 443,
            "path": "/dns-query",
            "detour": "tor",
        }));
        dns.as_object_mut().unwrap().get_mut("rules").unwrap().as_array_mut().unwrap().push(serde_json::json!({
            "query_type": ["A", "AAAA"],
            "action": "route",
            "server": "dns-fake",
        }));
        dns.as_object_mut().unwrap().insert("final".into(), serde_json::json!("dns-remote"));
    } else {
        dns.as_object_mut().unwrap().get_mut("servers").unwrap().as_array_mut().unwrap().push(serde_json::json!({
            "type": "https",
            "tag": "dns-remote",
            "server": opts.remote_dns,
            "server_port": 443,
            "path": "/dns-query",
            "detour": final_tag,
        }));
        dns.as_object_mut().unwrap().insert("final".into(), serde_json::json!("dns-remote"));
    }

    let inbounds = if opts.mode == "tun" {
        vec![serde_json::json!({
            "type": "tun",
            "tag": "tun-in",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "auto_route": true,
            "strict_route": opts.strict,
            "stack": "system",
        })]
    } else {
        vec![serde_json::json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": opts.port,
        })]
    };

    let mut rules: Vec<serde_json::Value> = vec![
        serde_json::json!({ "action": "sniff" }),
        serde_json::json!({ "protocol": "dns", "action": "hijack-dns" }),
    ];
    if opts.bypass_private {
        rules.push(serde_json::json!({ "ip_is_private": true, "outbound": "direct" }));
    }

    let mut cfg = serde_json::json!({
        "log": { "level": opts.log_level, "timestamp": true },
        "dns": dns,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": { "rules": rules, "final": final_tag, "auto_detect_interface": true, "default_domain_resolver": { "server": "dns-bootstrap" } },
    });
    if !endpoints.is_empty() {
        cfg.as_object_mut().unwrap().insert("endpoints".into(), serde_json::json!(endpoints));
    }
    Ok(cfg)
}

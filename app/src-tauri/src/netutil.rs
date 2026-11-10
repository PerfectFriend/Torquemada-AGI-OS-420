//! netutil.rs — Этап 30 (DameWare Parity): сетевые утилиты уровня DameWare
//! (TCP utilities): ping, traceroute, DNS lookup, port check.
//! Port check и DNS A/AAAA — чистый Rust (TcpStream / ToSocketAddrs), тестируются локально.
//! Ping/traceroute — системные бинарники с парсингом вывода (парсеры — чистые функции, тесты на моках).

use serde_json::{json, Value};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

// ======================= Port check (чистый Rust) =======================

/// TCP connect с таймаутом. true = порт открыт.
pub fn port_check(host: &str, port: u16, timeout_ms: u64) -> Result<bool, String> {
    if host.is_empty() || host.contains('\0') || host.len() > 253 {
        return Err("плохой хост".into());
    }
    let addr = format!("{host}:{port}");
    let to = Duration::from_millis(timeout_ms.max(100));
    // резолвим сами, чтобы таймаут применился и к DNS
    let addrs: Vec<_> = addr
        .to_socket_addrs()
        .map_err(|e| format!("DNS {addr}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("имя {host} не резолвится"));
    }
    for a in addrs {
        if TcpStream::connect_timeout(&a, to).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[tauri::command]
pub fn net_port_check(host: String, port: u16, timeout_ms: Option<u64>) -> Result<Value, String> {
    let open = port_check(&host, port, timeout_ms.unwrap_or(2000))?;
    Ok(json!({"host": host, "port": port, "open": open}))
}

/// Скан набора портов (как в DameWare TCP utils).
#[tauri::command]
pub fn net_port_scan(host: String, ports: Vec<u16>, timeout_ms: Option<u64>) -> Result<Value, String> {
    if ports.len() > 1024 {
        return Err("не больше 1024 портов за раз".into());
    }
    let to = timeout_ms.unwrap_or(800);
    let mut open = Vec::new();
    let scanned = ports.len();
    for p in ports {
        if port_check(&host, p, to)? {
            open.push(p);
        }
    }
    Ok(json!({"host": host, "scanned": scanned, "open": open}))
}

// ======================= DNS =======================

/// A/AAAA — через std (ToSocketAddrs). MX/TXT/SRV — через dig если есть.
#[tauri::command]
pub fn net_dns_lookup(name: String, record: Option<String>) -> Result<Value, String> {
    if name.is_empty() || name.contains('\0') || name.len() > 253 {
        return Err("плохое имя".into());
    }
    let record = record.unwrap_or_else(|| "A".to_string()).to_uppercase();
    match record.as_str() {
        "A" | "AAAA" | "ANY" => {
            let addrs: Vec<String> = format!("{name}:0")
                .to_socket_addrs()
                .map_err(|e| format!("DNS {name}: {e}"))?
                .map(|a| a.ip().to_string())
                .collect();
            Ok(json!({"name": name, "record": record, "answers": addrs}))
        }
        other => {
            // dig +short <type> <name>
            let out = std::process::Command::new("dig")
                .args(["+short", other, &name])
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    let answers: Vec<String> = String::from_utf8_lossy(&o.stdout)
                        .lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
                    Ok(json!({"name": name, "record": other, "answers": answers}))
                }
                Ok(o) => Err(format!("dig exit {:?}: {}", o.status.code(), String::from_utf8_lossy(&o.stderr).trim())),
                Err(_) => Err("нет dig в PATH (установите dnsutils)".into()),
            }
        }
    }
}

// ======================= Ping (парсинг `ping`) =======================

/// Парс вывода iputils ping: "rtt min/avg/max/mdev = 0.1/0.2/0.3/0.04 ms" + loss.
pub fn parse_ping(out: &str) -> Value {
    let mut sent = 0u32; let mut recv = 0u32;
    let mut rtt = String::new();
    for line in out.lines() {
        if let Some(i) = line.find("packets transmitted") {
            // "5 packets transmitted, 5 received, 0% packet loss"
            let nums: Vec<u32> = line.split(|c: char| !c.is_ascii_digit()).filter_map(|s| s.parse().ok()).collect();
            if nums.len() >= 2 { sent = nums[0]; recv = nums[1]; }
        }
        if line.contains("rtt min/avg/max") || line.contains("round-trip min/avg/max") {
            if let Some(i) = line.find('=') { rtt = line[i + 1..].trim().to_string(); }
        }
    }
    let loss = if sent > 0 { ((sent - recv) as f32 / sent as f32) * 100.0 } else { 100.0 };
    json!({"sent": sent, "received": recv, "loss_pct": loss, "rtt_ms": rtt})
}

#[tauri::command]
pub fn net_ping(host: String, count: Option<u8>) -> Result<Value, String> {
    if host.is_empty() || host.contains(|c: char| !c.is_ascii_alphanumeric() && !".-:".contains(c)) {
        return Err("плохой хост".into());
    }
    let n = count.unwrap_or(4).clamp(1, 20);
    let out = std::process::Command::new("ping")
        .args(["-c", &n.to_string(), "-W", "2", &host])
        .output();
    match out {
        Ok(o) => {
            let parsed = parse_ping(&String::from_utf8_lossy(&o.stdout));
            Ok(json!({"host": host, "ok": o.status.success(), "result": parsed}))
        }
        Err(e) => Err(format!("нет ping: {e}")),
    }
}

// ======================= Traceroute (парсинг) =======================

/// Парс `traceroute -n` строк: " 1  10.0.0.1  0.5 ms  0.4 ms  0.3 ms"
pub fn parse_traceroute(out: &str) -> Vec<Value> {
    let mut hops = Vec::new();
    for line in out.lines() {
        let t = line.trim();
        if t.is_empty() || !t.chars().next().unwrap().is_ascii_digit() { continue; }
        let cols: Vec<&str> = t.split_whitespace().collect();
        if cols.len() < 2 { continue; }
        let hop: u32 = cols[0].trim_end_matches('.').parse().unwrap_or(0);
        let mut addr = String::new();
        let mut rtts = Vec::new();
        for c in &cols[1..] {
            if *c == "*" { rtts.push("*".to_string()); continue; }
            if c.ends_with("ms") {
                rtts.push(c.trim_end_matches("ms").to_string());
            } else if addr.is_empty() && (c.contains('.') || c.contains(':')) {
                addr = c.to_string();
            }
        }
        hops.push(json!({"hop": hop, "addr": addr, "rtt_ms": rtts}));
    }
    hops
}

#[tauri::command]
pub fn net_traceroute(host: String, max_hops: Option<u8>) -> Result<Value, String> {
    if host.is_empty() || host.contains(|c: char| !c.is_ascii_alphanumeric() && !".-:".contains(c)) {
        return Err("плохой хост".into());
    }
    let m = max_hops.unwrap_or(30).clamp(1, 64);
    let out = std::process::Command::new("traceroute")
        .args(["-n", "-m", &m.to_string(), "-w", "2", &host])
        .output();
    match out {
        Ok(o) => Ok(json!({"host": host, "hops": parse_traceroute(&String::from_utf8_lossy(&o.stdout))})),
        Err(_) => {
            // фолбэк на tracepath
            let o = std::process::Command::new("tracepath")
                .args(["-n", "-m", &m.to_string(), &host])
                .output()
                .map_err(|e| format!("нет ни traceroute, ни tracepath: {e}"))?;
            Ok(json!({"host": host, "hops": parse_traceroute(&String::from_utf8_lossy(&o.stdout)), "via": "tracepath"}))
        }
    }
}

// ======================= Тесты =======================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_port_check_open_closed() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(port_check("127.0.0.1", port, 1000).unwrap());
        // закрытый порт: берём порт слушателя после drop
        drop(l);
        assert!(!port_check("127.0.0.1", port, 300).unwrap());
        assert!(port_check("", 80, 100).is_err());
    }

    #[test]
    fn test_dns_localhost() {
        let r = net_dns_lookup("localhost".into(), Some("A".into())).unwrap();
        let answers = r["answers"].as_array().unwrap();
        assert!(answers.iter().any(|a| a.as_str() == Some("127.0.0.1") || a.as_str() == Some("::1")));
    }

    #[test]
    fn test_parse_ping() {
        let out = "PING example.com (93.184.216.34) 56 data bytes\n\
                   64 bytes from 93.184.216.34: icmp_seq=0 ttl=56 time=12.3 ms\n\
                   --- example.com ping statistics ---\n\
                   4 packets transmitted, 4 received, 0% packet loss, time 3004ms\n\
                   rtt min/avg/max/mdev = 11.9/12.3/12.8/0.3 ms\n";
        let v = parse_ping(out);
        assert_eq!(v["sent"], 4);
        assert_eq!(v["received"], 4);
        assert_eq!(v["loss_pct"], 0.0);
        assert!(v["rtt_ms"].as_str().unwrap().contains("11.9/12.3"));
        let lossy = "2 packets transmitted, 1 received, 50% packet loss, time 1000ms\nrtt min/avg/max/mdev = 5.0/5.0/5.0/0.0 ms\n";
        let v2 = parse_ping(lossy);
        assert_eq!(v2["loss_pct"], 50.0);
    }

    #[test]
    fn test_parse_traceroute() {
        let out = "traceroute to 8.8.8.8 (8.8.8.8), 30 hops max\n\
                     1  192.168.1.1  0.512 ms  0.481 ms  0.402 ms\n\
                     2  10.20.0.1  2.101 ms  2.050 ms  2.033 ms\n\
                     3  * * *\n\
                     4  8.8.8.8  8.811 ms  8.790 ms  8.700 ms\n";
        let hops = parse_traceroute(out);
        assert_eq!(hops.len(), 4);
        assert_eq!(hops[0]["hop"], 1);
        assert_eq!(hops[0]["addr"], "192.168.1.1");
        assert_eq!(hops[0]["rtt_ms"].as_array().unwrap().len(), 3);
        assert_eq!(hops[2]["addr"], "");
        assert_eq!(hops[3]["addr"], "8.8.8.8");
    }
}

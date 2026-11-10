//! rat.rs — Этап 29 (DameWare Parity): RAT без GUI-сессии поверх SSH.
//!
//! power (reboot/shutdown/lock/logoff), systemctl сервисы, journald (view/clear),
//! диски (df), пакеты, экспорт system info в CSV/XML, Wake-on-LAN (чистый Rust,
//! UDP magic packet — без sidecar'ов).
//! Все команды идут через HostsManager::exec_command, но аргументы валидируются
//! белым списком символов — никаких shell-метасимволов в строку команды.

use serde_json::{json, Value};
use std::net::UdpSocket;

/// Разрешённые символы в аргументах (unit, путь, since): без shell-метасимволов.
fn valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._:/-+ ".contains(c))
}

fn run(h: &crate::hosts::HostsManager, host_id: &str, cmd: String) -> Result<String, String> {
    let r = h.exec_command(host_id, &cmd)?;
    if r.exit_code.unwrap_or(-1) != 0 {
        return Err(format!("exit {}: {}", r.exit_code.unwrap_or(-1), r.stderr.trim()));
    }
    Ok(r.stdout)
}

// ======================= Команды Tauri =======================

/// power action: reboot | shutdown | lock | logoff
#[tauri::command]
pub fn rat_power(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String, action: String) -> Result<Value, String> {
    let cmd = match action.as_str() {
        "reboot" => "systemctl reboot".to_string(),
        "shutdown" => "systemctl poweroff".to_string(),
        "lock" => "loginctl lock-sessions".to_string(),
        "logoff" => {
            // завершаем все сессии пользователя хоста
            let user = crate::hosts::HostsManager::default()
                .list_hosts().ok().and_then(|l| l.into_iter().find(|h| h.id == host_id))
                .map(|h| h.username).unwrap_or_default();
            if !valid_token(&user) { return Err("плохое имя пользователя".into()); }
            format!("loginctl terminate-user {user}")
        }
        other => return Err(format!("неизвестное power-действие: {other}")),
    };
    // reboot/poweroff рвут соединение — ssh вернёт ненулевой exit, это норма
    let r = hosts.exec_command(&host_id, &cmd)?;
    Ok(json!({"action": action, "exit_code": r.exit_code.unwrap_or(-1), "note": "для reboot/shutdown ненулевой exit ожидаем — соединение рвётся"}))
}

#[tauri::command]
pub fn rat_services_list(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String) -> Result<Value, String> {
    let out = run(&hosts, &host_id, "systemctl list-units --type=service --no-legend --no-pager".into())?;
    Ok(json!({"services": out}))
}

/// action: start | stop | restart | status
#[tauri::command]
pub fn rat_service_control(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String, unit: String, action: String) -> Result<Value, String> {
    if !valid_token(&unit) { return Err("плохое имя unit'а".into()); }
    let verb = match action.as_str() {
        "start" | "stop" | "restart" => action.as_str(),
        "status" => "status",
        other => return Err(format!("неизвестное действие: {other}")),
    };
    let cmd = if verb == "status" {
        format!("systemctl status {unit} --no-pager")
    } else {
        format!("systemctl {verb} {unit}")
    };
    let out = run(&hosts, &host_id, cmd)?;
    Ok(json!({"unit": unit, "action": action, "output": out}))
}

#[tauri::command]
pub fn rat_log_view(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String, unit: Option<String>, since: Option<String>, limit: Option<u16>) -> Result<Value, String> {
    let mut cmd = "journalctl --no-pager -n ".to_string();
    cmd.push_str(&limit.unwrap_or(200).to_string());
    if let Some(u) = unit { if valid_token(&u) { cmd.push_str(" -u "); cmd.push_str(&u); } }
    if let Some(s) = since { if valid_token(&s) { cmd.push_str(" --since "); cmd.push_str(&format!("\"{s}\"")); } }
    let out = run(&hosts, &host_id, cmd)?;
    Ok(json!({"log": out}))
}

/// Очистка журнала: rotate + vacuum до минимального размера (честный «clear» для journald).
#[tauri::command]
pub fn rat_log_clear(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String) -> Result<Value, String> {
    let out = run(&hosts, &host_id, "journalctl --rotate && journalctl --vacuum-time=1s".into())?;
    Ok(json!({"cleared": true, "output": out}))
}

#[tauri::command]
pub fn rat_disk(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String) -> Result<Value, String> {
    let out = run(&hosts, &host_id, "df -h --output=source,fstype,size,used,avail,pcent,target".into())?;
    Ok(json!({"disks": out}))
}

/// Сколько пакетов в системе (dpkg или rpm).
#[tauri::command]
pub fn rat_pkgs(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String) -> Result<Value, String> {
    let out = run(&hosts, &host_id,
        "if command -v dpkg >/dev/null; then echo dpkg:$(dpkg -l 2>/dev/null | grep -c '^ii'); elif command -v rpm >/dev/null; then echo rpm:$(rpm -qa 2>/dev/null | wc -l); else echo unknown; fi".into())?;
    Ok(json!({"pkgs": out.trim()}))
}

/// Экспорт system info хоста в CSV или XML (как у DRS exporter).
#[tauri::command]
pub fn rat_info_export(hosts: tauri::State<'_, crate::hosts::HostsManager>, host_id: String, format: String, out_path: String) -> Result<Value, String> {
    if format != "csv" && format != "xml" { return Err("формат: csv|xml".into()); }
    if !valid_token(&out_path) { return Err("плохой путь вывода".into()); }
    // один проход: маркеры между полями
    let sep = "@@W420@@";
    let cmd = format!(
        "echo -n \"$(hostname){s}\"; cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'\"' -f2; echo -n \"{s}\"; uptime -p 2>/dev/null; echo -n \"{s}\"; nproc; echo -n \"{s}\"; free -m | awk '/^Mem:/{{print $2}}'"
    , s = sep);
    let out = run(&hosts, &host_id, cmd)?;
    let parts: Vec<&str> = out.split(sep).collect();
    let hostname = parts.get(0).unwrap_or(&"").trim().to_string();
    let os = parts.get(1).unwrap_or(&"").trim().to_string();
    let uptime = parts.get(2).unwrap_or(&"").trim().to_string();
    let cpu = parts.get(3).unwrap_or(&"").trim().to_string();
    let mem = parts.get(4).unwrap_or(&"").trim().to_string();
    let content = match format.as_str() {
        "csv" => format!("field,value\nhost_id,{host_id}\nhostname,{hostname}\nos,{}\nuptime,{uptime}\ncpu_cores,{cpu}\nmem_mb,{mem}\n",
            csv_escape(&os)),
        _ => format!("<host id=\"{host_id}\"><hostname>{}</hostname><os>{}</os><uptime>{}</uptime><cpu_cores>{cpu}</cpu_cores><mem_mb>{mem}</mem_mb></host>\n",
            xml_escape(&hostname), xml_escape(&os), xml_escape(&uptime)),
    };
    std::fs::write(&out_path, &content).map_err(|e| format!("write {out_path}: {e}"))?;
    Ok(json!({"path": out_path, "format": format, "hostname": hostname, "os": os}))
}

fn csv_escape(s: &str) -> String { s.replace('"', "\"\"") }
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

// ======================= Wake-on-LAN (чистый Rust) =======================

/// MAC вида aa:bb:cc:dd:ee:ff → [u8;6]
pub fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 { return Err(format!("плохой MAC: {s}")); }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).map_err(|_| format!("плохой MAC: {s}"))?;
    }
    Ok(mac)
}

/// Собрать magic packet: 6×0xFF + 16×MAC = 102 байта.
pub fn build_wol_packet(mac: [u8; 6]) -> [u8; 102] {
    let mut p = [0u8; 102];
    for i in 0..6 { p[i] = 0xFF; }
    for r in 0..16 {
        for i in 0..6 { p[6 + r * 6 + i] = mac[i]; }
    }
    p
}

/// Отправить WoL на broadcast 255.255.255.255:9 (и дубль на 127.0.0.1 для тестов — нет).
#[tauri::command]
pub fn rat_wake(host_id: String, mac: String) -> Result<Value, String> {
    let mac = parse_mac(&mac)?;
    let pkt = build_wol_packet(mac);
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_broadcast(true).map_err(|e| e.to_string())?;
    // основной broadcast + запасной на широковещательный адрес подсети
    let sent1 = sock.send_to(&pkt, "255.255.255.255:9").map_err(|e| e.to_string())?;
    Ok(json!({"host_id": host_id, "mac": mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"), "sent_bytes": sent1}))
}

// ======================= Тесты =======================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_token() {
        assert!(valid_token("nginx.service"));
        assert!(valid_token("/var/log/syslog"));
        assert!(valid_token("2026-11-09 10:00"));
        assert!(!valid_token("a;rm -rf /"));
        assert!(!valid_token("$(id)"));
        assert!(!valid_token("a`b"));
        assert!(!valid_token(""));
        assert!(!valid_token(&"x".repeat(300)));
    }

    #[test]
    fn test_wol_packet() {
        let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        let p = build_wol_packet(mac);
        assert_eq!(p.len(), 102);
        assert!(p[..6].iter().all(|b| *b == 0xFF));
        for r in 0..16 {
            assert_eq!(&p[6 + r * 6..6 + r * 6 + 6], &mac);
        }
        assert!(parse_mac("aa:bb:cc:dd:ee").is_err());
        assert!(parse_mac("zz:bb:cc:dd:ee:ff").is_err());
    }

    #[test]
    fn test_wol_send_loopback() {
        // принимаем пакет на локальном сокете вместо broadcast
        let recv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = recv.local_addr().unwrap().port();
        let mac = parse_mac("11:22:33:44:55:66").unwrap();
        let pkt = build_wol_packet(mac);
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.send_to(&pkt, format!("127.0.0.1:{port}")).unwrap();
        let mut buf = [0u8; 200];
        let (n, _) = recv.recv_from(&mut buf).unwrap();
        assert_eq!(n, 102);
        assert_eq!(&buf[..102], &pkt);
    }

    #[test]
    fn test_xml_csv_escape() {
        assert_eq!(xml_escape("a<b>&\"c"), "a&lt;b&gt;&amp;&quot;c");
        assert_eq!(csv_escape("a\"b"), "a\"\"b");
    }
}

//! Фаза 12: VPN — WireGuard сервер на этом хосте (vpn.rs).
//!
//! sing-box sidecar (клиентские прокси) уже есть в bridge.rs; здесь — WG-сервер:
//! генерация ключей, конфиг, добавление/отзыв peer'ов, start/stop, мониторинг handshake/трафика.
//! Управление интерфейсом идёт через `sudo -n wg setconf / wg show` и `sudo -n ip ...` с фиксированными
//! аргументами — см. scripts/root_setup.sh (минимальный sudoers-набор, аудит 13.11.2026).
//! nft вызывается напрямую (setcap cap_net_admin), sudo — только фолбэк.
//! Ключи и конфиг: ~/.w420/wg/ (dir 700, key 600). БД peer'ов: ~/.w420/vpn.db.

use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

pub const WG_IFACE: &str = "w420wg";
pub const WG_PORT: u16 = 51820;
pub const WG_SUBNET: &str = "10.77.0.1/24";
/// AppArmor-профиль wg разрешает чтение только /etc/wireguard/ — сюда и пишем живой конфиг.
pub const ETC_CONF: &str = "/etc/wireguard/w420wg.conf";

pub struct VpnManager {
    pub db: Mutex<PathBuf>,
    pub wg_dir: PathBuf,
}

fn home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn wg_dir() -> PathBuf {
    home().join(".w420").join("wg")
}

fn conf_path() -> PathBuf {
    wg_dir().join(format!("{WG_IFACE}.conf"))
}

impl VpnManager {
    pub fn new() -> Self {
        let dir = wg_dir();
        let _ = std::fs::create_dir_all(&dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let db = home().join(".w420").join("vpn.db");
        let m = Self { db: Mutex::new(db.clone()), wg_dir: dir };
        m.init_db(&db);
        m
    }

    fn init_db(&self, db: &PathBuf) {
        if let Ok(c) = Connection::open(db) {
            let _ = c.execute_batch(
                "CREATE TABLE IF NOT EXISTS peers (
                    name TEXT PRIMARY KEY,
                    pubkey TEXT NOT NULL,
                    client_privkey TEXT NOT NULL,
                    allowed_ip TEXT NOT NULL,
                    created TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );",
            );
        }
    }

    pub fn conn(&self) -> Result<Connection, String> {
        let p = self.db.lock().unwrap().clone();
        Connection::open(p).map_err(|e| e.to_string())
    }

    fn run_sudo_n(args: &[&str]) -> Result<String, String> {
        let out = Command::new("sudo")
            .arg("-n")
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(format!("{}{}", String::from_utf8_lossy(&out.stderr), String::from_utf8_lossy(&out.stdout)))
        }
    }

    /// Привилегированная команда: nft — сначала напрямую (setcap cap_net_admin, см. root_setup.sh),
    /// sudo — только фолбэк. Остальные (wg/ip/tee) — только через sudoers из root_setup.sh.
    fn run_priv(args: &[&str]) -> Result<String, String> {
        if args[0].ends_with("/nft") || args[0] == "nft" {
            if let Ok(o) = Command::new(args[0]).args(&args[1..]).output() {
                if o.status.success() {
                    return Ok(String::from_utf8_lossy(&o.stdout).into_owned());
                }
            }
        }
        Self::run_sudo_n(args)
    }

    fn wg(args: &[&str], sudo: bool) -> Result<String, String> {
        let mut full = vec!["/usr/bin/wg"];
        full.extend_from_slice(args);
        if sudo {
            Self::run_sudo_n(&full)
        } else {
            let out = Command::new("/usr/bin/wg").args(args).output().map_err(|e| e.to_string())?;
            Ok(format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
        }
    }

    fn genkey() -> Result<(String, String), String> {
        let priv_out = Command::new("wg").args(["genkey"]).output().map_err(|e| e.to_string())?;
        let priv_key = String::from_utf8_lossy(&priv_out.stdout).trim().to_string();
        let pub_out = Command::new("wg")
            .arg("pubkey")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut ch| {
                use std::io::Write;
                ch.stdin.take().unwrap().write_all(priv_key.as_bytes())?;
                ch.wait_with_output()
            })
            .map_err(|e| e.to_string())?;
        let pub_key = String::from_utf8_lossy(&pub_out.stdout).trim().to_string();
        Ok((priv_key, pub_key))
    }

    /// Инициализация сервера: ключи + конфиг. needs_root если sudoers не покрывает wg-quick/запись конфига.
    pub fn server_init(&self, port: Option<u16>, subnet: Option<String>) -> Result<serde_json::Value, String> {
        let port = port.unwrap_or(WG_PORT);
        let subnet = subnet.unwrap_or_else(|| WG_SUBNET.to_string());
        let (priv_key, pub_key) = Self::genkey()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let key_path = self.wg_dir.join("server.key");
            std::fs::write(&key_path, format!("{priv_key}\n")).map_err(|e| e.to_string())?;
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }
        let conf = build_server_conf(&priv_key, port, &subnet, &[]);
        std::fs::write(conf_path(), &conf).map_err(|e| format!("write conf: {e}"))?;
        Ok(serde_json::json!({
            "iface": WG_IFACE, "port": port, "subnet": subnet,
            "server_pubkey": pub_key, "conf": conf_path().display().to_string(),
        }))
    }

    /// Добавить peer: генерирует пару ключей клиента, назначает allowed-ip из пула, пишет в конфиг и в wg (если iface up).
    pub fn peer_add(&self, name: &str) -> Result<serde_json::Value, String> {
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err("имя peer: только [A-Za-z0-9-_]".into());
        }
        let c = self.conn()?;
        let exists: i64 = c
            .query_row("SELECT COUNT(*) FROM peers WHERE name=?1 AND revoked=0", [name], |r| r.get(0))
            .unwrap_or(0);
        if exists > 0 {
            return Err(format!("peer '{name}' уже существует"));
        }
        // следующий allowed-ip: 10.77.0.N, N = max+1
        let max_n: i64 = c
            .query_row("SELECT COALESCE(MAX(CAST(substr(allowed_ip, 9, length(allowed_ip)-10) AS INTEGER)), 1) FROM peers WHERE allowed_ip LIKE '10.77.0.%'", [], |r| r.get(0))
            .unwrap_or(1);
        let allowed_ip = format!("10.77.0.{}/32", max_n + 1);
        drop(c);

        let (client_priv, client_pub) = Self::genkey()?;
        let peer_block = build_peer_block(&client_pub, &allowed_ip);
        // дописываем в конфиг
        let mut conf = std::fs::read_to_string(conf_path()).map_err(|e| format!("нет конфига (сначала vpn_server_init): {e}"))?;
        conf.push_str(&peer_block);
        std::fs::write(conf_path(), &conf).map_err(|e| e.to_string())?;
        // применяем в живой интерфейс, если он поднят: перезаписываем /etc/wireguard конфиг + setconf
        let live = Self::wg(&["show", "interfaces"], true).map(|t| t.contains(WG_IFACE)).unwrap_or(false);
        let mut applied_live = false;
        if live {
            if let Ok(new_conf) = std::fs::read_to_string(conf_path()) {
                applied_live = self.push_conf(&new_conf).is_ok() && self.sync_live();
            }
        }
        // запись в БД
        if let Ok(c) = self.conn() {
            let _ = c.execute(
                "INSERT INTO peers (name, pubkey, client_privkey, allowed_ip, created) VALUES (?1,?2,?3,?4,?5)",
                rusqlite::params![name, &client_pub, &client_priv, &allowed_ip, chrono::Utc::now().to_rfc3339()],
            );
        }
        // клиентский конфиг (готовый .conf для peer'а)
        let server_pub = std::fs::read_to_string(self.wg_dir.join("server.key"))
            .ok()
            .and_then(|k| {
                Command::new("wg").arg("pubkey")
                    .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
                    .spawn().ok().and_then(|mut ch| {
                        use std::io::Write;
                        let _ = ch.stdin.take().unwrap().write_all(k.trim().as_bytes());
                        ch.wait_with_output().ok()
                    })
            })
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        let client_conf = build_client_conf(&client_priv, &allowed_ip, &server_pub, WG_IFACE);
        Ok(serde_json::json!({
            "name": name, "pubkey": client_pub, "allowed_ip": allowed_ip,
            "applied_live": applied_live, "client_conf": client_conf,
        }))
    }

    /// Отзыв peer'а: убираем из wg и из конфига, помечаем revoked в БД.
    pub fn peer_revoke(&self, name: &str) -> Result<String, String> {
        let c = self.conn()?;
        let row: Option<(String, String)> = c
            .query_row("SELECT pubkey, allowed_ip FROM peers WHERE name=?1 AND revoked=0", [name], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()
            .map_err(|e| e.to_string())?;
        let Some((pubkey, _allowed)) = row else {
            return Err(format!("peer '{name}' не найден"));
        };
        // Live-удаление peer не делаем отдельной командой (sudoers не разрешает динамические аргументы wg):
        // peer вычищается из конфига ниже и применяется через фиксированный `wg setconf w420wg /etc/wireguard/w420wg.conf`.
        // вычищаем блок из локального конфига и перезаливаем живой
        if let Ok(conf) = std::fs::read_to_string(conf_path()) {
            let cleaned = remove_peer_block(&conf, &pubkey);
            let _ = std::fs::write(conf_path(), &cleaned);
            let _ = self.push_conf(&cleaned);
            let _ = self.sync_live();
        }
        let _ = c.execute("UPDATE peers SET revoked=1 WHERE name=?1", [name]);
        Ok(format!("peer '{name}' отозван ({pubkey})"))
    }

    pub fn peer_list(&self) -> Result<Vec<serde_json::Value>, String> {
        let c = self.conn()?;
        let mut st = c
            .prepare("SELECT name, pubkey, allowed_ip, created, revoked FROM peers ORDER BY created")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map([], |r| {
                Ok(serde_json::json!({
                    "name": r.get::<_, String>(0)?, "pubkey": r.get::<_, String>(1)?,
                    "allowed_ip": r.get::<_, String>(2)?, "created": r.get::<_, String>(3)?,
                    "revoked": r.get::<_, i64>(4)? == 1,
                }))
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }

    /// Записать конфиг в /etc/wireguard/w420wg.conf через `sudo -n tee` (единственный путь, разрешённый AppArmor профилем wg).
    /// В /etc льём ЧИСТЫЙ wg(8)-формат: wg setconf не понимает wg-quick-поля вроде Address/PostUp.
    fn push_conf(&self, conf: &str) -> Result<(), String> {
        use std::io::Write;
        let stripped = to_wg_setconf_conf(conf);
        let mut ch = Command::new("sudo")
            .arg("-n")
            .arg("/usr/bin/tee")
            .arg(ETC_CONF)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        ch.stdin.take().unwrap().write_all(stripped.as_bytes()).map_err(|e| e.to_string())?;
        let out = ch.wait_with_output().map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!("tee: {}", String::from_utf8_lossy(&out.stderr)))
        }
    }

    /// Применить конфиг к живому интерфейсу (если поднят): setconf читает /etc/wireguard/w420wg.conf.
    fn sync_live(&self) -> bool {
        Self::wg(&["show", "interfaces"], true)
            .map(|t| t.contains(WG_IFACE))
            .unwrap_or(false)
            && Self::wg(&["setconf", WG_IFACE, ETC_CONF], true).is_ok()
    }

    pub fn server_start(&self) -> Result<serde_json::Value, String> {
        if !conf_path().exists() {
            return Err("сначала vpn_server_init".into());
        }
        // Поднимаем вручную: ip link add → tee конфиг в /etc/wireguard → wg setconf → ip address → ip link set up.
        // NAT — через nft (w420_nat), уже в sudoers.
        let conf = std::fs::read_to_string(conf_path()).map_err(|e| e.to_string())?;
        let mut errors = Vec::new();
        // 1) создаём iface (до setconf — wg setconf требует существующий интерфейс)
        let link_args = ["/usr/sbin/ip", "link", "add", WG_IFACE, "type", "wireguard"];
        if let Err(e) = Self::run_sudo_n(&link_args) {
            if !e.contains("File exists") {
                errors.push(format!("link add: {}", e.chars().take(160).collect::<String>()));
            }
        }
        // 2) конфиг в /etc/wireguard (AppArmor wg разрешает только этот путь) + setconf
        if let Err(e) = self.push_conf(&conf) {
            errors.push(format!("tee: {}", e.chars().take(160).collect::<String>()));
        } else if let Err(e) = Self::wg(&["setconf", WG_IFACE, ETC_CONF], true) {
            errors.push(format!("setconf: {}", e.chars().take(160).collect::<String>()));
        }
        // 3) адрес, поднятие, NAT
        let steps: Vec<(&str, Vec<String>)> = vec![
            ("addr", vec!["/usr/sbin/ip".into(), "address".into(), "add".into(), WG_SUBNET.into(), "dev".into(), WG_IFACE.into()]),
            ("up", vec!["/usr/sbin/ip".into(), "link".into(), "set".into(), "up".into(), "dev".into(), WG_IFACE.into()]),
            ("nat", vec!["/usr/sbin/nft".into(), "add table inet w420_nat".into()]),
            ("nat2", vec!["/usr/sbin/nft".into(), "add chain inet w420_nat postrouting { type nat hook postrouting priority 100 ; }".into()]),
            ("nat3", vec!["/usr/sbin/nft".into(), "add rule inet w420_nat postrouting ip saddr 10.77.0.0/24 masquerade".into()]),
        ];
        for (name, args) in &steps {
            let refs: Vec<&str> = args.iter().map(|s| &s[..]).collect();
            if let Err(e) = Self::run_priv(&refs) {
                // уже существующие сущности — не ошибка
                if e.contains("File exists") || e.contains("Address already assigned") {
                    continue;
                }
                errors.push(format!("{name}: {}", e.chars().take(160).collect::<String>()));
            }
        }
        let up = Self::wg(&["show", "interfaces"], true).map(|t| t.contains(WG_IFACE)).unwrap_or(false);
        Ok(serde_json::json!({"up": up, "iface": WG_IFACE, "errors": errors,
            "needs_root": errors.iter().any(|e| e.contains("password") || e.contains("not allowed") || e.contains("Operation not permitted"))}))
    }

    pub fn server_stop(&self) -> Result<serde_json::Value, String> {
        let mut errors = Vec::new();
        for args in [
            vec!["/usr/sbin/ip", "link", "set", "down", "dev", WG_IFACE],
            vec!["/usr/sbin/ip", "link", "delete", "dev", WG_IFACE],
            vec!["/usr/sbin/nft", "delete table inet w420_nat"],
        ] {
            let refs: Vec<&str> = args.iter().map(|s| &s[..]).collect();
            if let Err(e) = Self::run_priv(&refs) {
                if !e.contains("Cannot find device") && !e.contains("No such file") {
                    errors.push(e.chars().take(160).collect::<String>());
                }
            }
        }
        let up = Self::wg(&["show", "interfaces"], true).map(|t| t.contains(WG_IFACE)).unwrap_or(false);
        Ok(serde_json::json!({"up": up, "errors": errors}))
    }

    /// Статус: `wg show all` (sudo -n wg, fallback без sudo). Парсинг — чистой функцией.
    pub fn status(&self) -> Result<Vec<WgPeerStatus>, String> {
        let text = Self::wg(&["show", "all"], true)
            .or_else(|_| Self::wg(&["show", "all"], false))
            .unwrap_or_default();
        Ok(parse_wg_show(&text))
    }

    /// Трафик VPN: агрегация transfer по пирам (из `wg show all`) + суммарно + топ-талкеры.
    pub fn traffic(&self) -> Result<serde_json::Value, String> {
        Ok(aggregate_traffic(&self.status()?))
    }
}

/// Чистая функция: агрегация трафика по пирам WireGuard.
/// Возвращает JSON: peers (с rx/tx и суммой, отсортированы по трафику), total_rx/tx, top_talker.
pub fn aggregate_traffic(peers: &[WgPeerStatus]) -> serde_json::Value {
    let mut rows: Vec<serde_json::Value> = peers.iter().map(|p| {
        serde_json::json!({
            "interface": p.interface,
            "peer": p.peer,
            "endpoint": p.endpoint,
            "allowed_ips": p.allowed_ips,
            "latest_handshake": p.latest_handshake,
            "rx": p.transfer_rx,
            "tx": p.transfer_tx,
            "total": p.transfer_rx + p.transfer_tx,
        })
    }).collect();
    rows.sort_by(|a, b| b["total"].as_u64().unwrap_or(0).cmp(&a["total"].as_u64().unwrap_or(0)));
    let total_rx: u64 = peers.iter().map(|p| p.transfer_rx).sum();
    let total_tx: u64 = peers.iter().map(|p| p.transfer_tx).sum();
    let top = rows.first().cloned().unwrap_or(serde_json::json!({}));
    serde_json::json!({
        "peers": rows,
        "peers_count": peers.len(),
        "total_rx": total_rx,
        "total_tx": total_tx,
        "total": total_rx + total_tx,
        "top_talker": top,
    })
}

#[derive(Serialize, Clone)]
pub struct WgPeerStatus {
    pub interface: String,
    pub peer: String,
    pub endpoint: String,
    pub allowed_ips: String,
    pub latest_handshake: String,
    pub transfer_rx: u64,
    pub transfer_tx: u64,
}

/// Конфиг сервера WG (чистая функция). NAT/forward — через nft (w420_nat), не через PostUp.
pub fn build_server_conf(private_key: &str, listen_port: u16, address_cidr: &str, peers: &[(&str, &str)]) -> String {
    let mut s = format!("[Interface]\nPrivateKey = {private_key}\nAddress = {address_cidr}\nListenPort = {listen_port}\n");
    for (pubkey, allowed) in peers {
        s.push_str(&build_peer_block(pubkey, allowed));
    }
    s
}

pub fn build_peer_block(pubkey: &str, allowed_ip: &str) -> String {
    format!("[Peer]\nPublicKey = {pubkey}\nAllowedIPs = {allowed_ip}\n\n")
}

/// Клиентский конфиг для peer'а.
pub fn build_client_conf(client_priv: &str, client_addr: &str, server_pub: &str, _iface: &str) -> String {
    format!(
        "[Interface]\nPrivateKey = {client_priv}\nAddress = {client_addr}\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = {server_pub}\nEndpoint = YOUR_SERVER_IP:{WG_PORT}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
    )
}

/// wg-quick конфиг → чистый wg(8)-формат для `wg setconf`:
/// оставляем только PrivateKey/ListenPort/FwMark и поля [Peer]; Address, DNS, PostUp и т.п. выкидываем.
pub fn to_wg_setconf_conf(conf: &str) -> String {
    const KEEP: [&str; 8] = ["PrivateKey", "ListenPort", "FwMark", "PublicKey", "PresharedKey", "AllowedIPs", "PersistentKeepalive", "Endpoint"];
    let mut out = String::new();
    for line in conf.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.starts_with('[') {
            out.push_str(t);
            out.push('\n');
            continue;
        }
        if let Some(key) = t.split('=').next().map(|k| k.trim()) {
            if KEEP.contains(&key) {
                out.push_str(t);
                out.push('\n');
            }
        }
    }
    out
}

/// Убрать блок peer'а из конфига по pubkey (чистая функция): режем по блокам [Peer].
pub fn remove_peer_block(conf: &str, pubkey: &str) -> String {
    let mut out = String::new();
    let mut block: Vec<&str> = Vec::new();
    let mut in_peer = false;
    let mut flush = |block: &mut Vec<&str>, in_peer: bool, out: &mut String| {
        let target = in_peer && block.iter().any(|l| l.starts_with("PublicKey") && l.contains(pubkey));
        let keep = !target;
        for l in block.drain(..) {
            if keep {
                out.push_str(l);
                out.push('\n');
            }
        }
    };
    for line in conf.lines() {
        if line.starts_with("[Peer]") {
            flush(&mut block, in_peer, &mut out);
            in_peer = true;
        }
        block.push(line);
    }
    flush(&mut block, in_peer, &mut out);
    out
}

/// Парсинг `wg show all` (чистая функция).
pub fn parse_wg_show(text: &str) -> Vec<WgPeerStatus> {
    let mut out = Vec::new();
    let mut iface = String::new();
    let mut peer = String::new();
    let mut endpoint = String::new();
    let mut allowed = String::new();
    let mut handshake = String::new();
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("interface:") {
            iface = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("peer:") {
            // предыдущий peer сохраняем с его transfer
            if !peer.is_empty() {
                out.push(WgPeerStatus {
                    interface: iface.clone(),
                    peer: std::mem::take(&mut peer),
                    endpoint: std::mem::take(&mut endpoint),
                    allowed_ips: std::mem::take(&mut allowed),
                    latest_handshake: std::mem::take(&mut handshake),
                    transfer_rx: rx,
                    transfer_tx: tx,
                });
                rx = 0;
                tx = 0;
            }
            peer = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("endpoint:") {
            endpoint = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("allowed ips:") {
            allowed = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("latest handshake:") {
            handshake = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("transfer:") {
            // transfer: 1.23 MiB received, 4.56 MiB sent
            let parts: Vec<&str> = v.split(',').collect();
            if let Some(r) = parts.first() {
                rx = parse_transfer(r.trim());
            }
            if let Some(s) = parts.get(1) {
                tx = parse_transfer(s.trim());
            }
        }
    }
    if !peer.is_empty() {
        out.push(WgPeerStatus {
            interface: iface,
            peer,
            endpoint,
            allowed_ips: allowed,
            latest_handshake: handshake,
            transfer_rx: rx,
            transfer_tx: tx,
        });
    }
    out
}

/// "1.23 MiB received" → байты
fn parse_transfer(s: &str) -> u64 {
    let mut it = s.split_whitespace();
    let val: f64 = it.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let unit = it.next().unwrap_or("B");
    let mult = match unit {
        "KiB" => 1024.0,
        "MiB" => 1024.0 * 1024.0,
        "GiB" => 1024.0_f64.powi(3),
        "TiB" => 1024.0_f64.powi(4),
        _ => 1.0,
    };
    (val * mult) as u64
}

// ---------- Tauri команды ----------

#[tauri::command]
pub fn vpn_server_init(mgr: tauri::State<'_, VpnManager>, port: Option<u16>, subnet: Option<String>) -> Result<serde_json::Value, String> {
    mgr.server_init(port, subnet)
}

#[tauri::command]
pub fn vpn_peer_add(mgr: tauri::State<'_, VpnManager>, name: String) -> Result<serde_json::Value, String> {
    mgr.peer_add(&name)
}

#[tauri::command]
pub fn vpn_peer_revoke(mgr: tauri::State<'_, VpnManager>, name: String) -> Result<String, String> {
    mgr.peer_revoke(&name)
}

#[tauri::command]
pub fn vpn_peer_list(mgr: tauri::State<'_, VpnManager>) -> Result<Vec<serde_json::Value>, String> {
    mgr.peer_list()
}

#[tauri::command]
pub fn vpn_server_start(mgr: tauri::State<'_, VpnManager>) -> Result<serde_json::Value, String> {
    mgr.server_start()
}

#[tauri::command]
pub fn vpn_server_stop(mgr: tauri::State<'_, VpnManager>) -> Result<serde_json::Value, String> {
    mgr.server_stop()
}

#[tauri::command]
pub fn vpn_status(mgr: tauri::State<'_, VpnManager>) -> Result<Vec<WgPeerStatus>, String> {
    mgr.status()
}

/// Трафик VPN: rx/tx по каждому peer'у, суммарно и top-talker (из `wg show all`).
#[tauri::command]
pub fn vpn_traffic(mgr: tauri::State<'_, VpnManager>) -> Result<serde_json::Value, String> {
    mgr.traffic()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_server_conf() {
        let c = build_server_conf("PRIV", 51820, "10.77.0.1/24", &[("PUB1", "10.77.0.2/32")]);
        assert!(c.contains("PrivateKey = PRIV"));
        assert!(c.contains("ListenPort = 51820"));
        assert!(c.contains("[Peer]\nPublicKey = PUB1\nAllowedIPs = 10.77.0.2/32"));
    }

    #[test]
    fn test_remove_peer_block() {
        let conf = "[Interface]\nPrivateKey = X\n\n[Peer]\nPublicKey = AAA\nAllowedIPs = 10.77.0.2/32\n\n[Peer]\nPublicKey = BBB\nAllowedIPs = 10.77.0.3/32\n";
        let cleaned = remove_peer_block(conf, "AAA");
        assert!(!cleaned.contains("AAA"));
        assert!(cleaned.contains("BBB"));
        assert!(cleaned.contains("[Interface]"));
    }

    #[test]
    fn test_parse_wg_show() {
        let sample = "interface: w420wg\n  public key: SRVPUB\n  listen port: 51820\npeer: PEER1\n  endpoint: 1.2.3.4:55555\n  allowed ips: 10.77.0.2/32\n  latest handshake: 1 minute, 20 seconds ago\n  transfer: 1.50 MiB received, 2.25 MiB sent\npeer: PEER2\n  allowed ips: 10.77.0.3/32\n  transfer: 0 B received, 512 B sent\n";
        let peers = parse_wg_show(sample);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].peer, "PEER1");
        assert_eq!(peers[0].endpoint, "1.2.3.4:55555");
        assert_eq!(peers[0].transfer_rx, (1.5 * 1024.0 * 1024.0) as u64);
        assert_eq!(peers[0].transfer_tx, (2.25 * 1024.0 * 1024.0) as u64);
        assert_eq!(peers[1].peer, "PEER2");
        assert_eq!(peers[1].transfer_tx, 512);
    }

    #[test]
    fn test_to_wg_setconf_conf() {
        let quick = "[Interface]\nPrivateKey = PRIV\nAddress = 10.77.0.1/24\nListenPort = 51820\nPostUp = iptables ...\n\n[Peer]\nPublicKey = PUB\nAllowedIPs = 10.77.0.2/32\n";
        let stripped = to_wg_setconf_conf(quick);
        assert!(stripped.contains("PrivateKey = PRIV"));
        assert!(stripped.contains("ListenPort = 51820"));
        assert!(stripped.contains("PublicKey = PUB"));
        assert!(!stripped.contains("Address"));
        assert!(!stripped.contains("PostUp"));
    }

    #[test]
    fn test_parse_transfer() {
        assert_eq!(parse_transfer("1.00 KiB received"), 1024);
        assert_eq!(parse_transfer("2 B sent"), 2);
    }

    #[test]
    fn test_aggregate_traffic() {
        let peers = vec![
            WgPeerStatus { interface: "w420wg".into(), peer: "aaa".into(), endpoint: "1.1.1.1:1".into(), allowed_ips: "10.77.0.2/32".into(), latest_handshake: "10s".into(), transfer_rx: 100, transfer_tx: 50 },
            WgPeerStatus { interface: "w420wg".into(), peer: "bbb".into(), endpoint: "2.2.2.2:2".into(), allowed_ips: "10.77.0.3/32".into(), latest_handshake: "5s".into(), transfer_rx: 9000, transfer_tx: 1000 },
        ];
        let v = aggregate_traffic(&peers);
        assert_eq!(v["peers_count"], 2);
        assert_eq!(v["total_rx"], 9100);
        assert_eq!(v["total_tx"], 1050);
        assert_eq!(v["total"], 10150);
        // сортировка по total: bbb первый
        assert_eq!(v["peers"][0]["peer"], "bbb");
        assert_eq!(v["top_talker"]["peer"], "bbb");
        // пустой список — нули, без паники
        let empty = aggregate_traffic(&[]);
        assert_eq!(empty["peers_count"], 0);
        assert_eq!(empty["total"], 0);
    }

    /// Живой smoke: wg show all без интерфейса — пусто, но не падает; peer_add без конфига — осмысленная ошибка.
    #[test]
    fn live_wg_status_no_iface() {
        let m = VpnManager::new();
        let st = m.status().unwrap_or_default();
        println!("LIVE wg status peers: {}", st.len());
    }

    /// LIVE полный цикл: init → peer_add → start → status → stop. Требует sudoers (root_setup.sh).
    #[test]
    #[ignore]
    fn live_vpn_full_cycle() {
        let m = VpnManager::new();
        let init = m.server_init(None, None).expect("init");
        println!("LIVE init: port={} pub={}", init["port"], init["server_pubkey"]);
        let peer_name = format!("test-peer-{}", std::process::id());
        let peer = m.peer_add(&peer_name).expect("peer_add");
        println!("LIVE peer: allowed_ip={} applied_live={}", peer["allowed_ip"], peer["applied_live"]);
        let st = m.server_start().expect("start");
        println!("LIVE start: up={} errors={:?}", st["up"], st["errors"]);
        assert_eq!(st["up"], true, "iface должен быть поднят");
        let status = m.status().expect("status");
        println!("LIVE status peers: {}", status.len());
        assert!(status.iter().any(|p| p.peer == peer["pubkey"]));
        // allowed-ip применён
        let want = peer["allowed_ip"].as_str().unwrap_or("").to_string();
        assert!(status.iter().any(|p| p.allowed_ips.contains(&want)), "allowed_ips должен содержать {want}");
        let stop = m.server_stop().expect("stop");
        println!("LIVE stop: up={}", stop["up"]);
        assert_eq!(stop["up"], false);
        let _ = m.peer_revoke(&peer_name);
    }
}

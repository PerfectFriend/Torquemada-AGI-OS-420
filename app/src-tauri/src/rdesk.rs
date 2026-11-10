//! rdesk.rs — Этап 27 (DameWare Parity): Remote Desktop core.
//!
//! Менеджер remote-сессий: VNC идёт in-app через sidecar `websockify`
//! (VNC → WebSocket, фронтенд рисует кадры на canvas своим RFB-клиентом),
//! RDP — через sidecar `xfreerdp` отдельным окном ОС (на десктопе).
//! Скриншот — собственным минимальным RFB-клиентом (Raw encoding) → PNG.
//! На хосте без sidecar'ов — честная ошибка, не молчаливый отказ.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Протокол сессии.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Vnc,
    Rdp,
}

/// Состояние сессии.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessState {
    Connecting,
    Live,
    Closed,
}

/// Одна remote-сессия.
#[derive(Serialize, Clone)]
pub struct Session {
    pub id: u32,
    pub host: String,       // ip из инвентаря hosts
    pub host_name: String,
    pub proto: Proto,
    pub port: u16,
    pub ws_port: Option<u16>, // для VNC — порт websockify
    pub state: SessState,
    pub locked: bool,  // lock input (client-side флаг + UI overlay)
    pub blanked: bool, // blank screen (UI overlay)
    pub viewers: u32,  // сколько UI-вкладок смотрит (оценочно)
    pub role: String,  // Этап 28: "controller" | "viewer" — кто последний открыл, тот контролирует
}

/// Сообщение in-session чата (Этап 28).
#[derive(Serialize, Deserialize, Clone)]
pub struct ChatMsg {
    pub ts: u64,
    pub author: String,
    pub text: String,
}

pub struct RdeskManager {
    pub sessions: Mutex<HashMap<u32, Session>>,
    pub procs: Mutex<HashMap<u32, Child>>,
    pub next_id: AtomicU32,
    /// Этап 28: чат-логи по сессиям (память + дубль на диск в ~/.w420/rdesk/)
    pub chat: Mutex<HashMap<u32, Vec<ChatMsg>>>,
    /// Переопределяемая команда sidecar (для тестов).
    pub vnc_bridge: String, // напр. "websockify"
    pub rdp_client: String, // напр. "xfreerdp"
}

impl Default for RdeskManager {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            procs: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
            chat: Mutex::new(HashMap::new()),
            vnc_bridge: "websockify".to_string(),
            rdp_client: "xfreerdp".to_string(),
        }
    }
}

fn find_binary(name: &str) -> Option<String> {
    if let Ok(paths) = std::env::var("PATH") {
        for p in paths.split(':') {
            let c = format!("{p}/{name}");
            if std::path::Path::new(&c).is_file() {
                return Some(c);
            }
        }
    }
    None
}

/// Найти хост в инвентаре hosts (ip + имя + username).
fn host_info(host_id: &str) -> Result<(String, String, String), String> {
    let home = std::env::var("HOME").map_err(|_| "нет HOME".to_string())?;
    let p = format!("{home}/.w420/hosts.json");
    let s = std::fs::read_to_string(&p).map_err(|_| "инвентарь hosts пуст — добавьте хост".to_string())?;
    let v: Value = serde_json::from_str(&s).map_err(|e| format!("hosts.json: {e}"))?;
    let arr = v.as_array().cloned().unwrap_or_default();
    for h in arr {
        if h.get("id").and_then(|i| i.as_str()) == Some(host_id) {
            let ip = h.get("ip").and_then(|i| i.as_str()).unwrap_or("").to_string();
            let name = h.get("name").and_then(|i| i.as_str()).unwrap_or("").to_string();
            let user = h.get("username").and_then(|i| i.as_str()).unwrap_or("root").to_string();
            if ip.is_empty() {
                return Err("у хоста нет IP".into());
            }
            return Ok((ip, name, user));
        }
    }
    Err(format!("хост {host_id} не найден в инвентаре"))
}

impl RdeskManager {
    /// Открыть сессию. VNC: websockify sidecar (ws_port → host:port). RDP: xfreerdp окном.
    pub fn connect(&self, host_id: &str, proto: Proto, port: Option<u16>) -> Result<Session, String> {
        let (ip, name, user) = host_info(host_id)?;
        let port = port.unwrap_or(match proto { Proto::Vnc => 5900, Proto::Rdp => 3389 });
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let ws_port = match proto {
            Proto::Vnc => {
                let bin = find_binary(&self.vnc_bridge)
                    .ok_or_else(|| format!("sidecar '{}' не найден в PATH — установите websockify", self.vnc_bridge))?;
                // свободный порт для ws
                let ws = (16900 + (id % 500) * 2) as u16;
                let child = Command::new(&bin)
                    .arg(ws.to_string())
                    .arg(format!("{ip}:{port}"))
                    .spawn()
                    .map_err(|e| format!("spawn {bin}: {e}"))?;
                self.procs.lock().unwrap().insert(id, child);
                Some(ws)
            }
            Proto::Rdp => {
                let bin = find_binary(&self.rdp_client)
                    .ok_or_else(|| format!("sidecar '{}' не найден в PATH — установите freerdp", self.rdp_client))?;
                let child = Command::new(&bin)
                    .args([format!("/v:{ip}:{port}"), format!("/u:{user}"), "/f".into()])
                    .spawn()
                    .map_err(|e| format!("spawn {bin}: {e}"))?;
                self.procs.lock().unwrap().insert(id, child);
                None
            }
        };
        let s = Session {
            id, host: ip, host_name: name, proto, port, ws_port,
            state: SessState::Live, locked: false, blanked: false, viewers: 1,
            role: "controller".to_string(),
        };
        self.sessions.lock().unwrap().insert(id, s.clone());
        Ok(s)
    }

    pub fn disconnect(&self, id: u32) -> Result<Value, String> {
        if let Some(mut c) = self.procs.lock().unwrap().remove(&id) {
            let _ = c.kill();
            let _ = c.wait();
        }
        let mut g = self.sessions.lock().unwrap();
        if let Some(mut s) = g.remove(&id) {
            s.state = SessState::Closed;
            Ok(json!({"closed": id}))
        } else {
            Err(format!("сессия {id} не найдена"))
        }
    }

    pub fn list(&self) -> Vec<Session> {
        self.sessions.lock().unwrap().values().cloned().collect()
    }

    pub fn set_flag(&self, id: u32, lock: Option<bool>, blank: Option<bool>, viewer_delta: Option<i32>) -> Result<Session, String> {
        let mut g = self.sessions.lock().unwrap();
        let s = g.get_mut(&id).ok_or(format!("сессия {id} не найдена"))?;
        if let Some(v) = lock { s.locked = v; }
        if let Some(v) = blank { s.blanked = v; }
        if let Some(d) = viewer_delta { s.viewers = (s.viewers as i32 + d).max(0) as u32; }
        Ok(s.clone())
    }

    /// Этап 28: смена роли участника сессии (viewer не шлёт ввод, controller — шлёт).
    pub fn set_role(&self, id: u32, role: &str) -> Result<Session, String> {
        if role != "controller" && role != "viewer" {
            return Err(format!("неизвестная роль: {role}"));
        }
        let mut g = self.sessions.lock().unwrap();
        let s = g.get_mut(&id).ok_or(format!("сессия {id} не найдена"))?;
        s.role = role.to_string();
        Ok(s.clone())
    }

    /// Этап 28: отправить сообщение в чат сессии. Пишем в память + дубль в ~/.w420/rdesk/<id>.chat.jsonl
    pub fn chat_send(&self, id: u32, author: &str, text: &str) -> Result<ChatMsg, String> {
        if !self.sessions.lock().unwrap().contains_key(&id) {
            return Err(format!("сессия {id} не найдена"));
        }
        if text.is_empty() || text.len() > 4096 {
            return Err("пустое сообщение или длиннее 4096".into());
        }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
        let msg = ChatMsg { ts, author: author.to_string(), text: text.to_string() };
        self.chat.lock().unwrap().entry(id).or_default().push(msg.clone());
        if let Ok(home) = std::env::var("HOME") {
            let dir = format!("{home}/.w420/rdesk");
            let _ = std::fs::create_dir_all(&dir);
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(format!("{dir}/{id}.chat.jsonl")) {
                let _ = writeln!(f, "{}", serde_json::to_string(&msg).unwrap_or_default());
            }
        }
        Ok(msg)
    }

    /// Этап 28: прочитать чат с offset (для polling из нескольких UI-вкладок).
    pub fn chat_recv(&self, id: u32, since: usize) -> Result<Vec<ChatMsg>, String> {
        let g = self.chat.lock().unwrap();
        let v = g.get(&id).cloned().unwrap_or_default();
        Ok(v.into_iter().skip(since).collect())
    }

    /// Этап 28: file transfer поверх SSH (scp). Валидация путей — без shell-инъекций: аргументы scp подаём списком.
    fn ssh_target(host_id: &str) -> Result<(String, String), String> {
        let (ip, _name, user) = host_info(host_id)?;
        Ok((format!("{user}@{ip}"), ip))
    }

    pub fn xfer_list(&self, host_id: &str, remote_path: &str) -> Result<String, String> {
        let (target, _) = Self::ssh_target(host_id)?;
        if remote_path.is_empty() || remote_path.contains('\0') {
            return Err("плохой путь".into());
        }
        let out = Command::new("ssh")
            .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=5", &target, "ls", "-la", "--", remote_path])
            .output().map_err(|e| format!("spawn ssh: {e}"))?;
        if !out.status.success() {
            return Err(format!("ssh: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    pub fn xfer_down(&self, host_id: &str, remote_path: &str, local_path: &str) -> Result<Value, String> {
        let (target, _) = Self::ssh_target(host_id)?;
        if remote_path.is_empty() || local_path.is_empty() || remote_path.contains('\0') || local_path.contains('\0') {
            return Err("плохой путь".into());
        }
        let out = Command::new("scp")
            .args(["-O", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", &format!("{target}:{remote_path}"), local_path])
            .output().map_err(|e| format!("spawn scp: {e}"))?;
        if !out.status.success() {
            return Err(format!("scp: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        let meta = std::fs::metadata(local_path).map_err(|e| e.to_string())?;
        Ok(json!({"ok": true, "local": local_path, "bytes": meta.len()}))
    }

    pub fn xfer_up(&self, host_id: &str, local_path: &str, remote_path: &str) -> Result<Value, String> {
        let (target, _) = Self::ssh_target(host_id)?;
        if remote_path.is_empty() || local_path.is_empty() || remote_path.contains('\0') || local_path.contains('\0') {
            return Err("плохой путь".into());
        }
        if !std::path::Path::new(local_path).is_file() {
            return Err(format!("локальный файл не найден: {local_path}"));
        }
        let out = Command::new("scp")
            .args(["-O", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", local_path, &format!("{target}:{remote_path}")])
            .output().map_err(|e| format!("spawn scp: {e}"))?;
        if !out.status.success() {
            return Err(format!("scp: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(json!({"ok": true, "remote": format!("{target}:{remote_path}")}))
    }
}

// ======================= Команды Tauri =======================

#[tauri::command]
pub fn rdesk_sessions(mgr: tauri::State<'_, RdeskManager>) -> Result<Value, String> {
    let mut l = mgr.list();
    l.sort_by_key(|s| s.id);
    Ok(json!({"sessions": l, "count": l.len()}))
}

#[tauri::command]
pub fn rdesk_connect(
    mgr: tauri::State<'_, RdeskManager>,
    host_id: String,
    proto: Proto,
    port: Option<u16>,
) -> Result<Value, String> {
    let s = mgr.connect(&host_id, proto, port)?;
    Ok(serde_json::to_value(s).map_err(|e| e.to_string())?)
}

#[tauri::command]
pub fn rdesk_disconnect(mgr: tauri::State<'_, RdeskManager>, id: u32) -> Result<Value, String> {
    mgr.disconnect(id)
}

#[tauri::command]
pub fn rdesk_lock_input(mgr: tauri::State<'_, RdeskManager>, id: u32, locked: bool) -> Result<Value, String> {
    let s = mgr.set_flag(id, Some(locked), None, None)?;
    Ok(serde_json::to_value(s).map_err(|e| e.to_string())?)
}

#[tauri::command]
pub fn rdesk_blank_screen(mgr: tauri::State<'_, RdeskManager>, id: u32, blanked: bool) -> Result<Value, String> {
    let s = mgr.set_flag(id, None, Some(blanked), None)?;
    Ok(serde_json::to_value(s).map_err(|e| e.to_string())?)
}

#[tauri::command]
pub fn rdesk_viewer_join(mgr: tauri::State<'_, RdeskManager>, id: u32, delta: i32) -> Result<Value, String> {
    let s = mgr.set_flag(id, None, None, Some(delta))?;
    Ok(json!({"id": s.id, "viewers": s.viewers}))
}

// ===== Этап 28: multi-admin роли, in-session чат, file transfer =====

#[tauri::command]
pub fn rdesk_set_role(mgr: tauri::State<'_, RdeskManager>, id: u32, role: String) -> Result<Value, String> {
    let s = mgr.set_role(id, &role)?;
    Ok(serde_json::to_value(s).map_err(|e| e.to_string())?)
}

#[tauri::command]
pub fn rdesk_chat_send(mgr: tauri::State<'_, RdeskManager>, id: u32, author: String, text: String) -> Result<Value, String> {
    let m = mgr.chat_send(id, &author, &text)?;
    Ok(serde_json::to_value(m).map_err(|e| e.to_string())?)
}

#[tauri::command]
pub fn rdesk_chat_recv(mgr: tauri::State<'_, RdeskManager>, id: u32, since: usize) -> Result<Value, String> {
    let msgs = mgr.chat_recv(id, since)?;
    Ok(json!({"messages": msgs, "count": msgs.len()}))
}

#[tauri::command]
pub fn rdesk_xfer_list(mgr: tauri::State<'_, RdeskManager>, host_id: String, remote_path: String) -> Result<Value, String> {
    let out = mgr.xfer_list(&host_id, &remote_path)?;
    Ok(json!({"listing": out}))
}

#[tauri::command]
pub fn rdesk_xfer_down(mgr: tauri::State<'_, RdeskManager>, host_id: String, remote_path: String, local_path: String) -> Result<Value, String> {
    mgr.xfer_down(&host_id, &remote_path, &local_path)
}

#[tauri::command]
pub fn rdesk_xfer_up(mgr: tauri::State<'_, RdeskManager>, host_id: String, local_path: String, remote_path: String) -> Result<Value, String> {
    mgr.xfer_up(&host_id, &local_path, &remote_path)
}

/// Скриншот VNC-экрана: минимальный RFB-клиент (handshake → ServerInit →
/// SetEncodings(Raw) → FramebufferUpdateRequest → FramebufferUpdate → PNG).
#[tauri::command]
pub fn rdesk_screenshot(host: String, port: u16, out_path: String) -> Result<Value, String> {
    let img = rfb_grab_frame(&host, port, Duration::from_secs(8))?;
    let mut f = std::fs::File::create(&out_path).map_err(|e| format!("create {out_path}: {e}"))?;
    let mut enc = png::Encoder::new(&mut f, img.width, img.height);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    let mut w = enc.write_header().map_err(|e| format!("png header: {e}"))?;
    w.write_image_data(&img.rgba).map_err(|e| format!("png data: {e}"))?;
    Ok(json!({"path": out_path, "width": img.width, "height": img.height, "bytes": img.rgba.len()}))
}

pub struct RgbImage {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// Один RFB-grab: handshake + один кадр Raw → RGBA.
pub fn rfb_grab_frame(host: &str, port: u16, timeout: Duration) -> Result<RgbImage, String> {
    let mut s = TcpStream::connect(format!("{host}:{port}")).map_err(|e| format!("connect {host}:{port}: {e}"))?;
    s.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    // ProtocolVersion
    let mut buf = [0u8; 12];
    s.read_exact(&mut buf).map_err(|e| format!("read version: {e}"))?;
    s.write_all(b"RFB 003.008\n").map_err(|e| format!("write version: {e}"))?;
    // Security types
    let mut n = [0u8; 1];
    s.read_exact(&mut n).map_err(|e| format!("read sectypes: {e}"))?;
    let mut types = vec![0u8; n[0] as usize];
    s.read_exact(&mut types).map_err(|e| format!("read sectypes list: {e}"))?;
    if !types.contains(&1) {
        return Err("сервер не предлагает security type None (нужен пароль?)".into());
    }
    s.write_all(&[1u8]).map_err(|e| format!("choose None: {e}"))?; // type 1 = None
    let mut sec_result = [0u8; 4];
    s.read_exact(&mut sec_result).map_err(|e| format!("read secresult: {e}"))?;
    if u32::from_be_bytes(sec_result) != 0 {
        return Err("сервер отклонил security handshake".into());
    }
    // ClientInit (shared=1)
    s.write_all(&[1u8]).map_err(|e| format!("clientinit: {e}"))?;
    // ServerInit: width(2) height(2) pixelformat(16) name-len(4) name
    let mut si = [0u8; 24];
    s.read_exact(&mut si).map_err(|e| format!("read serverinit: {e}"))?;
    let width = u16::from_be_bytes([si[0], si[1]]) as u32;
    let height = u16::from_be_bytes([si[2], si[3]]) as u32;
    let bpp = si[4]; // bits-per-pixel
    let depth = si[5];
    let name_len = u32::from_be_bytes([si[20], si[21], si[22], si[23]]) as usize;
    let mut name = vec![0u8; name_len];
    s.read_exact(&mut name).map_err(|e| format!("read name: {e}"))?;
    // SetPixelFormat: 20 байт. Формат пикселя (16 байт после type+pad):
    // bpp(1) depth(1) big-endian-flag(1) true-color(1) red-max(2 BE) green-max(2) blue-max(2) red-shift(1) green-shift(1) blue-shift(1) pad(3)
    // Просим 32bpp little-endian truecolor, shift R=16 G=8 B=0 → байты пикселя [B,G,R,X]
    let mut spf = [0u8; 20];
    spf[0] = 0; // SetPixelFormat
    spf[4] = 32; // bpp
    spf[5] = 24; // depth
    spf[6] = 0; // little-endian
    spf[7] = 1; // true color
    spf[8..10].copy_from_slice(&255u16.to_be_bytes()); // red max
    spf[10..12].copy_from_slice(&255u16.to_be_bytes()); // green max
    spf[12..14].copy_from_slice(&255u16.to_be_bytes()); // blue max
    spf[14] = 16; // red shift
    spf[15] = 8; // green shift
    spf[16] = 0; // blue shift
    let _ = (bpp, depth);
    s.write_all(&spf).map_err(|e| format!("setpixelformat: {e}"))?;
    // SetEncodings: Raw (0)
    let mut se = [0u8; 8];
    se[0] = 2;
    se[2..4].copy_from_slice(&1u16.to_be_bytes()); // 1 encoding
    se[4..8].copy_from_slice(&0i32.to_be_bytes()); // Raw
    s.write_all(&se).map_err(|e| format!("setencodings: {e}"))?;
    // FramebufferUpdateRequest (incremental=0, full screen)
    let mut req = [0u8; 10];
    req[0] = 3;
    req[1] = 0;
    req[2..4].copy_from_slice(&(0u16).to_be_bytes());
    req[4..6].copy_from_slice(&(0u16).to_be_bytes());
    req[6..8].copy_from_slice(&(width as u16).to_be_bytes());
    req[8..10].copy_from_slice(&(height as u16).to_be_bytes());
    s.write_all(&req).map_err(|e| format!("fbu request: {e}"))?;
    // Ответ: type(1)=0, pad(1), nrects(2)
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).map_err(|e| format!("read fbu hdr: {e}"))?;
    if hdr[0] != 0 {
        return Err(format!("неожиданный тип сообщения {}: возможно Bell(2) или ServerCutText(3)", hdr[0]));
    }
    let nrects = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    let mut rgba = vec![0u8; (width * height * 4) as usize];
    for _ in 0..nrects {
        let mut rh = [0u8; 12];
        s.read_exact(&mut rh).map_err(|e| format!("read rect hdr: {e}"))?;
        let x = u16::from_be_bytes([rh[0], rh[1]]) as u32;
        let y = u16::from_be_bytes([rh[2], rh[3]]) as u32;
        let w = u16::from_be_bytes([rh[4], rh[5]]) as u32;
        let h = u16::from_be_bytes([rh[6], rh[7]]) as u32;
        let enc = i32::from_be_bytes([rh[8], rh[9], rh[10], rh[11]]);
        if enc != 0 {
            return Err(format!("не Raw encoding: {enc}"));
        }
        let len = (w * h * 4) as usize;
        let mut px = vec![0u8; len];
        s.read_exact(&mut px).map_err(|e| format!("read rect pixels: {e}"))?;
        // 32bpp little-endian: байты [B,G,R,X] → в RGBA
        for row in 0..h {
            for col in 0..w {
                let si = ((row * w + col) * 4) as usize;
                let di = (((y + row) * width + (x + col)) * 4) as usize;
                rgba[di] = px[si + 2];
                rgba[di + 1] = px[si + 1];
                rgba[di + 2] = px[si];
                rgba[di + 3] = 255;
            }
        }
    }
    Ok(RgbImage { width, height, rgba })
}

// ======================= Тесты =======================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    /// Мок VNC-сервер: handshake + ServerInit 4x3 + один Raw кадр.
    fn mock_vnc_server(addr: &str) -> u16 {
        let listener = TcpListener::bind(addr).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            // версия
            s.write_all(b"RFB 003.008\n").unwrap();
            let mut v = [0u8; 12];
            s.read_exact(&mut v).unwrap();
            // security: 1 type = None
            s.write_all(&[1u8, 1u8]).unwrap();
            let mut t = [0u8; 1];
            s.read_exact(&mut t).unwrap();
            s.write_all(&0u32.to_be_bytes()).unwrap(); // OK
            let mut ci = [0u8; 1];
            s.read_exact(&mut ci).unwrap();
            // ServerInit 4x3, 32bpp, name "mock"
            let mut si = Vec::new();
            si.extend_from_slice(&4u16.to_be_bytes());
            si.extend_from_slice(&3u16.to_be_bytes());
            si.extend_from_slice(&[32, 24, 0, 1]); // bpp, depth, LE, truecolor
            si.extend_from_slice(&[0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]); // maxes(BE u16) + shifts(u8) + pad
            si.extend_from_slice(&4u32.to_be_bytes());
            si.extend_from_slice(b"mock");
            s.write_all(&si).unwrap();
            // SetPixelFormat (20) + SetEncodings (8) + FBURequest (10) — просто читаем
            let mut tmp = [0u8; 38];
            s.read_exact(&mut tmp).unwrap();
            // FramebufferUpdate: 1 rect 4x3 raw
            let mut resp = vec![0u8; 4];
            resp[2..4].copy_from_slice(&1u16.to_be_bytes());
            let mut rect = vec![0u8; 12];
            rect[4..6].copy_from_slice(&4u16.to_be_bytes());
            rect[6..8].copy_from_slice(&3u16.to_be_bytes());
            rect[8..12].copy_from_slice(&0i32.to_be_bytes());
            let px: Vec<u8> = (0..4 * 3).flat_map(|i| [10u8 * i as u8, 20, 30, 0]).collect();
            s.write_all(&resp).unwrap();
            s.write_all(&rect).unwrap();
            s.write_all(&px).unwrap();
        });
        port
    }

    #[test]
    fn test_rfb_grab_frame_mock() {
        let port = mock_vnc_server("127.0.0.1:0");
        let img = rfb_grab_frame("127.0.0.1", port, Duration::from_secs(5)).unwrap();
        assert_eq!((img.width, img.height), (4, 3));
        assert_eq!(img.rgba.len(), 4 * 3 * 4);
        // первый пиксель: BGRA [0,20,30,0] → RGBA [30,20,0,255]
        assert_eq!(&img.rgba[0..4], &[30, 20, 0, 255]);
        // последний пиксель i=11: [110,20,30,0] → [30,20,110,255]
        let last = &img.rgba[(4 * 3 - 1) * 4..];
        assert_eq!(last, &[30, 20, 110, 255]);
    }

    #[test]
    fn test_rfb_grab_no_server() {
        assert!(rfb_grab_frame("127.0.0.1", 1, Duration::from_millis(300)).is_err());
    }

    #[test]
    fn test_session_bookkeeping() {
        let m = RdeskManager::default();
        // connect без sidecar → честная ошибка
        assert!(m.connect("no-such-host", Proto::Vnc, None).is_err());
        // inject сессию вручную и проверяем флаги
        let s = Session {
            id: 1, host: "10.0.0.1".into(), host_name: "h".into(), proto: Proto::Vnc,
            port: 5900, ws_port: Some(16900), state: SessState::Live,
            locked: false, blanked: false, viewers: 1, role: "controller".into(),
        };
        m.sessions.lock().unwrap().insert(1, s);
        let s2 = m.set_flag(1, Some(true), Some(true), Some(2)).unwrap();
        assert!(s2.locked && s2.blanked && s2.viewers == 3);
        assert_eq!(m.list().len(), 1);
        assert!(m.disconnect(1).is_ok());
        assert!(m.list().is_empty());
        assert!(m.disconnect(99).is_err());
    }

    #[test]
    fn test_stage28_roles_chat() {
        let m = RdeskManager::default();
        let s = Session {
            id: 7, host: "10.0.0.2".into(), host_name: "h2".into(), proto: Proto::Vnc,
            port: 5900, ws_port: None, state: SessState::Live,
            locked: false, blanked: false, viewers: 2, role: "controller".into(),
        };
        m.sessions.lock().unwrap().insert(7, s);
        // роль: валидная и невалидная
        assert_eq!(m.set_role(7, "viewer").unwrap().role, "viewer");
        assert!(m.set_role(7, "admin").is_err());
        assert!(m.set_role(42, "viewer").is_err());
        // чат: send/recv с offset, лимиты, чужая сессия
        let m1 = m.chat_send(7, "thomas", "привет").unwrap();
        m.chat_send(7, "admin2", "привет!").unwrap();
        assert!(m.chat_send(7, "x", "").is_err());
        assert!(m.chat_send(7, "x", &"a".repeat(5000)).is_err());
        assert!(m.chat_send(99, "x", "hi").is_err());
        let all = m.chat_recv(7, 0).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].text, "привет");
        assert!(all[0].ts >= m1.ts);
        let tail = m.chat_recv(7, 1).unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].author, "admin2");
        assert!(m.chat_recv(7, 99).unwrap().is_empty());
    }

    #[test]
    fn test_stage28_xfer_validation() {
        let m = RdeskManager::default();
        // без хоста в инвентаре — честная ошибка до любого ssh
        assert!(m.xfer_list("no-such", "/tmp").is_err());
        assert!(m.xfer_down("no-such", "/a", "/b").is_err());
        assert!(m.xfer_up("no-such", "/a", "/b").is_err());
    }
}

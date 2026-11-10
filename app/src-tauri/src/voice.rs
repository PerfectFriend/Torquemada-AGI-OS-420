//! Голосовое управление W420: запуск/статус голосового бэкенда (TTS/STT),
//! синтез ответов голосом оператора и диспетчер голосовых команд.
//!
//! Бэкенд — локальный сервер w420_tts (espeak-ng + faster-whisper) на 127.0.0.1,
//! порт и токен берутся из ~/.w420/tts.json и ~/.w420/tts.env.
//! Команды распознаются по русским ключевым словам и исполняются напрямую
//! (аварийный режим, IDS, блокировки, скан сети, хосты) — без лишних задержек,
//! чтобы реакция на тревогу была мгновенной. Ответ возвращается текстом,
//! а voice_say озвучивает его голосом оператора (клон-профилем).

use serde::Serialize;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use tauri::State;

use crate::emergency::{emergency_set_inner, EmergencyManager};
use crate::hosts::HostsManager;
use crate::net_scan::NetScanManager;
use crate::traffic::TrafficManager;

// ---------------------------------------------------------------------------
// Мини-HTTP клиент (только localhost, без внешних зависимостей)
// ---------------------------------------------------------------------------

fn http_req(port: u16, method: &str, path: &str, token: &str, body: Option<(&str, Vec<u8>)>) -> Result<(u16, Vec<u8>), String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(300)))
        .map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    let (ctype, data) = body.unwrap_or(("", Vec::new()));
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-W420-Token: {token}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        data.len()
    );
    s.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
    s.write_all(&data).map_err(|e| e.to_string())?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).map_err(|e| e.to_string())?;
    let sep = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("нет заголовка ответа")?;
    let head_str = String::from_utf8_lossy(&resp[..sep]).to_string();
    let code: u16 = head_str
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    // тело с учётом chunked не нужен — сервер шлёт Content-Length, Connection: close
    Ok((code, resp[sep + 4..].to_vec()))
}

fn tts_conf() -> (u16, String) {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let port = fs::read_to_string(format!("{home}/.w420/tts.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v["port"].as_u64())
        .unwrap_or(8420) as u16;
    let token = fs::read_to_string(format!("{home}/.w420/tts.env"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("W420_TTS_TOKEN="))
                .map(|l| l.trim_start_matches("W420_TTS_TOKEN=").trim().to_string())
        })
        .unwrap_or_default();
    (port, token)
}

/// base64 decode (стандартный алфавит, с padding и без).
pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let tbl: Vec<i8> = {
        let mut t = vec![-1i8; 256];
        for (i, c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .iter()
            .enumerate()
        {
            t[*c as usize] = i as i8;
        }
        t
    };
    let clean: Vec<u8> = s.bytes().filter(|b| *b != b'=' && !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0;
    for &c in &clean {
        let v = tbl[c as usize];
        if v < 0 {
            return Err(format!("bad base64 char: {}", c as char));
        }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

pub fn b64_encode(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[n as usize & 63] as char } else { '=' });
    }
    out
}

// ---------------------------------------------------------------------------
// Команды
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct VoiceStatus {
    pub tts_running: bool,
    pub port: u16,
    pub engine: String,
    pub voices: usize,
    pub voice_profiles: Vec<serde_json::Value>,
}

/// Статус голосового бэкенда: жив ли сервер, сколько профилей голоса.
#[tauri::command]
pub fn voice_status() -> VoiceStatus {
    let (port, token) = tts_conf();
    let (code, body) = http_req(port, "GET", "/health", &token, None).unwrap_or((0, Vec::new()));
    let running = code == 200;
    let engine = if running {
        String::from_utf8_lossy(&body).to_string()
    } else {
        String::new()
    };
    let profiles = if running {
        http_req(port, "GET", "/voices", &token, None)
            .ok()
            .filter(|(c, _)| *c == 200)
            .and_then(|(_, b)| serde_json::from_slice::<Vec<serde_json::Value>>(&b).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let voices = profiles.len();
    VoiceStatus {
        tts_running: running,
        port,
        engine,
        voices,
        voice_profiles: profiles,
    }
}

#[derive(Serialize)]
pub struct VoiceSayResult {
    pub ok: bool,
    pub bytes: usize,
    /// base64 WAV для мгновенного воспроизведения во фронтенде
    pub b64: String,
    pub path: String,
    pub error: String,
}

/// Озвучить текст голосом (voice_id — профиль клона оператора, если есть).
#[tauri::command]
pub fn voice_say(text: String, voice_id: Option<String>, lang: Option<String>) -> VoiceSayResult {
    let (port, token) = tts_conf();
    let body = serde_json::json!({
        "text": text,
        "lang": lang.unwrap_or_else(|| "ru".into()),
        "voice_id": voice_id,
        "speed": 1.0,
    });
    match http_req(
        port,
        "POST",
        "/speak",
        &token,
        Some(("application/json", body.to_string().into_bytes())),
    ) {
        Ok((200, wav)) if !wav.is_empty() => {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            let dir = PathBuf::from(home).join(".w420/voice_out");
            let _ = fs::create_dir_all(&dir);
            let path = dir.join(format!("say_{}.wav", chrono::Utc::now().timestamp_millis()));
            let _ = fs::write(&path, &wav);
            VoiceSayResult {
                ok: true,
                bytes: wav.len(),
                b64: b64_encode(&wav),
                path: path.to_string_lossy().to_string(),
                error: String::new(),
            }
        }
        Ok((code, body)) => VoiceSayResult {
            ok: false,
            bytes: 0,
            b64: String::new(),
            path: String::new(),
            error: format!("HTTP {code}: {}", String::from_utf8_lossy(&body)),
        },
        Err(e) => VoiceSayResult {
            ok: false,
            bytes: 0,
            b64: String::new(),
            path: String::new(),
            error: e,
        },
    }
}

#[derive(Serialize)]
pub struct VoiceHearResult {
    pub ok: bool,
    pub text: String,
    pub error: String,
}

/// Распознать речь из base64-аудио (запись микрофона) через STT бэкенда.
/// Аудио конвертируется в WAV 16 кГц через ffmpeg перед отправкой.
#[tauri::command]
pub fn voice_hear_b64(b64: String) -> VoiceHearResult {
    let raw = match b64_decode(&b64) {
        Ok(r) => r,
        Err(e) => {
            return VoiceHearResult {
                ok: false,
                text: String::new(),
                error: format!("base64: {e}"),
            }
        }
    };
    let (port, token) = tts_conf();
    let tmp_in = std::env::temp_dir().join("w420_hear_in.webm");
    let tmp_wav = std::env::temp_dir().join("w420_hear.wav");
    if fs::write(&tmp_in, &raw).is_err() {
        return VoiceHearResult {
            ok: false,
            text: String::new(),
            error: "не удалось записать временный файл".into(),
        };
    }
    // конвертация в wav 16кГц моно (ffmpeg есть в системе)
    let conv = std::process::Command::new("ffmpeg")
        .args(["-y", "-i"])
        .arg(&tmp_in)
        .args(["-ar", "16000", "-ac", "1"])
        .arg(&tmp_wav)
        .output();
    let wav = match conv {
        Ok(o) if o.status.success() => fs::read(&tmp_wav).ok(),
        _ => Some(raw.clone()), // если ffmpeg недоступен — шлём как есть
    };
    let Some(wav) = wav else {
        return VoiceHearResult {
            ok: false,
            text: String::new(),
            error: "ffmpeg не смог конвертировать аудио".into(),
        };
    };
    // multipart/form-data вручную
    let boundary = "w420voiceboundary";
    let mut mp = Vec::new();
    mp.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"hear.wav\"\r\nContent-Type: audio/wav\r\n\r\n"
        )
        .as_bytes(),
    );
    mp.extend_from_slice(&wav);
    mp.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let ctype = format!("multipart/form-data; boundary={boundary}");
    match http_req(port, "POST", "/stt", &token, Some((&ctype, mp))) {
        Ok((200, body)) => {
            let text = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v["text"].as_str().map(|s| s.to_string()))
                .unwrap_or_default();
            VoiceHearResult {
                ok: true,
                text,
                error: String::new(),
            }
        }
        Ok((code, body)) => VoiceHearResult {
            ok: false,
            text: String::new(),
            error: format!("HTTP {code}: {}", String::from_utf8_lossy(&body)),
        },
        Err(e) => VoiceHearResult {
            ok: false,
            text: String::new(),
            error: e,
        },
    }
}

#[derive(Serialize)]
pub struct VoiceReply {
    pub action: String,
    pub reply: String,
    pub ok: bool,
}

/// Найти IPv4-адрес в тексте голосовой команды.
fn find_ip(text: &str) -> Option<String> {
    let mut cur = String::new();
    let mut found = None;
    for ch in text.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            cur.push(ch);
        } else if !cur.is_empty() {
            if cur.split('.').count() == 4 && cur.split('.').all(|p| p.parse::<u8>().is_ok()) {
                found = Some(cur.clone());
            }
            cur.clear();
        }
    }
    if !cur.is_empty() && cur.split('.').count() == 4 && cur.split('.').all(|p| p.parse::<u8>().is_ok()) {
        found = Some(cur);
    }
    found
}

/// Подсеть по умолчанию из /proc/net/route (для голосовой команды «сканируй сеть»).
fn default_subnet() -> String {
    if let Ok(s) = fs::read_to_string("/proc/net/route") {
        for line in s.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() >= 3 && f[2] == "00000000" {
                // default route: маска из f[7], адрес шлюза f[2]... берём адрес интерфейса f[1]? нам нужна подсеть:
                // gateway = f[2], mask = f[7]; подсеть = iface addr & mask — упростим: /24 от gateway
                let gw = f[2];
                if let Ok(g) = u32::from_str_radix(gw, 16) {
                    let ip = [
                        (g & 0xff) as u8,
                        ((g >> 8) & 0xff) as u8,
                        ((g >> 16) & 0xff) as u8,
                        0,
                    ];
                    return format!("{}.{}.{}.0/24", ip[0], ip[1], ip[2]);
                }
            }
        }
    }
    "192.168.1.0/24".to_string()
}

/// Диспетчер голосовых команд: распознаёт намерение и исполняет действие напрямую.
#[tauri::command]
pub async fn voice_command(
    text: String,
    tm: State<'_, TrafficManager>,
    em: State<'_, EmergencyManager>,
    nm: State<'_, NetScanManager>,
    hm: State<'_, HostsManager>,
) -> Result<VoiceReply, String> {
    Ok(voice_command_inner(text, tm, em, nm, hm).await)
}

async fn voice_command_inner(
    text: String,
    tm: State<'_, TrafficManager>,
    em: State<'_, EmergencyManager>,
    nm: State<'_, NetScanManager>,
    hm: State<'_, HostsManager>,
) -> VoiceReply {
    let t = text.to_lowercase();
    let say = |action: &str, reply: String, ok: bool| VoiceReply {
        action: action.to_string(),
        reply,
        ok,
    };

    // --- Аварийный режим ---
    if t.contains("тревог") || t.contains("аварийн") || (t.contains("жестк") || t.contains("жёстк")) && t.contains("режим")
        || t.contains("включи защиту") || t.contains("максимальн") && t.contains("защит")
    {
        let r = emergency_set_inner(&em, true, Some("emergency".into()), None, None);
        let msg = if r.applied {
            "Аварийный режим включён. Жёсткая фильтрация пакетов применена на всех каналах.".to_string()
        } else if r.needs_root {
            format!("Аварийный режим сохранён, но для применения в ядро нужны права root: {}", r.detail)
        } else {
            format!("Аварийный режим сохранён, применить не удалось: {}", r.detail)
        };
        return say("emergency_on", msg, r.saved);
    }
    if t.contains("отбой") || t.contains("нормальн") && t.contains("режим") || t.contains("мониторинг") && t.contains("включи") && t.contains("обычн")
        || (t.contains("выключи") && t.contains("тревог"))
    {
        let r = emergency_set_inner(&em, false, Some("monitor".into()), None, None);
        return say(
            "emergency_off",
            "Аварийный режим выключен. Система в режиме мониторинга.".to_string(),
            r.saved,
        );
    }
    // --- IDS ---
    if (t.contains("включи") || t.contains("запусти") || t.contains("старт")) && (t.contains("мониторинг") || t.contains("защит") || t.contains("ids")) {
        let iface = "any".to_string();
        match tm.start_ids(iface, String::new(), false).await {
            Ok(st) => {
                return say(
                    "ids_on",
                    format!("Мониторинг включён: перехват на {}, алертов: {}.", st.interface, st.alerts_generated),
                    true,
                )
            }
            Err(e) => return say("ids_on", format!("Не удалось включить мониторинг: {e}"), false),
        }
    }
    if (t.contains("выключи") || t.contains("стоп") || t.contains("останови")) && (t.contains("мониторинг") || t.contains("защит") || t.contains("ids")) {
        match tm.stop().await {
            Ok(s) => {
                return say(
                    "ids_off",
                    format!("Мониторинг остановлен. Захвачено пакетов: {}, алертов: {}.", s.packets_seen, s.alerts_generated),
                    true,
                )
            }
            Err(e) => return say("ids_off", format!("Ошибка остановки: {e}"), false),
        }
    }
    // --- Блокировка IP ---
    if t.contains("блокир") || t.contains("заблокир") {
        if let Some(ip) = find_ip(&t) {
            return match tm.do_block(&ip, "голосовая команда") {
                Ok(m) => say("block", format!("IP {ip} заблокирован: {m}"), true),
                Err(e) => say("block", format!("Не удалось заблокировать {ip}: {e}"), false),
            };
        }
        return say("block", "Скажите: заблокируй, и адрес, например 10.0.0.5".into(), false);
    }
    if t.contains("разблокир") {
        if let Some(ip) = find_ip(&t) {
            return match tm.do_unblock(&ip) {
                Ok(m) => say("unblock", format!("IP {ip} разблокирован: {m}"), true),
                Err(e) => say("unblock", format!("Ошибка: {e}"), false),
            };
        }
    }
    // --- Скан сети ---
    if t.contains("сканир") || t.contains("найди хост") || t.contains("поиск хост") || t.contains("кто в сети") {
        let cidr = default_subnet();
        return match nm.run_scan(&cidr, None, None, None).await {
            Ok(res) => say(
                "scan",
                format!("Сканирую {cidr}: найдено хостов: {}.", res.hosts.len()),
                true,
            ),
            Err(e) => say("scan", format!("Ошибка сканирования: {e}"), false),
        };
    }
    // --- Статус ---
    if t.contains("статус") || t.contains("отчёт") || t.contains("что происходит") || t.contains("как дела") {
        let ids = tm.status();
        let alerts = tm.list_alerts(10).map(|a| a.len()).unwrap_or(0);
        let em_st = em.state.lock().unwrap().clone();
        let hosts = hm.list_hosts().map(|h| h.len()).unwrap_or(0);
        let level = if em_st.enabled { em_st.level.as_str() } else { "monitor" };
        return say(
            "status",
            format!(
                "Статус: режим «{level}», мониторинг {}, последних алертов: {alerts}, хостов в инвентаре: {hosts}.",
                if ids.running { "включён" } else { "выключен" }
            ),
            true,
        );
    }
    if t.contains("алерт") || t.contains("тревожн") && t.contains("событи") {
        return match tm.list_alerts(5) {
            Ok(a) => say(
                "alerts",
                if a.is_empty() {
                    "Тревожных событий нет.".to_string()
                } else {
                    a.iter()
                        .map(|x| format!("{}: {}", x.severity, x.signature))
                        .collect::<Vec<_>>()
                        .join("; ")
                },
                true,
            ),
            Err(e) => say("alerts", format!("Ошибка: {e}"), false),
        };
    }
    // --- Хосты ---
    if t.contains("хост") && (t.contains("список") || t.contains("покажи") || t.contains("сколько")) {
        return match hm.list_hosts() {
            Ok(h) => say(
                "hosts",
                if h.is_empty() {
                    "Инвентарь пуст. Скажите «сканируй сеть».".to_string()
                } else {
                    h.iter()
                        .map(|x| format!("{} ({}, {})", x.ip, x.os_type, x.status))
                        .collect::<Vec<_>>()
                        .join("; ")
                },
                true,
            ),
            Err(e) => say("hosts", format!("Ошибка: {e}"), false),
        };
    }

    say(
        "unknown",
        format!("Команда не распознана: «{text}». Доступно: тревога, отбой, статус, сканируй сеть, заблокируй IP, мониторинг включи/выключи."),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_b64_roundtrip() {
        let data: Vec<u8> = (0u8..=250).collect();
        let enc = b64_encode(&data);
        let dec = b64_decode(&enc).unwrap();
        assert_eq!(data, dec);
        // без padding
        assert_eq!(b64_decode("aGVsbG8").unwrap(), b"hello");
    }

    #[test]
    fn test_find_ip() {
        assert_eq!(find_ip("заблокируй 10.0.0.5 пожалуйста"), Some("10.0.0.5".into()));
        assert_eq!(find_ip("никакого адреса"), None);
        assert_eq!(find_ip("ip 999.1.1.1"), None); // 999 не байт
        assert_eq!(find_ip("адрес 192.168.1.20!"), Some("192.168.1.20".into()));
    }
}

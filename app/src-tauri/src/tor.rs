//! Embedded Tor (Arti, linked into the app): a local SOCKS5 proxy that sends connections through the Tor network,
//! including .onion addresses. Domain names are passed to Tor as names (no local DNS), so there is no DNS leak here.
use serde::Serialize;
use std::sync::{Arc, Mutex};

#[derive(Clone, Serialize, Default)]
pub struct TorStatus {
    pub state: String, // idle | bootstrapping | ready | error | stopped
    pub progress: f32,
    pub message: String,
    pub port: u16,
}

#[derive(Default)]
pub struct Tor {
    #[cfg(feature = "embedded-tor")]
    task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    pub status: Arc<Mutex<TorStatus>>,
}

#[cfg(feature = "embedded-tor")]
fn set(st: &Arc<Mutex<TorStatus>>, f: impl FnOnce(&mut TorStatus)) { if let Ok(mut g) = st.lock() { f(&mut g); } }

#[tauri::command]
pub fn tor_status(state: tauri::State<Tor>) -> TorStatus {
    state.status.lock().map(|g| g.clone()).unwrap_or_default()
}

#[cfg(not(feature = "embedded-tor"))]
#[tauri::command]
pub fn tor_start(_state: tauri::State<Tor>, _socks_port: u16, _bridges: Vec<String>) -> Result<(), String> {
    Err("Tor-движок не включён в эту сборку (cargo feature embedded-tor)".into())
}

#[cfg(not(feature = "embedded-tor"))]
#[tauri::command]
pub fn tor_stop(_state: tauri::State<Tor>) {}

#[cfg(feature = "embedded-tor")]
#[tauri::command]
pub fn tor_start(app: tauri::AppHandle, state: tauri::State<Tor>, socks_port: u16, bridges: Vec<String>) -> Result<(), String> {
    real::start(app, &state, socks_port, bridges)
}

#[cfg(feature = "embedded-tor")]
#[tauri::command]
pub fn tor_stop(state: tauri::State<Tor>) { real::stop(&state) }

#[cfg(feature = "embedded-tor")]
mod real {
    use super::*;
    use arti_client::{config::TorClientConfigBuilder, TorClient};
    use futures::StreamExt;
    use tauri::Manager;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const REP_OK: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    fn reply(code: u8) -> [u8; 10] { [5, code, 0, 1, 0, 0, 0, 0, 0, 0] }

    /// Minimal SOCKS5 (no auth, CONNECT only) in front of an Arti client.
    async fn session(mut s: TcpStream, client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>) -> std::io::Result<()> {
        let mut h = [0u8; 2];
        s.read_exact(&mut h).await?;
        if h[0] != 5 { return Ok(()); }
        let mut methods = vec![0u8; h[1] as usize];
        s.read_exact(&mut methods).await?;
        if !methods.contains(&0) { s.write_all(&[5, 0xff]).await?; return Ok(()); }
        s.write_all(&[5, 0]).await?;
        let mut r = [0u8; 4];
        s.read_exact(&mut r).await?;
        if r[0] != 5 || r[1] != 1 { s.write_all(&reply(7)).await?; return Ok(()); } // only CONNECT
        let host = match r[3] {
            1 => { let mut b = [0u8; 4]; s.read_exact(&mut b).await?; std::net::Ipv4Addr::from(b).to_string() }
            4 => { let mut b = [0u8; 16]; s.read_exact(&mut b).await?; std::net::Ipv6Addr::from(b).to_string() }
            3 => { let mut l = [0u8; 1]; s.read_exact(&mut l).await?; let mut b = vec![0u8; l[0] as usize]; s.read_exact(&mut b).await?; String::from_utf8_lossy(&b).into_owned() }
            _ => { s.write_all(&reply(8)).await?; return Ok(()); }
        };
        let mut p = [0u8; 2];
        s.read_exact(&mut p).await?;
        let port = u16::from_be_bytes(p);
        match client.connect((host.as_str(), port)).await {
            Ok(mut t) => { s.write_all(&REP_OK).await?; let _ = tokio::io::copy_bidirectional(&mut s, &mut t).await; }
            Err(_) => { s.write_all(&reply(4)).await?; } // host unreachable
        }
        Ok(())
    }

    pub fn start(app: tauri::AppHandle, state: &Tor, socks_port: u16, bridges: Vec<String>) -> Result<(), String> {
        if !bridges.is_empty() {
            return Err("Мосты Tor (obfs4/webtunnel/snowflake) пока не подключены: нужен отдельный транспорт. Используйте Tor внутри системного VPN.".into());
        }
        let mut task = state.task.lock().map_err(|_| "внутренняя ошибка")?;
        if task.as_ref().map(|t| !t.inner().is_finished()).unwrap_or(false) { return Ok(()); }
        let root = app.path().home_dir().map_err(|e| e.to_string())?.join(".w420").join("tor");
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let st = state.status.clone();
        set(&st, |s| *s = TorStatus { state: "bootstrapping".into(), progress: 0.0, message: "подключаюсь к сети Tor".into(), port: socks_port });
        *task = Some(tauri::async_runtime::spawn(async move {
            let mut b = TorClientConfigBuilder::from_directories(root.join("state"), root.join("cache"));
            b.address_filter().allow_onion_addrs(true);
            let cfg = match b.build() { Ok(c) => c, Err(e) => { set(&st, |s| { s.state = "error".into(); s.message = e.to_string(); }); return; } };
            let client = match TorClient::builder().config(cfg).create_unbootstrapped() {
                Ok(c) => c, // already an Arc<TorClient>
                Err(e) => { set(&st, |s| { s.state = "error".into(); s.message = e.to_string(); }); return; }
            };
            let mut events = client.bootstrap_events();
            let st2 = st.clone();
            let watcher = tauri::async_runtime::spawn(async move {
                while let Some(ev) = events.next().await { set(&st2, |s| { s.progress = ev.as_frac(); s.message = ev.to_string(); }); }
            });
            let res = client.bootstrap().await;
            watcher.abort();
            if let Err(e) = res { set(&st, |s| { s.state = "error".into(); s.message = e.to_string(); }); return; }
            let listener = match TcpListener::bind(("127.0.0.1", socks_port)).await {
                Ok(l) => l,
                Err(e) => { set(&st, |s| { s.state = "error".into(); s.message = format!("порт {socks_port}: {e}"); }); return; }
            };
            set(&st, |s| { s.state = "ready".into(); s.progress = 1.0; s.message = format!("Tor готов, SOCKS5 на 127.0.0.1:{socks_port}"); });
            loop {
                match listener.accept().await {
                    Ok((sock, _)) => { let c = client.clone(); tauri::async_runtime::spawn(async move { let _ = session(sock, c).await; }); }
                    Err(_) => break,
                }
            }
        }));
        Ok(())
    }

    pub fn stop(state: &Tor) {
        if let Ok(mut t) = state.task.lock() { if let Some(h) = t.take() { h.abort(); } }
        set(&state.status, |s| { s.state = "stopped".into(); s.message = String::new(); });
    }
}

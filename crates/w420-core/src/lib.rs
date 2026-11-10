//! Shared types for the w420 project.
//!
//! This crate holds the data model that is shared between the Tauri backend,
//! the installer utility, and the TTS service. Keeping it in one place avoids
//! duplicating structs across crates and makes the Rust-only migration
//! straightforward.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub mod config_gen;

pub use config_gen::{build_config, parse_link, parse_ovpn, parse_profiles, parse_wireguard_conf, BuildOpts, ParsedProfiles, VpnCreds};

/// Top-level error type used across w420 crates.
#[derive(Error, Debug)]
pub enum W420Error {
    #[error("sing-box binary not found: {0}")]
    SingBoxNotFound(String),
    #[error("invalid proxy link: {0}")]
    InvalidProxyLink(String),
    #[error("unsupported proxy protocol: {0}")]
    UnsupportedProtocol(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("tts error: {0}")]
    Tts(String),
    #[error("network error: {0}")]
    Network(String),
}

/// Kind of a proxy / VPN profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyKind {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria2,
    Tuic,
    AnyTls,
    Socks5,
    WireGuard,
    OpenVpn,
    Direct,
    Tor,
}

/// Mode in which sing-box runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SingBoxMode {
    Proxy,
    Tun,
}

/// Parsed representation of a proxy subscription link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyProfile {
    pub id: Uuid,
    pub kind: ProxyKind,
    pub tag: String,
    pub server: String,
    pub port: u16,
    pub config: serde_json::Value,
}

/// Complete sing-box configuration built from a list of profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingBoxConfig {
    pub version: String,
    pub log: serde_json::Value,
    pub dns: serde_json::Value,
    pub inbounds: Vec<serde_json::Value>,
    pub outbounds: Vec<serde_json::Value>,
    pub route: serde_json::Value,
}

/// Request sent to the TTS service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtsRequest {
    pub voice_id: String,
    pub text: String,
    pub lang: String,
    pub speed: f32,
}

/// Response returned by the TTS service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtsResponse {
    pub audio_wav: Vec<u8>,
    pub sample_rate: u32,
    pub channels: u16,
}

/// Voice metadata stored in ~/.w420/voices.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceMeta {
    pub id: String,
    pub name: String,
    pub seconds: f32,
    pub created: String,
    pub consent_at: String,
}

/// Real system metrics reported to the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub cores: usize,
    pub cpu_percent: f32,
    pub mem_used_gb: f32,
    pub mem_total_gb: f32,
    pub online: bool,
}

impl Default for ProxyKind {
    fn default() -> Self {
        ProxyKind::Direct
    }
}

impl Default for SingBoxMode {
    fn default() -> Self {
        SingBoxMode::Proxy
    }
}

impl ProxyProfile {
    pub fn new(kind: ProxyKind, tag: String, server: String, port: u16) -> Self {
        Self {
            id: Uuid::new_v4(),
            kind,
            tag,
            server,
            port,
            config: serde_json::Value::Null,
        }
    }
}

impl SingBoxConfig {
    pub fn empty() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            log: serde_json::json!({ "level": "info", "timestamp": true }),
            dns: serde_json::json!({ "servers": [], "rules": [], "final": "direct" }),
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            route: serde_json::json!({ "rules": [], "final": "direct" }),
        }
    }
}

//! W420 TTS-сервис на Rust (axum). Заменяет Python FastAPI + Coqui/XTTS.
//! Бэкенд озвучки: espeak-ng (уже в системе, geen скачиваний моделей).
//! API совместимо с бывшим Python-сервером: /health, /voices, /speak.
//! Порт 8420, только 127.0.0.1, токен X-W420-Token из переменной W420_TTS_TOKEN.

use axum::{
    body::Body,
    extract::State,
    http::{header, StatusCode, HeaderMap},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

const PORT: u16 = 8420;
const MAX_TEXT: usize = 600;
const TOKEN_ENV: &str = "W420_TTS_TOKEN";
#[derive(Clone)]
struct AppState {
    token: Option<String>,
    espeak: bool,
    voices_cache: Arc<RwLock<Option<Vec<Voice>>>>,
}

#[derive(Serialize, Clone)]
struct Voice {
    id: String,
    name: String,
    lang: String,
}

#[derive(Deserialize)]
struct SpeakReq {
    text: String,
    voice_id: Option<String>,
    lang: Option<String>,
    #[serde(default = "default_speed")]
    speed: f32,
}

fn default_speed() -> f32 {
    1.0
}

#[tokio::main]
async fn main() {
    let token = std::env::var(TOKEN_ENV).ok().filter(|t| !t.is_empty());
    if token.is_none() {
        eprintln!("W420_TTS_TOKEN не задан: сервер без токена не запускается");
        std::process::exit(1);
    }

    let espeak = Command::new("espeak-ng")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !espeak {
        eprintln!("ВНИМАНИЕ: espeak-ng не найден в PATH; TTS будет недоступен");
    }

    eprintln!("W420 TTS слушает 127.0.0.1:{} (espeak-ng: {})", PORT, espeak);

    let state = AppState {
        token,
        espeak,
        voices_cache: Arc::new(RwLock::new(None)),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/voices", get(list_voices))
        .route("/speak", post(speak))
        .route("/stt", post(stt))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], PORT));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn auth_ok(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get("x-w420-token")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == token)
        .unwrap_or(false)
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let voices = state.voices_cache.read().await;
    let n = voices.as_ref().map(|v| v.len()).unwrap_or(0);
    Json(json!({
        "status": if state.espeak { "ready" } else { "error" },
        "engine": "espeak-ng",
        "device": "cpu",
        "msg": if state.espeak { "" } else { "espeak-ng не найден в PATH" },
        "voices": n,
    }))
}

async fn list_voices(State(state): State<AppState>) -> Result<Json<serde_json::Value>, StatusCode> {
    {
        let cached = state.voices_cache.read().await;
        if let Some(v) = cached.as_ref() {
            return Ok(Json(serde_json::to_value(v).unwrap()));
        }
    }

    if !state.espeak {
        return Ok(Json(serde_json::to_value(&Vec::<Voice>::new()).unwrap()));
    }

    let out = Command::new("espeak-ng")
        .arg("--voices")
        .output()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut voices: Vec<Voice> = Vec::new();
    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            let lang = parts[1].to_string();
            let name = parts[4..].join(" ");
            let id = format!("espeak-{}-{}", lang, name.replace(' ', "_"));
            voices.push(Voice { id, name, lang });
        }
    }

    *state.voices_cache.write().await = Some(voices.clone());
    Ok(Json(serde_json::to_value(&voices).unwrap()))
}

async fn speak(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SpeakReq>,
) -> Result<Response, StatusCode> {
    let token = state.token.as_deref().unwrap_or("");
    if token.is_empty() || !auth_ok(&headers, token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let text = req.text.trim();
    if text.is_empty() || text.len() > MAX_TEXT {
        return Err(StatusCode::BAD_REQUEST);
    }

    let lang = req.lang.as_deref().unwrap_or("ru");
    let speed = req.speed.clamp(0.5, 2.0);

    if !state.espeak {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let wpm = (175.0 * speed) as i32;
    let out_path = PathBuf::from(format!("/tmp/w420-tts-{}.wav", Uuid::new_v4()));

    let status = Command::new("espeak-ng")
        .arg("-v")
        .arg(lang)
        .arg("-s")
        .arg(wpm.to_string())
        .arg("-w")
        .arg(&out_path)
        .arg(text)
        .output()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !status.status.success() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let data = std::fs::read(&out_path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = std::fs::remove_file(&out_path);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "audio/wav")
        .header(header::CONTENT_LENGTH, data.len())
        .body(Body::from(data))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?)
}

// ==================== STT (требует модель vosk/whisper) ====================

#[derive(Deserialize)]
struct SttReq {
    #[serde(default)]
    lang: String,
}

async fn stt(
    State(_state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let token = std::env::var(TOKEN_ENV).ok().filter(|t| !t.is_empty());
    let token = token.as_deref().unwrap_or("");
    if token.is_empty() || !auth_ok(&headers, token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // STT без модели (vosk/whisper) невозможен. Возвращаем понятную ошибку,
    // чтобы фронтенд мог показать пользователю инструкцию — без танцев с бубном.
    Err(StatusCode::NOT_IMPLEMENTED)
}

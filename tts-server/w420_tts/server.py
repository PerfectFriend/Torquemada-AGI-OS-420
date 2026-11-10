"""W420 local TTS server: XTTS-v2 speech + voice cloning.

* binds to 127.0.0.1 only; every call except /health needs the X-W420-Token header
* voice samples and the voice list live in ~/.w420 (override: W420_HOME); nothing leaves the machine
* a voice can only be created with an explicit consent flag, the consent time is stored with it
"""
import argparse
import hashlib
import io
import json
import os
import re
import secrets
import threading
import time
import uuid
import wave
from urllib.parse import unquote
from collections import OrderedDict
from contextlib import asynccontextmanager
from pathlib import Path

import numpy as np
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

SR = 24000
LANGS = {"ru", "en", "de", "fr", "es", "it", "pt", "pl", "tr", "nl", "cs", "ar", "zh-cn", "ja", "hu", "ko", "hi"}
CHAR_LIMIT = {"ru": 170}          # XTTS warns above 182 for Russian; other languages ~250
DEFAULT_LIMIT = 230
MAX_TEXT = 600
MIN_REF, MAX_REF = 3.0, 65.0      # seconds accepted for a voice sample
KEEP_REF = 30.0                   # seconds of the sample that are kept / used
ID_RE = re.compile(r"^[0-9a-f]{12}$")

HOME = Path(os.environ.get("W420_HOME", str(Path.home() / ".w420")))
VOICES = HOME / "voices"
META = HOME / "voices.json"
state = {"status": "starting", "msg": "", "device": "", "engine": ""}
engine = None
gen_lock, meta_lock = threading.Lock(), threading.Lock()
cache: "OrderedDict[str, bytes]" = OrderedDict()
latents: dict = {}


# ---------- audio helpers ----------
def wav_bytes(x: np.ndarray, sr: int = SR) -> bytes:
    pcm = (np.clip(x, -1, 1) * 32767).astype("<i2")
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes(pcm.tobytes())
    return buf.getvalue()


def read_wav(data: bytes):
    with wave.open(io.BytesIO(data)) as w:
        ch, sw, sr, n = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
        if sw != 2:
            raise ValueError("нужен 16-битный WAV")
        x = np.frombuffer(w.readframes(n), "<i2").astype(np.float32) / 32768
    if ch > 1:
        x = x.reshape(-1, ch).mean(1)
    return x, sr


def resample(x: np.ndarray, sr: int, to: int = SR) -> np.ndarray:
    if sr == to or len(x) == 0:
        return x
    n = int(len(x) * to / sr)
    return np.interp(np.linspace(0, len(x) - 1, n), np.arange(len(x)), x).astype(np.float32)


def split_text(text: str, limit: int):
    """Sentence-first splitting so that no chunk exceeds the model limit."""
    parts, out = re.split(r"(?<=[.!?…])\s+", text.strip()), []
    for p in parts:
        while len(p) > limit:
            cut = max(p.rfind(",", 0, limit), p.rfind(" ", 0, limit))
            cut = cut if cut > 20 else limit
            out.append(p[:cut].strip())
            p = p[cut:].lstrip(" ,")
        if p.strip():
            out.append(p.strip())
    return out


# ---------- engines ----------
class FakeEngine:
    """Test engine: a tone whose length follows the text. Used only with W420_TTS_FAKE=1."""

    sr = SR

    def latents(self, path):
        return str(path)

    def speak(self, text, lang, lat, speed):
        n = int(SR * max(0.2, len(text) * 0.05 / speed))
        t = np.arange(n) / SR
        return (0.2 * np.sin(2 * np.pi * 220 * t)).astype(np.float32)


class XttsEngine:
    sr = SR

    def __init__(self, model):
        self.m = model

    def latents(self, path):
        return self.m.get_conditioning_latents(
            audio_path=[str(path)], gpt_cond_len=30, gpt_cond_chunk_len=6, max_ref_length=30
        )

    def speak(self, text, lang, lat, speed):
        gpt, spk = lat
        out = self.m.inference(text, lang, gpt, spk, speed=speed, enable_text_splitting=False)
        return np.asarray(out["wav"], dtype=np.float32)


def load_engine():
    global engine
    try:
        if os.environ.get("W420_TTS_FAKE") == "1":
            engine = FakeEngine()
            state.update(status="ready", engine="fake", device="cpu", msg="тестовый движок (тон вместо голоса)")
            return
        if os.environ.get("COQUI_TOS_AGREED") != "1":
            state.update(status="error", msg="лицензия XTTS (CPML, некоммерческая) не принята")
            return
        state.update(status="loading", msg="загрузка XTTS-v2 (первый запуск скачивает около 1,8 ГБ)")
        import torch
        from TTS.api import TTS

        dev = "cuda" if torch.cuda.is_available() else "cpu"
        tts = TTS("tts_models/multilingual/multi-dataset/xtts_v2", progress_bar=False).to(dev)
        engine = XttsEngine(tts.synthesizer.tts_model)
        state.update(status="ready", engine="xtts-v2", device=dev, msg="")
    except Exception as e:  # keep the server alive and report the reason to the UI
        state.update(status="error", msg=f"{type(e).__name__}: {e}")


# ---------- voice storage ----------
def load_meta():
    try:
        return json.loads(META.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_meta(items):
    HOME.mkdir(parents=True, exist_ok=True)
    tmp = META.with_suffix(".tmp")
    tmp.write_text(json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, META)


def auth(req: Request):
    token = os.environ.get("W420_TTS_TOKEN", "")
    if not token or not secrets.compare_digest(req.headers.get("x-w420-token", ""), token):
        raise HTTPException(401, "bad token")


@asynccontextmanager
async def lifespan(app):
    threading.Thread(target=load_engine, daemon=True).start()
    yield


app = FastAPI(title="W420 TTS", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(tauri://localhost|https?://tauri\.localhost|https?://localhost(:\d+)?|http://127\.0\.0\.1(:\d+)?)$",
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {**state, "voices": len(load_meta())}


@app.get("/voices", dependencies=[Depends(auth)])
def voices():
    return load_meta()


@app.post("/voices", dependencies=[Depends(auth)])
async def add_voice(req: Request):
    if req.headers.get("x-consent") != "1":
        raise HTTPException(400, "нужно подтверждение: это ваш голос или у вас есть согласие владельца голоса")
    name = re.sub(r"\s+", " ", unquote(req.headers.get("x-voice-name", "")).strip())[:60]  # header is percent-encoded UTF-8
    if not name:
        raise HTTPException(400, "нужно имя голоса")
    data = await req.body()
    if len(data) > 8_000_000:
        raise HTTPException(413, "файл слишком большой")
    try:
        x, sr = read_wav(data)
    except Exception as e:
        raise HTTPException(400, f"не удалось прочитать WAV: {e}")
    x = resample(x, sr)
    dur = len(x) / SR
    if dur < MIN_REF:
        raise HTTPException(400, f"слишком короткая запись ({dur:.1f} с), нужно хотя бы {MIN_REF:.0f} с, лучше 20-30")
    if dur > MAX_REF:
        raise HTTPException(400, f"слишком длинная запись ({dur:.0f} с)")
    if float(np.sqrt(np.mean(x**2))) < 0.003:
        raise HTTPException(400, "запись почти беззвучная")
    x = x[: int(KEEP_REF * SR)]
    vid = uuid.uuid4().hex[:12]
    VOICES.mkdir(parents=True, exist_ok=True)
    (VOICES / f"{vid}.wav").write_bytes(wav_bytes(x))
    item = {
        "id": vid,
        "name": name,
        "seconds": round(len(x) / SR, 1),
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "consent_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    with meta_lock:
        save_meta(load_meta() + [item])
    return item


@app.delete("/voices/{vid}", dependencies=[Depends(auth)])
def del_voice(vid: str):
    if not ID_RE.match(vid):
        raise HTTPException(404, "нет такого голоса")
    with meta_lock:
        items = load_meta()
        if vid not in [i["id"] for i in items]:
            raise HTTPException(404, "нет такого голоса")
        save_meta([i for i in items if i["id"] != vid])
    try:
        (VOICES / f"{vid}.wav").unlink()
    except FileNotFoundError:
        pass
    latents.pop(vid, None)
    for k in [k for k in cache if k.startswith(vid)]:
        cache.pop(k, None)
    return {"deleted": vid}


@app.post("/speak", dependencies=[Depends(auth)])
async def speak(req: Request):
    body = await req.json()
    text = str(body.get("text", "")).strip()
    vid, lang = str(body.get("voice_id", "")), str(body.get("lang", "ru"))
    speed = min(1.4, max(0.7, float(body.get("speed", 1.0))))
    if not text or len(text) > MAX_TEXT:
        raise HTTPException(400, f"текст пуст или длиннее {MAX_TEXT} символов")
    if lang not in LANGS:
        raise HTTPException(400, "неподдерживаемый язык")
    if not ID_RE.match(vid) or vid not in [i["id"] for i in load_meta()]:
        raise HTTPException(404, "нет такого голоса")
    if state["status"] != "ready" or engine is None:
        raise HTTPException(503, state["msg"] or state["status"])
    key = vid + hashlib.sha1(f"{lang}|{speed}|{text}".encode()).hexdigest()
    if key in cache:
        cache.move_to_end(key)
        return Response(cache[key], media_type="audio/wav")
    with gen_lock:
        if vid not in latents:
            latents[vid] = engine.latents(VOICES / f"{vid}.wav")
        gap = np.zeros(int(SR * 0.12), dtype=np.float32)
        parts = []
        for chunk in split_text(text, CHAR_LIMIT.get(lang, DEFAULT_LIMIT)):
            parts += [engine.speak(chunk, lang, latents[vid], speed), gap]
    out = wav_bytes(np.concatenate(parts))
    cache[key] = out
    while len(cache) > 64:
        cache.popitem(last=False)
    return Response(out, media_type="audio/wav")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8420)
    a = ap.parse_args()
    if not os.environ.get("W420_TTS_TOKEN"):
        raise SystemExit("W420_TTS_TOKEN не задан: сервер без токена не запускается")
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")

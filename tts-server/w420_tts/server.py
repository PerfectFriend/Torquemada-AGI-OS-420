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


class QwenEngine:
    """Qwen3-TTS 12Hz через llama-tts (llama.cpp) — работает на GPU (Vulkan/HIP),
    поэтому RAM-гейт XTTS на него не распространяется. Модели лежат в
    ~/.w420/tts-models, бинарь — в W420_QWEN_TTS_BIN (или рядом с ними).
    Клонирование голоса: --tts-speaker-file <референс.wav> (т.е. latents(path) — путь к файлу).
    """

    sr = SR

    def __init__(self, bin_path, talker, mmproj):
        self.bin = bin_path
        self.talker = talker
        self.mmproj = mmproj

    def latents(self, path):
        # для Qwen "latent" — это просто путь к референсному WAV спикера
        return str(path)

    def speak(self, text, lang, lat, speed):
        import subprocess, tempfile

        qwen_lang = {"ru": "ru", "en": "en", "es": "es"}.get(lang, "en")
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tf:
            out_path = tf.name
        try:
            cmd = [
                self.bin,
                "-m", self.talker,
                "-mm", self.mmproj,
                "-p", text,
                "--tts-lang", qwen_lang,
                "--tts-speaker-file", str(lat),
                "-o", out_path,
                "-ngl", "99",  # вся модель на GPU
                "--log-disable",  # не раздражать логами в stderr
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if r.returncode != 0:
                raise RuntimeError(f"llama-tts rc={r.returncode}: {r.stderr[-400:]}")
            raw = Path(out_path).read_bytes()
            x, sr = read_wav(raw)
            return resample(x, sr)
        finally:
            try:
                os.unlink(out_path)
            except FileNotFoundError:
                pass


class KokoroRuEngine:
    """Kokoro-RU (zaakirio/kokoro-ru, 82M, ONNX, CPU ~10x realtime).
    Фиксированные голоса dima/sveta/masha из ~/.w420/tts-models/kokoro-ru.
    Русский G2P с ударениями: '+' перед ударной гласной (phonemize_accented),
    напр. "времена" -> "вре+мена". Для не-ru языков — фолбэк на espeak-ng ниже.
    """

    sr = SR
    VOICES = ("dima", "sveta", "masha")

    def __init__(self, model_dir: Path):
        import sys

        sys.path.insert(0, str(model_dir))  # для ru_g2p
        import numpy as np
        from kokoro_onnx import Kokoro
        from ru_g2p import RuG2P

        self.dir = model_dir
        self.g2p = RuG2P(espeak_data=model_dir / "espeak-data")
        model = os.environ.get(
            "W420_KOKORO_MODEL", str(model_dir / "onnx" / "model_dima_quantized.onnx")
        )
        if not os.path.isfile(model):
            model = str(model_dir / "onnx" / "model.onnx")
        self.kokoro = Kokoro(model, str(model_dir / "voices" / "dima.npy"))
        self.packs = {}
        for v in self.VOICES:
            raw = np.fromfile(model_dir / "voices" / f"{v}.bin", dtype=np.float32)
            self.packs[v] = raw.reshape(-1, 1, 256)

    def latents(self, name):
        # для Kokoro "latent" — это имя фиксированного голоса (dima/sveta/masha)
        name = str(name).strip().lower()
        return name if name in self.VOICES else self.VOICES[0]

    def speak(self, text, lang, lat, speed):
        import numpy as np

        if lang != "ru":
            # Kokoro-RU только русский; прочее отдаём espeak-ng как раньше
            import subprocess, tempfile

            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tf:
                out = tf.name
            try:
                subprocess.run(
                    ["espeak-ng", "-v", lang, "-s", str(int(170 * speed)), "-w", out, text],
                    capture_output=True, timeout=60,
                )
                raw = Path(out).read_bytes()
                x, sr = read_wav(raw)
                return resample(x, sr)
            finally:
                try:
                    os.unlink(out)
                except FileNotFoundError:
                    pass
        ipa, oov = self.g2p.phonemize_accented(_plus_to_acute_marks(text))
        if oov:
            state["msg"] = f"kokoro-ru OOV: {sorted(oov)}"
        samples, sr = self.kokoro.create(
            ipa, voice=self.packs[lat], speed=min(2.0, max(0.5, speed)), lang="ru", is_phonemes=True
        )
        return resample(np.asarray(samples, dtype=np.float32), sr)


def _plus_to_acute_marks(text: str) -> str:
    """'+' рядом с гласной -> combining acute U+0301 на этой гласной (то, что
    понимает acute-aware espeak-data kokoro-ru). Сам '+' всегда удаляется и
    никогда не озвучивается. Работает и "времена+" (после гласной), и "вре+мена" (до)."""
    vowels = "аеёиоуыэюяАЕЁИОУЫЭЮЯaeiouyAEIOUY"
    out, i = [], 0
    while i < len(text):
        ch = text[i]
        if ch == "+":
            if out and out[-1] and out[-1][-1] in vowels and not out[-1].endswith("́"):
                out[-1] += "́"  # U+0301 после гласной слева ("времена+")
            elif i + 1 < len(text) and text[i + 1] in vowels:
                out.append(text[i + 1] + "́")  # U+0301 после гласной справа ("вре+мена")
                i += 1
            # иначе '+' просто выбрасываем
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _register_kokoro_voices():
    """Регистрирует фиксированные голоса Kokoro-RU в общем реестре голосов,
    чтобы /speak принимал их id как обычные voice_id (с полем pack=имя голоса)."""
    with meta_lock:
        items = load_meta()
        have = {i["id"] for i in items}
        for v in KokoroRuEngine.VOICES:
            vid = hashlib.md5(f"kokoro-ru:{v}".encode()).hexdigest()[:12]
            if vid not in have:
                items.append({
                    "id": vid, "name": f"kokoro-ru {v}", "pack": v,
                    "seconds": 0, "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "consent_at": "fixed voice (consented studio actor, OpenRAIL)",
                })
        save_meta(items)


def load_engine():
    global engine
    try:
        if os.environ.get("W420_TTS_FAKE") == "1":
            engine = FakeEngine()
            state.update(status="ready", engine="fake", device="cpu", msg="тестовый движок (тон вместо голоса)")
            return
        # Выбор движка: W420_TTS_ENGINE=qwen|kokoro|xtts|auto (auto: kokoro-ru, если модель на месте, иначе qwen, иначе xtts)
        want = os.environ.get("W420_TTS_ENGINE", "auto").lower()
        home = Path(os.environ.get("W420_HOME", Path.home() / ".w420"))
        tmodels = home / "tts-models"
        kdir = Path(os.environ.get("W420_KOKORO_DIR", str(tmodels / "kokoro-ru")))
        kokoro_ok = (kdir / "onnx").is_dir() and any((kdir / "voices").glob("*.bin"))
        if want == "kokoro" or (want == "auto" and kokoro_ok):
            if not kokoro_ok:
                state.update(status="error", msg="Kokoro-RU: нет модели в ~/.w420/tts-models/kokoro-ru")
                return
            try:
                engine = KokoroRuEngine(kdir)
            except Exception as e:
                state.update(status="error", msg=f"Kokoro-RU не загрузился: {type(e).__name__}: {e}")
                return
            _register_kokoro_voices()
            state.update(
                status="ready",
                engine="kokoro-ru-onnx",
                device="cpu",
                msg=f"Kokoro-RU 82M ONNX (голоса: {', '.join(KokoroRuEngine.VOICES)}), CPU ~10x realtime, ударения через '+'",
            )
            return
        qbin = os.environ.get(
            "W420_QWEN_TTS_BIN",
            str(Path.home() / ".hermes/tools/llamacpp-vulkan-11671-linux-x64/llama-tts"),
        )
        qtalker = os.environ.get("W420_QWEN_TALKER", str(tmodels / "qwen3-tts-1.7b-base-q8_0.gguf"))
        qmm = os.environ.get("W420_QWEN_MMPROJ", str(tmodels / "mmproj-qwen3-tts-1.7b-q8_0.gguf"))
        qwen_ok = os.path.isfile(qbin) and os.path.isfile(qtalker) and os.path.isfile(qmm)
        if want == "qwen" or (want == "auto" and qwen_ok):
            if not qwen_ok:
                state.update(status="error", msg="Qwen3-TTS: не найден llama-tts или модели в ~/.w420/tts-models")
                return
            engine = QwenEngine(qbin, qtalker, qmm)
            state.update(
                status="ready",
                engine="qwen3-tts-llamacpp",
                device="gpu-vulkan",
                msg=f"Qwen3-TTS 1.7B q8_0 через llama-tts ({Path(qtalker).name}), VRAM ~2.3 ГБ",
            )
            return
        if want not in ("xtts", "auto"):
            state.update(status="error", msg=f"неизвестный W420_TTS_ENGINE={want}")
            return
        if os.environ.get("COQUI_TOS_AGREED") != "1":
            state.update(status="error", msg="лицензия XTTS (CPML, некоммерческая) не принята")
            return
        # RAM-гейт (аудит 15.11): XTTS-v2 на CPU держит в памяти ~4 ГБ (веса fp32 +
        # буферы инференса). Если доступной памяти меньше порога — честно говорим
        # об ошибке вместо того чтобы ловить OOM-kill от ядра.
        try:
            avail_mb = int(
                next(l for l in open("/proc/meminfo") if l.startswith("MemAvailable")).split()[1]
            ) / 1024
            if avail_mb < 6144:  # порог 6 ГБ
                state.update(
                    status="error",
                    msg=f"XTTS-v2 на CPU требует ~6 ГБ свободной RAM (сейчас доступно {avail_mb / 1024:.1f} ГБ). "
                    "Освободите память или озвучка уйдёт на espeak-ng (фолбэк в приложении).",
                )
                return
        except Exception:
            pass  # не смогли прочитать meminfo — пробуем грузить как раньше
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
            item = next((i for i in load_meta() if i["id"] == vid), {})
            latents[vid] = engine.latents(item.get("pack") or VOICES / f"{vid}.wav")
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

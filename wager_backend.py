# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import re
import threading
import time
import logging
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Tuple, Optional

import requests
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

# =========================================================
# Pretty logging (zero deps)
# =========================================================

def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return getattr(getattr(logging, "StreamHandler").stream, "isatty", lambda: False)()
    except Exception:
        try:
            import sys
            return sys.stdout.isatty()
        except Exception:
            return False

COLOR = _supports_color()

class PrettyLog:
    C_RESET = "\033[0m"
    C_DIM   = "\033[2m"
    C_BOLD  = "\033[1m"
    C_RED   = "\033[31m"
    C_GRN   = "\033[32m"
    C_YEL   = "\033[33m"
    C_BLU   = "\033[34m"
    C_CYN   = "\033[36m"

    def __init__(self, logger: logging.Logger):
        self.l = logger

    def _fmt(self, icon: str, msg: str, color: str = "", bold: bool = False) -> str:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        if COLOR and color:
            return f"[{ts}] {icon} {(self.C_BOLD if bold else '')}{color}{msg}{self.C_RESET}"
        return f"[{ts}] {icon} {msg}"

    def info(self, msg: str):  self.l.info(self._fmt("ℹ️", msg))
    def ok(self, msg: str):    self.l.info(self._fmt("✅", msg, self.C_GRN))
    def warn(self, msg: str):  self.l.warning(self._fmt("⚠️", msg, self.C_YEL, True))
    def err(self, msg: str):   self.l.error(self._fmt("❌", msg, self.C_RED, True))
    def star(self, msg: str):  self.l.info(self._fmt("⭐", msg, self.C_BLU))
    def live(self, msg: str):  self.l.info(self._fmt("📺", msg, self.C_CYN))
    def dice(self, msg: str):  self.l.info(self._fmt("🎲", msg, self.C_GRN))
    def debug(self, msg: str): self.l.debug(self._fmt("🔍", msg, self.C_DIM))

def _mk_logger() -> PrettyLog:
    os.makedirs("logs", exist_ok=True)
    logger = logging.getLogger("wager")
    level  = os.getenv("LOGLEVEL", "INFO").upper()
    logger.setLevel(getattr(logging, level, logging.INFO))

    fmt = logging.Formatter("%(message)s")
    sh  = logging.StreamHandler()
    sh.setLevel(getattr(logging, level, logging.INFO))
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    fh = RotatingFileHandler("logs/audit.log", maxBytes=2_000_000, backupCount=5)
    fh.setLevel(logging.DEBUG)  # always keep file verbose
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return PrettyLog(logger)

log = _mk_logger()

# =========================================================
# App & CORS
# =========================================================

app = Flask(__name__)
CORS(app)

# =========================================================
# Config
# =========================================================

API_KEY = os.getenv("API_KEY", "f45f746d-b021-494d-b9b6-b47628ee5cc9")

START_TIME = int(os.getenv("START_TIME", "1763506800"))  # 2025-11-18 18:00:00 EST
END_TIME   = int(os.getenv("END_TIME",   "1764111600"))  # 2025-11-25 18:00:00 EST

REFRESH_SECONDS = int(os.getenv("REFRESH_SECONDS", "60"))
PORT = int(os.getenv("PORT", "8080"))

# Kick OAuth credentials
KICK_CLIENT_ID = os.getenv("KICK_CLIENT_ID", "01K39PNSMPVX2PS4EEJ2K69EVF")
KICK_CLIENT_SECRET = os.getenv(
    "KICK_CLIENT_SECRET",
    "47970da4c8790427e09eaebd1b7c8d522ef233c54bbd896514c7f562c66ca74e",
)
KICK_CHANNEL_SLUG = os.getenv("KICK_CHANNEL_SLUG", "redhunllef")

_KICK_API_BASE   = "https://api.kick.com/public/v1"
_KICK_OAUTH_TOKEN = "https://id.kick.com/oauth/token"

URL_RANGE = "https://affiliate.shuffle.com/stats/{API_KEY}?startTime={start}&endTime={end}"
URL_LIFE  = "https://affiliate.shuffle.com/stats/{API_KEY}"

log.star("Backend starting…")

# =========================================================
# Caches
# =========================================================

_cache_lock   = threading.Lock()
_data_cache: Dict[str, Any] = {"podium": [], "others": []}

_stream_lock  = threading.Lock()
_stream_cache: Dict[str, Any] = {"live": False, "title": None, "viewers": None, "updated": 0, "source": "unknown"}
_STREAM_TTL_OK    = 60
_STREAM_TTL_ERROR = 120

_token_lock  = threading.Lock()
_kick_token: Dict[str, Any] = {"access_token": None, "expires_at": 0}

# =========================================================
# Helpers
# =========================================================

def censor_username(username: str) -> str:
    """Public rule: first two characters + six asterisks."""
    if not username:
        return "******"
    return username[:2] + "*" * 6

def _sanitize_window() -> Tuple[int, int, str]:
    """Clamp window to now; fallback to last 14d if invalid."""
    now = int(time.time())
    start = START_TIME
    end = END_TIME
    reason = "configured"

    if end > now:
        end = now
        reason = "end_clamped_to_now"

    if start >= end:
        end = now
        start = now - 14 * 24 * 3600
        reason = "fallback_last_14d"

    return start, end, reason

def _money(v) -> str:
    try:
        return f"${float(v):,.2f}"
    except Exception:
        return "$0.00"

# =========================================================
# Shuffle fetch/transform
# =========================================================

def _fetch_from_shuffle() -> List[dict]:
    headers = {"User-Agent": "Shuffle-WagerRace/Final"}
    start, end, why = _sanitize_window()
    url_range = URL_RANGE.format(API_KEY=API_KEY, start=start, end=end)
    url_life  = URL_LIFE.format(API_KEY=API_KEY)

    try:
        t0 = time.perf_counter()
        log.debug(f"shuffle: window fetch start={start} end={end} ({why})")
        r = requests.get(url_range, timeout=20, headers=headers)

        if r.status_code == 400:
            log.warn("Shuffle window rejected (400). Falling back to lifetime.")
            r2 = requests.get(url_life, timeout=20, headers=headers)
            r2.raise_for_status()
            dt = (time.perf_counter() - t0) * 1000
            log.ok(f"Shuffle lifetime fetch OK ({dt:.1f} ms)")
            data = r2.json()
            if not isinstance(data, list):
                raise ValueError("unexpected API format (lifetime)")
            return data

        r.raise_for_status()
        dt = (time.perf_counter() - t0) * 1000
        log.ok(f"Shuffle window fetch OK ({dt:.1f} ms)")
        data = r.json()
        if not isinstance(data, list):
            raise ValueError("unexpected API format (window)")
        return data

    except requests.RequestException as exc:
        log.warn(f"Shuffle window fetch failed ({exc}). Trying lifetime…")
        r3 = requests.get(url_life, timeout=20, headers=headers)
        r3.raise_for_status()
        data = r3.json()
        if not isinstance(data, list):
            raise ValueError("unexpected API format (lifetime_after_fail)")
        return data

def _process_entries(entries: List[dict]) -> Dict[str, Any]:
    # Keep only referral campaign
    filtered = [e for e in entries if e.get("campaignCode") == "Red"]

    def _w(e: dict) -> float:
        try:
            return float(e.get("wagerAmount", 0) or 0)
        except (TypeError, ValueError):
            return 0.0

    sorted_entries = sorted(filtered, key=_w, reverse=True)

    podium, others = [], []
    top10_admin_lines = []

    for i, entry in enumerate(sorted_entries[:10], start=1):
        full = entry.get("username", "Unknown")
        try:
            amt = float(entry.get("wagerAmount", 0) or 0)
        except (TypeError, ValueError) as exc:
            log.err(f"Could not parse wager for row {i} (user={full}): {exc}")
            amt = 0.0

        wager_str = _money(amt)

        # Build admin summary (FULL names in console)
        top10_admin_lines.append(f"   {str(i).rjust(2)}. {full} — {wager_str} wagered")

        public = {"username": censor_username(full), "wager": wager_str}
        if i <= 3:
            podium.append(public)
        else:
            others.append({"rank": i, **public})

    if top10_admin_lines:
        log.dice("Leaderboard refreshed (top 10)\n" + "\n".join(top10_admin_lines))

    return {"podium": podium, "others": others}

def _refresh_cache() -> None:
    t0 = time.perf_counter()
    try:
        processed = _process_entries(_fetch_from_shuffle())
        with _cache_lock:
            _data_cache.update(processed)

        # snapshot
        try:
            with open("logs/latest_cache.json", "w", encoding="utf-8") as f:
                json.dump(processed, f, indent=2)
        except Exception as ex:
            log.warn(f"Cache snapshot skipped ({ex})")

        log.ok(f"Cache updated in {(time.perf_counter()-t0)*1000:.1f} ms "
               f"(podium={len(processed['podium'])}, others={len(processed['others'])})")
    except Exception as exc:
        log.err(f"Cache update failed: {exc}")

def _schedule_refresh() -> None:
    _refresh_cache()
    threading.Timer(REFRESH_SECONDS, _schedule_refresh).start()

# Start refresh loop once
_schedule_refresh()

# =========================================================
# Kick live status
# =========================================================

_KICK_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.8",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "DNT": "1",
    "Connection": "keep-alive",
    "Referer": "https://kick.com/",
}

_NEXT_JSON_RE = re.compile(r'(?s)<script[^>]+type="application/json"[^>]*>\s*(\{.*?\})\s*</script>')
_BOOL_RE = re.compile(r'"is_live"\s*:\s*(true|false)', re.IGNORECASE)
_TITLE_RE = re.compile(r'"(session_title|stream_title)"\s*:\s*"([^"]+)"')
_VIEWERS_RE = re.compile(r'"viewer_count"\s*:\s*(\d+)', re.IGNORECASE)

def _extract_live_from_api_channel_payload(data: dict) -> Tuple[bool, Optional[str], Optional[int], str]:
    if not isinstance(data, dict):
        return (False, None, None, "kick-api")
    stream  = data.get("stream") or {}
    is_live = bool(stream.get("is_live"))
    title   = data.get("stream_title") or stream.get("title") or None
    viewers = stream.get("viewer_count") or None
    try:
        viewers = int(viewers) if viewers is not None else None
    except Exception:
        viewers = None
    return (is_live, title, viewers, "kick-api")

def get_kick_app_token(force_refresh: bool = False) -> Optional[str]:
    if not KICK_CLIENT_ID or not KICK_CLIENT_SECRET:
        log.warn("Kick token not requested (missing client ID/secret)")
        return None

    now = time.time()
    with _token_lock:
        token = _kick_token.get("access_token")
        exp   = float(_kick_token.get("expires_at") or 0)
        if token and not force_refresh and (exp - now) > 30:
            return token

        try:
            payload = {
                "grant_type": "client_credentials",
                "client_id": KICK_CLIENT_ID,
                "client_secret": KICK_CLIENT_SECRET,
            }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            r = requests.post(_KICK_OAUTH_TOKEN, data=payload, headers=headers, timeout=10)
            if r.status_code != 200:
                log.warn(f"Kick token request failed (HTTP {r.status_code})")
                return None
            j = r.json()
            access     = j.get("access_token")
            expires_in = int(j.get("expires_in") or 3600)
            if not access:
                log.warn("Kick token received without access_token")
                return None
            _kick_token["access_token"] = access
            _kick_token["expires_at"]  = now + max(expires_in - 10, 30)  # safety buffer
            log.ok("Kick OAuth token acquired")
            return access
        except Exception as exc:
            log.warn(f"Kick token request error: {exc}")
            return None

def _scrape_kick_html(channel: str) -> Dict[str, Any]:
    url_page = f"https://kick.com/{channel}"
    try:
        r = requests.get(url_page, headers=_KICK_HEADERS, timeout=10)
        if r.status_code != 200:
            log.warn(f"Kick HTML fetch failed (HTTP {r.status_code})")
            return {"live": False, "title": None, "viewers": None, "source": "kick-html"}

        html = r.text or ""
        try:
            m = _NEXT_JSON_RE.search(html)
            if m:
                _ = json.loads(m.group(1))  # reserved for future stable path parsing
        except Exception as ex:
            log.debug(f"Kick HTML embedded JSON parse failed: {ex}")

        is_live = False
        title   = None
        viewers = None

        bm = _BOOL_RE.search(html)
        if bm:
            is_live = (bm.group(1).lower() == "true")

        tm = _TITLE_RE.search(html)
        if tm:
            title = tm.group(2).encode('utf-8', 'ignore').decode('utf-8', 'ignore')

        vm = _VIEWERS_RE.search(html)
        if vm:
            try:
                viewers = int(vm.group(1))
            except Exception:
                viewers = None

        log.info(f"Kick HTML parsed — live={is_live} viewers={viewers} title={'yes' if title else 'no'}")
        return {"live": is_live, "title": title, "viewers": viewers, "source": "kick-html"}
    except Exception as exc:
        log.warn(f"Kick HTML fetch error: {exc}")
        return {"live": False, "title": None, "viewers": None, "source": "unknown"}

def _fetch_kick_status(channel: str = KICK_CHANNEL_SLUG) -> Dict[str, Any]:
    token = get_kick_app_token(force_refresh=False)
    if token:
        try:
            url = f"{_KICK_API_BASE}/channels"
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            params = [("slug", channel)]
            log.debug(f"Kick API fetch {url} params={params}")
            r = requests.get(url, headers=headers, params=params, timeout=10)
            if r.status_code == 401:
                log.warn("Kick API 401 — refreshing token and retrying")
                token2 = get_kick_app_token(force_refresh=True)
                if token2:
                    headers["Authorization"] = f"Bearer {token2}"
                    r = requests.get(url, headers=headers, params=params, timeout=10)

            if r.status_code == 200:
                j = r.json()
                data = (j.get("data") or [])
                if data:
                    is_live, title, viewers, src = _extract_live_from_api_channel_payload(data[0])
                    log.info(f"Kick API parsed — live={is_live} viewers={viewers}")
                    return {"live": is_live, "title": title, "viewers": viewers, "source": src}
                log.info("Kick API returned no channel data for slug")
                return {"live": False, "title": None, "viewers": None, "source": "kick-api"}

            log.warn(f"Kick API error HTTP {r.status_code} — falling back to HTML")
            # fall through to HTML
        except Exception as exc:
            log.warn(f"Kick API request failed: {exc}")
            # fall through to HTML

    return _scrape_kick_html(channel)

def get_stream_status() -> Dict[str, Any]:
    now = int(time.time())
    with _stream_lock:
        ttl = _STREAM_TTL_OK if _stream_cache.get("source") == "kick-api" else _STREAM_TTL_ERROR
        if now - int(_stream_cache.get("updated", 0)) < ttl:
            return dict(_stream_cache)

    status = _fetch_kick_status(KICK_CHANNEL_SLUG)
    status["updated"] = now
    with _stream_lock:
        _stream_cache.update(status)

    if status.get("live"):
        log.live(f"Stream status: LIVE — {status.get('viewers') if status.get('viewers') is not None else 'unknown'} watching ({status.get('source')})")
    else:
        log.live(f"Stream status: OFFLINE ({status.get('source')})")
    return status

# =========================================================
# HTTP
# =========================================================

@app.before_request
def _audit():
    ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "?").split(",")[0].strip()
    ua = (request.user_agent.string or "").replace("\n", " ")[:160]
    log.info(f"Request from {ip} — {request.path} ({ua})")

@app.after_request
def _sec(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return resp

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/data")
def data():
    with _cache_lock:
        payload = dict(_data_cache)
    return jsonify(payload)

@app.route("/config")
def config():
    return jsonify({"start_time": START_TIME, "end_time": END_TIME, "refresh_seconds": REFRESH_SECONDS})

@app.route("/stream")
def stream():
    return jsonify(get_stream_status())

@app.errorhandler(404)
def nf(e):
    return render_template("404.html"), 404

# =========================================================
# Entrypoint
# =========================================================

if __name__ == "__main__":
    log.star(f"Background refreshers run every {REFRESH_SECONDS}s")
    log.ok(f"Server listening on 0.0.0.0:{PORT}")
    app.run(host="0.0.0.0", port=PORT)









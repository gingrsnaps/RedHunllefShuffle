# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import re
import threading
import time
import logging
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Tuple

import requests
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS


# =========================================================
# Logging with color + prefixes
# =========================================================

def _supports_color() -> bool:
    """Very small guard so local dev gets color, logs still readable in files."""
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
    def warn(self, msg: str):  self.l.warning(self._fmt("⚠️", msg, self.C_YEL))
    def err(self, msg: str):   self.l.error(self._fmt("❌", msg, self.C_RED, bold=True))
    def star(self, msg: str):  self.l.info(self._fmt("✴️", msg, self.C_BLU))
    def dice(self, msg: str):  self.l.info(self._fmt("🎲", msg, self.C_GRN))


# Root logger writes both to console and rotating file
_root_logger = logging.getLogger("wager_backend")
_root_logger.setLevel(logging.INFO)

_console = logging.StreamHandler()
_console.setFormatter(logging.Formatter("%(message)s"))

os.makedirs("logs", exist_ok=True)
_file = RotatingFileHandler("logs/wager_backend.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
_file.setFormatter(logging.Formatter("%(message)s"))

_root_logger.addHandler(_console)
_root_logger.addHandler(_file)

log = PrettyLog(_root_logger)


# =========================================================
# Environment config
# =========================================================

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default

def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except Exception:
        return default

def _env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


PORT = _env_int("PORT", 5000)

SHUFFLE_API_KEY = _env_str("SHUFFLE_API_KEY")
if not SHUFFLE_API_KEY:
    log.warn("SHUFFLE_API_KEY is not set – /data will fail until configured.")

START_TIME = _env_int("START_TIME", 0)
END_TIME   = _env_int("END_TIME", 0)

REFRESH_SECONDS = _env_int("REFRESH_SECONDS", 60)

KICK_CLIENT_ID     = _env_str("KICK_CLIENT_ID")
KICK_CLIENT_SECRET = _env_str("KICK_CLIENT_SECRET")
KICK_CHANNEL_SLUG  = _env_str("KICK_CHANNEL_SLUG", "redhunllef")

# Kick endpoints (public)
KICK_PUBLIC_CHANNEL = "https://kick.com/api/v2/channels/{slug}"

# Shuffle endpoints
URL_WINDOW = "https://affiliate.shuffle.com/stats/{API_KEY}?startTime={start}&endTime={end}"
URL_LIFE   = "https://affiliate.shuffle.com/stats/{API_KEY}"

log.star("Backend booting…")
log.info(f"PORT={PORT}  START_TIME={START_TIME}  END_TIME={END_TIME}  REFRESH_SECONDS={REFRESH_SECONDS}")
if KICK_CHANNEL_SLUG:
    log.info(f"KICK_CHANNEL_SLUG={KICK_CHANNEL_SLUG}")
if KICK_CLIENT_ID:
    log.info("KICK_CLIENT_ID present")
if not KICK_CLIENT_ID or not KICK_CLIENT_SECRET:
    log.warn("Kick credentials not set; /stream will fallback to public endpoint only.")


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

def _money(value: float) -> str:
    """Format a float as currency string with commas and 2 decimals."""
    try:
        return "${:,.2f}".format(float(value or 0.0))
    except Exception:
        return "$0.00"

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

    # If no start/end, or start> end, fallback to 14 days ago.
    if start <= 0 or start >= end:
        start = now - 14 * 86400
        end = now
        reason = "fallback_last_14d"

    return start, end, reason

def _build_shuffle_urls() -> Tuple[str, str]:
    start, end, reason = _sanitize_window()
    if reason != "configured":
        log.warn(f"Using fallback window ({reason}) {start}–{end}")

    url_window = URL_WINDOW.format(API_KEY=SHUFFLE_API_KEY, start=start, end=end)
    url_life   = URL_LIFE.format(API_KEY=SHUFFLE_API_KEY)
    return url_window, url_life

def _http_get_json(url: str, headers: Dict[str, str] | None = None, timeout: float = 15.0) -> Any:
    """GET and decode JSON with basic error handling."""
    h = headers or {}
    t0 = time.perf_counter()
    r = requests.get(url, timeout=timeout, headers=h)
    dt = (time.perf_counter() - t0) * 1000
    r.raise_for_status()
    log.ok(f"GET {url} – {dt:.1f} ms (status {r.status_code})")
    return r.json()


# =========================================================
# Shuffle leaderboard fetching
# =========================================================

def _fetch_from_shuffle() -> List[dict]:
    """Hit Shuffle stats API with configured window, fallback to lifetime."""
    if not SHUFFLE_API_KEY:
        raise RuntimeError("SHUFFLE_API_KEY missing")

    url_window, url_life = _build_shuffle_urls()
    headers = {
        "User-Agent": "RedHunllef-WagerBoard/1.0",
        "Accept": "application/json",
    }

    try:
        log.info(f"Fetching Shuffle window stats: {url_window}")
        t0 = time.perf_counter()
        r = requests.get(url_window, timeout=20, headers=headers)
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

    except Exception as exc:
        log.err(f"Shuffle stats fetch failed: {exc}")
        raise


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
    top_admin_lines = []

    # NOTE: this is the only functional change:
    # previously we sliced [:10]; now [:11] so rank 11 is included.
    for i, entry in enumerate(sorted_entries[:11], start=1):
        full = entry.get("username", "Unknown")
        try:
            amt = float(entry.get("wagerAmount", 0) or 0)
        except (TypeError, ValueError) as exc:
            log.err(f"Could not parse wager for row {i} (user={full}): {exc}")
            amt = 0.0

        wager_str = _money(amt)

        # Build admin summary (FULL names in console)
        top_admin_lines.append(f"   {str(i).rjust(2)}. {full} — {wager_str} wagered")

        public = {"username": censor_username(full), "wager": wager_str}
        if i <= 3:
            podium.append(public)
        else:
            others.append({"rank": i, **public})

    if top_admin_lines:
        log.dice("Leaderboard refreshed (top 11)\n" + "\n".join(top_admin_lines))

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
# Kick stream status (public API)
# =========================================================

def _fetch_kick_public() -> Dict[str, Any]:
    """Lightweight public call – no OAuth, just channel slug."""
    slug = KICK_CHANNEL_SLUG or "redhunllef"
    url = KICK_PUBLIC_CHANNEL.format(slug=slug)
    try:
        t0 = time.perf_counter()
        r = requests.get(url, timeout=10)
        dt = (time.perf_counter() - t0) * 1000
        r.raise_for_status()
        log.ok(f"Kick public API OK ({dt:.1f} ms)")
        return r.json()
    except Exception as exc:
        log.warn(f"Kick public API failed: {exc}")
        raise


def _parse_kick_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract live flag, title and viewers from Kick API payload.

    We keep this defensive so schema changes don't crash the site – if anything
    looks wrong, we just treat it as offline.
    """
    try:
        livestream = data.get("livestream") or {}
        is_live = bool(livestream.get("is_live"))
        title = livestream.get("session_title") or ""
        viewers = livestream.get("viewer_count")
        return {"live": is_live, "title": title, "viewers": viewers}
    except Exception as exc:
        log.warn(f"Kick payload parse failed: {exc}")
        return {"live": False, "title": None, "viewers": None}


def get_stream_status() -> Dict[str, Any]:
    """Read stream cache; refresh if TTL expired."""
    now = time.time()
    with _stream_lock:
        cached = dict(_stream_cache)

    ttl = _STREAM_TTL_OK if cached.get("live") else _STREAM_TTL_ERROR
    if cached["updated"] and now - cached["updated"] < ttl:
        return cached

    try:
        raw = _fetch_kick_public()
        parsed = _parse_kick_payload(raw)
        parsed["updated"] = now
        parsed["source"] = "kick_public"
        with _stream_lock:
            _stream_cache.update(parsed)
        return parsed
    except Exception:
        # keep whatever is in cache, but mark as stale
        with _stream_lock:
            _stream_cache["source"] = "error"
        return _stream_cache


# =========================================================
# Flask app
# =========================================================

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)


@app.after_request
def _security_headers(resp):
    """Small CSP/security hardening."""
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "img-src 'self' data: https://*; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' https://*; "
        "frame-ancestors 'self';"
    )
    return resp


@app.route("/")
def index():
  return render_template("index.html")


@app.route("/data")
def data():
    """Return current podium + others cache."""
    with _cache_lock:
        payload = dict(_data_cache)
    # log a tiny trace so you can see IP/user-agent without extra deps
    try:
        ip = request.headers.get("CF-Connecting-IP") or request.remote_addr or "unknown"
        ua = request.headers.get("User-Agent", "unknown")
        log.info(f"/data -> {ip} :: {ua}")
    except Exception:
        pass
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

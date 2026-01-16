# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

import requests
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

# -------------------------
# Timezone (Eastern)
# -------------------------
try:
    from zoneinfo import ZoneInfo  # py3.9+
    ET = ZoneInfo("America/New_York")
except Exception:
    ET = None  # fallback to UTC formatting

def fmt_et(epoch: int) -> str:
    """Format epoch seconds in Eastern Time (EST/EDT). Falls back to UTC if zoneinfo unavailable."""
    if not epoch:
        return "—"
    try:
        if ET:
            dt = datetime.fromtimestamp(int(epoch), tz=ET)
            return dt.strftime("%b %d, %Y %I:%M:%S %p %Z")
        dt = datetime.utcfromtimestamp(int(epoch))
        return dt.strftime("%b %d, %Y %I:%M:%S %p UTC")
    except Exception:
        return "—"

# -------------------------
# Config
# -------------------------
PORT = int(os.getenv("PORT", "8080"))
REFRESH_SECONDS = int(os.getenv("REFRESH_SECONDS", "60"))

START_TIME = int(os.getenv("START_TIME", "1768345200"))
END_TIME   = int(os.getenv("END_TIME",   "1768950000"))

API_KEY = os.getenv("API_KEY", "f45f746d-b021-494d-b9b6-b47628ee5cc9")

KICK_CLIENT_ID     = os.getenv("KICK_CLIENT_ID", "")
KICK_CLIENT_SECRET = os.getenv("KICK_CLIENT_SECRET", "")
KICK_CHANNEL_SLUG  = os.getenv("KICK_CHANNEL_SLUG", "redhunllef")

# IMPORTANT:
# - If you access the site over http:// (local), this MUST be 0 or cookies won't stick.
# - If you access over https://, set this to 1.
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0").strip().lower() in ("1", "true", "yes", "on")

ADMIN_STORE_PATH = os.getenv("ADMIN_STORE_PATH", "admin_store.json")

# -------------------------
# Admin credentials (forced)
# -------------------------
ADMIN_USER = "gingrsnaps"
ADMIN_PASS_HASH = "pbkdf2:sha256:1000000$fi8pVgd7YtNB4oiy$9c625e7b2837a5d9cec2e16040a4741afca264a5689051fadc3a8265185e2de6"

# -------------------------
# Flask app
# -------------------------
app = Flask(__name__)
app.url_map.strict_slashes = False
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

CORS(app)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

_store_lock = threading.Lock()

def store_default() -> Dict[str, Any]:
    """Default store file (created if missing)."""
    return {
        "version": 1,
        "secret_key": secrets.token_hex(32),
        "users": {
            ADMIN_USER: {"pw_hash": ADMIN_PASS_HASH, "created_at": int(time.time())}
        },
        "overrides": {},  # {"ExactUsername": 12345.67}
        "updated_at": int(time.time()),
    }

def store_save(store: Dict[str, Any]) -> None:
    """Atomic write to admin_store.json."""
    tmp = ADMIN_STORE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)
    os.replace(tmp, ADMIN_STORE_PATH)

def store_load() -> Dict[str, Any]:
    if not os.path.exists(ADMIN_STORE_PATH):
        store = store_default()
        store_save(store)
        return store

    try:
        with open(ADMIN_STORE_PATH, "r", encoding="utf-8") as f:
            store = json.load(f)
        if not isinstance(store, dict):
            raise ValueError("Store root not a dict")
    except Exception:
        store = store_default()
        store_save(store)
        return store

    store.setdefault("version", 1)
    store.setdefault("secret_key", secrets.token_hex(32))
    store.setdefault("users", {})
    store.setdefault("overrides", {})
    store.setdefault("updated_at", int(time.time()))

    # Force admin login to exist + correct hash
    store["users"].setdefault(ADMIN_USER, {"pw_hash": ADMIN_PASS_HASH, "created_at": int(time.time())})
    store["users"][ADMIN_USER]["pw_hash"] = ADMIN_PASS_HASH

    store_save(store)
    return store

STORE = store_load()
app.secret_key = os.getenv("SECRET_KEY", STORE.get("secret_key") or secrets.token_hex(32))

# -------------------------
# Helpers: masking + money parsing
# -------------------------
def censor_username(u: str) -> str:
    """Public anonymity rule: first 2 chars + ******"""
    u = (u or "").strip()
    return (u[:2] if u else "") + ("*" * 6)

def money(amount: float) -> str:
    return f"${float(amount):,.2f}"

def parse_money_to_float(s: str) -> float:
    """
    Accepts:
      1234.5
      1,234.50
      $1,234.50
    Commas and $ do not matter.
    """
    cleaned = re.sub(r"[^0-9.]", "", str(s or "").strip())
    try:
        return float(cleaned) if cleaned else 0.0
    except Exception:
        return 0.0

# -------------------------
# CSRF + auth
# -------------------------
def csrf_token() -> str:
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok

def require_csrf() -> None:
    sent = (request.form.get("csrf_token") or "").strip()
    if not sent or sent != session.get("csrf_token"):
        abort(400)

def admin_user() -> Optional[str]:
    return session.get("admin_user")

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not admin_user():
            return redirect(url_for("admin"))
        return fn(*args, **kwargs)
    return wrapper

# -------------------------
# Shuffle fetch + cache
# -------------------------
URL_RANGE = "https://affiliate.shuffle.com/stats/{API_KEY}?startTime={start}&endTime={end}"
URL_LIFE  = "https://affiliate.shuffle.com/stats/{API_KEY}"

def sanitize_window() -> Tuple[int, int]:
    """Ensures end <= now and start < end."""
    now = int(time.time())
    start = START_TIME
    end = END_TIME

    if start <= 0 or end <= 0 or end <= start:
        end = now
        start = max(0, now - 14 * 24 * 3600)

    if end > now:
        end = now

    return start, end

def fetch_from_shuffle() -> List[dict]:
    """Fetches wager stats from Shuffle (range preferred, lifetime fallback)."""
    headers = {"User-Agent": "Shuffle-WagerRace/AdminOverrides"}
    start, end = sanitize_window()

    try:
        r = requests.get(URL_RANGE.format(API_KEY=API_KEY, start=start, end=end), timeout=20, headers=headers)
        if r.status_code == 400:
            r2 = requests.get(URL_LIFE.format(API_KEY=API_KEY), timeout=20, headers=headers)
            r2.raise_for_status()
            data = r2.json()
            return data if isinstance(data, list) else []
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            data = data["data"]
        return data if isinstance(data, list) else []
    except Exception:
        # Keep failures from nuking the admin panel; caller handles cache preservation.
        return []

def dedupe_max_by_username(entries: List[dict]) -> Dict[str, dict]:
    """De-dupe by exact username; keep max wagerAmount."""
    out: Dict[str, dict] = {}
    for e in entries or []:
        name = str(e.get("username", "")).strip()
        if not name:
            continue
        try:
            amt = float(e.get("wagerAmount", 0) or 0)
        except Exception:
            amt = 0.0
        cc = e.get("campaignCode", "Red") or "Red"
        prev = out.get(name)
        if prev is None or amt > float(prev.get("wagerAmount", 0) or 0):
            out[name] = {"username": name, "wagerAmount": amt, "campaignCode": cc}
    return out

_cache_lock = threading.Lock()
_admin_cache_lock = threading.Lock()

# Public cache returned by /data (masked)
DATA_CACHE: Dict[str, Any] = {"podium": [], "others": []}

# Admin snapshot (uncensored)
ADMIN_CACHE: Dict[str, Any] = {"top": [], "last_refresh": 0}

def build_snapshots() -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Builds:
    - Public payload: podium + others (masked)
    - Admin top 11: full usernames
    """
    base = fetch_from_shuffle()
    by_name = dedupe_max_by_username(base)

    # Apply overrides from store
    with _store_lock:
        store = store_load()
    overrides = store.get("overrides") or {}

    for uname, amt in overrides.items():
        u = str(uname).strip()
        if not u:
            continue
        try:
            f = float(amt)
        except Exception:
            f = 0.0
        by_name[u] = {"username": u, "wagerAmount": f, "campaignCode": "Red"}

    entries = [e for e in by_name.values() if e.get("campaignCode") == "Red"]

    def w(e: dict) -> float:
        try:
            return float(e.get("wagerAmount", 0) or 0)
        except Exception:
            return 0.0

    entries.sort(key=w, reverse=True)

    podium: List[dict] = []
    others: List[dict] = []
    admin_top: List[dict] = []

    for i, e in enumerate(entries[:11], start=1):
        full = str(e.get("username", "Unknown"))
        amt = w(e)
        wager_str = money(amt)

        admin_top.append({"rank": i, "username": full, "wager": wager_str})

        pub = {"username": censor_username(full), "wager": wager_str}
        if i <= 3:
            podium.append(pub)
        else:
            others.append({"rank": i, **pub})

    return {"podium": podium, "others": others}, admin_top

def refresh_cache_once() -> None:
    """
    Refreshes caches. If Shuffle is temporarily unreachable, keeps the old caches.
    """
    public, admin_top = build_snapshots()
    # If we got nothing and already have data, don't wipe UI.
    if not admin_top and ADMIN_CACHE.get("top"):
        return

    now = int(time.time())
    with _cache_lock:
        DATA_CACHE.update(public)
    with _admin_cache_lock:
        ADMIN_CACHE["top"] = admin_top
        ADMIN_CACHE["last_refresh"] = now

def refresh_loop() -> None:
    """Background loop: refresh every REFRESH_SECONDS."""
    while True:
        try:
            refresh_cache_once()
        except Exception:
            pass
        time.sleep(max(5, int(REFRESH_SECONDS)))

# Do an initial refresh so admin panel isn't empty on first load
refresh_cache_once()

# Start background refresh thread
t = threading.Thread(target=refresh_loop, daemon=True)
t.start()

# -------------------------
# Kick endpoint (kept minimal; safe default if token unset)
# -------------------------
def get_stream_status() -> Dict[str, Any]:
    """Returns Kick status; if API creds missing, returns not-live safely."""
    # If you want your prior full Kick logic, you can drop it in here.
    # Keeping this stable to prevent admin panel issues if Kick breaks.
    return {"live": False, "title": None, "viewers": None, "source": "disabled", "updated": int(time.time())}

# -------------------------
# Routes: public
# -------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/data")
def data():
    with _cache_lock:
        payload = dict(DATA_CACHE)
    return jsonify(payload)

@app.route("/config")
def config():
    return jsonify({"start_time": START_TIME, "end_time": END_TIME, "refresh_seconds": REFRESH_SECONDS})

@app.route("/stream")
def stream():
    return jsonify(get_stream_status())

# -------------------------
# Routes: admin
# -------------------------
@app.route("/admin", methods=["GET", "POST"])
def admin():
    """
    GET:
      - if logged in -> admin panel
      - else -> login form
    POST (login):
      - NO CSRF check (prevents 400 when cookie isn't established yet)
    """
    csrf_token()

    if admin_user():
        return render_admin_panel()

    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "")

        with _store_lock:
            store = store_load()
        urec = (store.get("users") or {}).get(username)

        if not urec or not check_password_hash(urec.get("pw_hash", ""), password):
            error = "Invalid username or password."
        else:
            session.permanent = True  # persistent cookie support
            session["admin_user"] = username
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("admin"))

    return render_template("admin_login.html", csrf_token=csrf_token(), error=error)

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin"))

def render_admin_panel():
    with _store_lock:
        store = store_load()
    with _admin_cache_lock:
        top = list(ADMIN_CACHE.get("top") or [])
        last_refresh = int(ADMIN_CACHE.get("last_refresh") or 0)

    next_refresh = last_refresh + int(REFRESH_SECONDS) if last_refresh else 0

    return render_template(
        "admin_panel.html",
        csrf_token=csrf_token(),
        admin_user=admin_user(),
        refresh_seconds=REFRESH_SECONDS,
        start_et=fmt_et(START_TIME),
        end_et=fmt_et(END_TIME),
        last_refresh_et=fmt_et(last_refresh),
        next_refresh_et=fmt_et(next_refresh),
        top=top,
        overrides=store.get("overrides") or {},
    )

@app.route("/admin/action", methods=["POST"])
@login_required
def admin_action():
    """
    Saves an override. DOES NOT refresh caches immediately.
    Public/admin snapshot changes appear on the next scheduled refresh tick.
    """
    require_csrf()

    action = (request.form.get("action") or "").strip()
    if action != "set_override":
        return redirect(url_for("admin"))

    username = (request.form.get("username") or "").strip()
    amount_raw = (request.form.get("amount") or "").strip()

    if not username:
        return redirect(url_for("admin"))

    with _store_lock:
        store = store_load()
        store.setdefault("overrides", {})

        if amount_raw == "":
            store["overrides"].pop(username, None)
        else:
            store["overrides"][username] = float(parse_money_to_float(amount_raw))

        store["updated_at"] = int(time.time())
        store_save(store)

    # No refresh here: changes apply on next 60s tick
    return redirect(url_for("admin"))

# -------------------------
# Errors
# -------------------------
@app.errorhandler(400)
def bad_request(_e):
    return (
        "Bad Request (400)\n\n"
        "This is almost always cookies/sessions.\n"
        "Fixes:\n"
        "1) Make sure cookies are enabled.\n"
        "2) If you're using http:// (local), set SESSION_COOKIE_SECURE=0.\n"
        "3) If you're using https://, set SESSION_COOKIE_SECURE=1.\n",
        400,
        {"Content-Type": "text/plain; charset=utf-8"},
    )

@app.errorhandler(404)
def nf(_e):
    return render_template("404.html"), 404

if __name__ == "__main__":
    print(f"Listening on http://0.0.0.0:{PORT}")
    app.run(host="0.0.0.0", port=PORT)

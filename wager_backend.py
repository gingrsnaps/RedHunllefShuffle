# -*- coding: utf-8 -*-

"""
wager_backend.py (updated)

Additions (no removal of existing behavior):
- Access log (rolling IP list in order) stored in admin_store.json
- Admin audit log (records admin actions)
- IP ban list (block abusive IPs early)
- Health fields (last refresh ok, API ms, last error)
- Top-11 delta snapshot support (shows movement since last tick)
- Admin user management UI/actions, but ONLY usable by the super-admin "gingrsnaps"

Notes:
- This file still preserves your existing endpoints (/data, /admin, /admin/action, etc.).
- Your existing override behavior is unchanged: overrides apply on the next scheduled refresh tick.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

import requests
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for, g
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

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

START_TIME = int(os.getenv("START_TIME", "1768950000"))  # 2026-01-20 18:00:00 Eastern
END_TIME   = int(os.getenv("END_TIME",   "1769554800"))  # 2026-01-27 18:00:00 Eastern

API_KEY = os.getenv("API_KEY", "f45f746d-b021-494d-b9b6-b47628ee5cc9")

KICK_CLIENT_ID     = os.getenv("KICK_CLIENT_ID", "")
KICK_CLIENT_SECRET = os.getenv("KICK_CLIENT_SECRET", "")
KICK_CHANNEL_SLUG  = os.getenv("KICK_CHANNEL_SLUG", "redhunllef")

# IMPORTANT:
# - If you access the site over http:// (local), this MUST be 0 or cookies won't stick.
# - If you access over https://, set this to 1.
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0").strip().lower() in ("1", "true", "yes", "on")

ADMIN_STORE_PATH = os.getenv("ADMIN_STORE_PATH", "admin_store.json")

# Rolling limits for logs (stored in admin_store.json)
ACCESS_LOG_MAX = int(os.getenv("ACCESS_LOG_MAX", "300"))
AUDIT_LOG_MAX  = int(os.getenv("AUDIT_LOG_MAX", "250"))

# -------------------------
# Admin credentials (forced super-admin)
# -------------------------
# Super-admin username. Only THIS user can manage other admin users.
ADMIN_USER = "gingrsnaps"
ADMIN_PASS_HASH = "pbkdf2:sha256:1000000$fi8pVgd7YtNB4oiy$9c625e7b2837a5d9cec2e16040a4741afca264a5689051fadc3a8265185e2de6"

# -------------------------
# Flask app
# -------------------------
app = Flask(__name__)
app.url_map.strict_slashes = False

# ProxyFix:
# - x_for=1 lets Flask see the real client IP via X-Forwarded-For (typical for DO/Cloudflare/Nginx).
# - Only enable x_for if you are behind a TRUSTED reverse proxy (which you are on most hosted platforms).
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

CORS(app)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

# Make sure INFO logs show up in console on most hosts
if not app.logger.handlers:
    logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

_store_lock = threading.Lock()


# -------------------------
# Admin store helpers
# -------------------------
def store_default() -> Dict[str, Any]:
    """
    Default store file (created if missing).

    IMPORTANT:
    - We keep your original keys (version/secret_key/users/overrides/updated_at).
    - We also add NEW keys for observability/user management.
    """
    now = int(time.time())
    return {
        "version": 1,
        "secret_key": secrets.token_hex(32),
        "users": {
            # Super-admin is always present and always uses the forced hash.
            ADMIN_USER: {"pw_hash": ADMIN_PASS_HASH, "created_at": now}
        },
        "overrides": {},  # {"ExactUsername": 12345.67}
        "updated_at": now,

        # ---- New additions (safe defaults) ----
        "access_log": [],              # rolling list of recent requests
        "audit_log": [],               # rolling list of admin actions
        "banned_ips": [],              # IPs blocked at request time
        "health": {                    # refresh/API health for admin visibility
            "last_refresh_ok": None,
            "last_refresh_et": None,
            "last_error": None,
            "last_api_ms": None,
            "last_source": None,
        },
        "leaderboard_snapshots": {     # used to compute deltas for Top 11
            "prev_top11": [],
            "last_top11": [],
            "updated_at": None,
        },
    }


def store_save(store: Dict[str, Any]) -> None:
    """Atomic write to admin_store.json."""
    tmp = ADMIN_STORE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)
    os.replace(tmp, ADMIN_STORE_PATH)


def _ensure_new_keys(store: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """
    Ensures new keys exist without removing anything.
    Returns (store, dirty_flag).
    """
    dirty = False

    def _sd(key: str, default: Any):
        nonlocal dirty
        if key not in store:
            store[key] = default
            dirty = True

    _sd("version", 1)
    _sd("secret_key", secrets.token_hex(32))
    _sd("users", {})
    _sd("overrides", {})
    _sd("updated_at", int(time.time()))

    # Observability keys
    _sd("access_log", [])
    _sd("audit_log", [])
    _sd("banned_ips", [])
    _sd("health", {})
    _sd("leaderboard_snapshots", {})

    # Health defaults
    h = store.get("health") or {}
    if not isinstance(h, dict):
        store["health"] = {}
        h = store["health"]
        dirty = True
    for hk, hv in {
        "last_refresh_ok": None,
        "last_refresh_et": None,
        "last_error": None,
        "last_api_ms": None,
        "last_source": None,
    }.items():
        if hk not in h:
            h[hk] = hv
            dirty = True

    # Snapshots defaults
    s = store.get("leaderboard_snapshots") or {}
    if not isinstance(s, dict):
        store["leaderboard_snapshots"] = {}
        s = store["leaderboard_snapshots"]
        dirty = True
    for sk, sv in {"prev_top11": [], "last_top11": [], "updated_at": None}.items():
        if sk not in s:
            s[sk] = sv
            dirty = True

    # Force super-admin to exist + correct hash (your current behavior)
    users = store.get("users") or {}
    if ADMIN_USER not in users:
        users[ADMIN_USER] = {"pw_hash": ADMIN_PASS_HASH, "created_at": int(time.time())}
        store["users"] = users
        dirty = True
    if users.get(ADMIN_USER, {}).get("pw_hash") != ADMIN_PASS_HASH:
        users[ADMIN_USER]["pw_hash"] = ADMIN_PASS_HASH
        dirty = True

    return store, dirty


def store_load() -> Dict[str, Any]:
    """
    Loads admin_store.json.

    IMPORTANT:
    - Preserves existing keys.
    - Adds missing keys via setdefault-style logic.
    - Writes back ONLY if we had to fix/add anything (reduces unnecessary disk writes).
    """
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

    store, dirty = _ensure_new_keys(store)
    if dirty:
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
    """Formats a float as $1,234.56."""
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


def is_superadmin() -> bool:
    """Only 'gingrsnaps' is allowed to manage admin users."""
    return (admin_user() or "") == ADMIN_USER


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not admin_user():
            return redirect(url_for("admin"))
        return fn(*args, **kwargs)
    return wrapper


# -------------------------
# Observability: IP logging + bans + audit log
# -------------------------
def get_client_ip() -> str:
    """
    Returns best-effort client IP.
    With ProxyFix(x_for=1), request.remote_addr should be the real client.
    """
    return (request.remote_addr or "unknown").strip() or "unknown"


def _ua_trim(ua: str, n: int = 140) -> str:
    ua = str(ua or "")
    return ua if len(ua) <= n else ua[: n - 1] + "…"


def _append_rolling(lst: List[dict], entry: dict, max_len: int) -> List[dict]:
    lst.append(entry)
    if len(lst) > max_len:
        lst = lst[-max_len:]
    return lst


def audit_log_add(store: Dict[str, Any], action: str, detail: Dict[str, Any]) -> None:
    """
    Add an admin audit entry to store['audit_log'] and also print to console.
    """
    entry = {
        "ts": int(time.time()),
        "ts_et": fmt_et(int(time.time())),
        "admin_user": admin_user() or "unknown",
        "ip": get_client_ip(),
        "action": action,
        "detail": detail,
    }
    store.setdefault("audit_log", [])
    store["audit_log"] = _append_rolling(store["audit_log"], entry, AUDIT_LOG_MAX)

    app.logger.info(
        f"[AUDIT] user={entry['admin_user']} ip={entry['ip']} action={action} detail={detail}"
    )


def compute_top11_deltas(store: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Computes Top 11 deltas (current - previous) using stored snapshots.
    Output structure matches your current admin 'top' rows plus a 'delta' field.
    """
    snaps = (store.get("leaderboard_snapshots") or {})
    last_top = snaps.get("last_top11") or []
    prev_top = snaps.get("prev_top11") or []

    prev_map: Dict[str, float] = {}
    for e in prev_top:
        u = str(e.get("username", "")).strip()
        prev_map[u] = float(parse_money_to_float(e.get("wager")))

    enriched: List[Dict[str, Any]] = []
    for e in last_top:
        u = str(e.get("username", "")).strip()
        cur = float(parse_money_to_float(e.get("wager")))
        prev = prev_map.get(u, 0.0)
        out = dict(e)
        d = cur - prev
        out["delta"] = d
        # Pre-format for the template (keeps HTML simple)
        if d > 0:
            out["delta_str"] = "+" + money(abs(d))
        elif d < 0:
            out["delta_str"] = "-" + money(abs(d))
        else:
            out["delta_str"] = "+$0.00"
        enriched.append(out)
    return enriched


@app.before_request
def obs_before_request():
    """
    - Starts a timer so we can calculate latency in after_request
    - Enforces IP bans globally (except static assets, to reduce noise)
    """
    g._req_t0 = time.time()

    # Skip static assets to keep logs useful
    if request.path.startswith("/static/"):
        return

    ip = get_client_ip()

    with _store_lock:
        store = store_load()
        banned = set(store.get("banned_ips") or [])
        if ip in banned:
            app.logger.warning(f"[BAN] blocked ip={ip} path={request.path}")
            abort(403)


@app.after_request
def obs_after_request(resp):
    """
    Records access log entries (rolling) into admin_store.json.
    """
    if request.path.startswith("/static/"):
        return resp

    t0 = getattr(g, "_req_t0", None)
    ms = int((time.time() - t0) * 1000) if t0 else None

    entry = {
        "ts": int(time.time()),
        "ts_et": fmt_et(int(time.time())),
        "ip": get_client_ip(),
        "method": request.method,
        "path": request.path,
        "status": int(getattr(resp, "status_code", 0) or 0),
        "ms": ms,
        "ua": _ua_trim(request.headers.get("User-Agent", ""), 140),
    }

    # Console output (single line)
    app.logger.info(f"[ACCESS] {entry['ip']} {entry['method']} {entry['path']} -> {entry['status']} ({entry['ms']}ms)")

    with _store_lock:
        store = store_load()
        store.setdefault("access_log", [])
        store["access_log"] = _append_rolling(store["access_log"], entry, ACCESS_LOG_MAX)
        store["updated_at"] = int(time.time())
        store_save(store)

    return resp


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


def fetch_from_shuffle() -> Tuple[List[dict], Dict[str, Any]]:
    """
    Fetches wager stats from Shuffle (range preferred, lifetime fallback).

    Returns:
      (data_list, meta)

    meta fields:
      - ok: bool
      - ms: int|None  (request round-trip time)
      - error: str|None
      - source: "range" | "lifetime" | "none"
    """
    headers = {"User-Agent": "Shuffle-WagerRace/AdminOverrides"}
    start, end = sanitize_window()

    t0 = time.perf_counter()
    try:
        r = requests.get(URL_RANGE.format(API_KEY=API_KEY, start=start, end=end), timeout=20, headers=headers)
        ms = int((time.perf_counter() - t0) * 1000)

        # Range endpoint sometimes returns 400; fall back to lifetime.
        if r.status_code == 400:
            t1 = time.perf_counter()
            r2 = requests.get(URL_LIFE.format(API_KEY=API_KEY), timeout=20, headers=headers)
            ms2 = int((time.perf_counter() - t1) * 1000)

            r2.raise_for_status()
            data = r2.json()
            out = data if isinstance(data, list) else []
            return out, {"ok": True, "ms": ms2, "error": None, "source": "lifetime"}

        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            data = data["data"]
        out = data if isinstance(data, list) else []
        return out, {"ok": True, "ms": ms, "error": None, "source": "range"}

    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        return [], {"ok": False, "ms": ms, "error": str(e), "source": "none"}


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


def build_snapshots() -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Builds:
    - Public payload: podium + others (masked)
    - Admin top 11: full usernames
    - meta: health for last fetch
    """
    base, meta = fetch_from_shuffle()
    by_name = dedupe_max_by_username(base)

    # Apply overrides from store (existing behavior)
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

    return {"podium": podium, "others": others}, admin_top, meta


def refresh_cache_once() -> None:
    """
    Refreshes caches. If Shuffle is temporarily unreachable, keeps the old caches.
    ALSO updates:
      - health block in admin_store.json
      - Top 11 snapshots for delta display
    """
    public, admin_top, meta = build_snapshots()
    now = int(time.time())

    # If we got nothing and already have data, don't wipe UI.
    # BUT still record health as a failure.
    if not admin_top and ADMIN_CACHE.get("top"):
        with _store_lock:
            store = store_load()
            store.setdefault("health", {})
            store["health"]["last_refresh_ok"] = False
            store["health"]["last_refresh_et"] = fmt_et(now)
            store["health"]["last_error"] = meta.get("error") or "Shuffle returned empty dataset."
            store["health"]["last_api_ms"] = meta.get("ms")
            store["health"]["last_source"] = meta.get("source")
            store["updated_at"] = now
            store_save(store)
        app.logger.warning(f"[REFRESH] failed (kept old cache) error={meta.get('error')}")
        return

    # Update in-memory caches (existing behavior)
    with _cache_lock:
        DATA_CACHE.update(public)
    with _admin_cache_lock:
        ADMIN_CACHE["top"] = admin_top
        ADMIN_CACHE["last_refresh"] = now

    # Update store health + snapshots for deltas
    with _store_lock:
        store = store_load()

        # Health
        store.setdefault("health", {})
        store["health"]["last_refresh_ok"] = bool(meta.get("ok"))
        store["health"]["last_refresh_et"] = fmt_et(now)
        store["health"]["last_error"] = meta.get("error")
        store["health"]["last_api_ms"] = meta.get("ms")
        store["health"]["last_source"] = meta.get("source")

        # Snapshots (prev vs current top 11)
        store.setdefault("leaderboard_snapshots", {})
        snaps = store["leaderboard_snapshots"]
        snaps["prev_top11"] = snaps.get("last_top11", [])
        snaps["last_top11"] = admin_top
        snaps["updated_at"] = now

        store["updated_at"] = now
        store_save(store)

    app.logger.info(f"[REFRESH] ok={meta.get('ok')} source={meta.get('source')} ms={meta.get('ms')} top={len(admin_top)}")


def refresh_loop() -> None:
    """Background loop: refresh every REFRESH_SECONDS."""
    while True:
        try:
            refresh_cache_once()
        except Exception as e:
            app.logger.exception(f"[REFRESH_LOOP] unexpected error: {e}")
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
            app.logger.warning(f"[LOGIN_FAIL] ip={get_client_ip()} user={username}")
        else:
            session.permanent = True  # persistent cookie support
            session["admin_user"] = username
            session["csrf_token"] = secrets.token_urlsafe(32)
            app.logger.info(f"[LOGIN_OK] ip={get_client_ip()} user={username}")

            # Record successful login in audit log
            with _store_lock:
                store = store_load()
                audit_log_add(store, "login_ok", {"user": username})
                store["updated_at"] = int(time.time())
                store_save(store)

            return redirect(url_for("admin"))

    return render_template("admin_login.html", csrf_token=csrf_token(), error=error)


@app.route("/admin/logout")
def admin_logout():
    # Record logout
    if admin_user():
        with _store_lock:
            store = store_load()
            audit_log_add(store, "logout", {"user": admin_user()})
            store["updated_at"] = int(time.time())
            store_save(store)

    session.clear()
    return redirect(url_for("admin"))


def render_admin_panel():
    """
    Renders the admin panel (existing behavior) PLUS new panels:
      - Access log
      - Audit log
      - Banned IPs
      - Admin user management (super-admin only)
      - Top-11 deltas (if snapshots exist)
      - Health
    """
    with _store_lock:
        store = store_load()

    with _admin_cache_lock:
        top = list(ADMIN_CACHE.get("top") or [])
        last_refresh = int(ADMIN_CACHE.get("last_refresh") or 0)

    next_refresh = last_refresh + int(REFRESH_SECONDS) if last_refresh else 0

    # New additions: logs, bans, deltas, health
    access_log = list(reversed(store.get("access_log") or []))  # newest first
    audit_log  = list(reversed(store.get("audit_log") or []))   # newest first
    banned_ips = store.get("banned_ips") or []
    health = store.get("health") or {}

    # Admin users (for display; management actions remain super-admin only)
    admin_users = sorted(list((store.get("users") or {}).keys()))

    # Deltas require stored snapshots; compute safely
    top_with_deltas = compute_top11_deltas(store) if store.get("leaderboard_snapshots") else []

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

        # ---- New context for additions ----
        is_superadmin=is_superadmin(),
        access_log=access_log,
        audit_log=audit_log,
        banned_ips=banned_ips,
        health=health,
        top_with_deltas=top_with_deltas,
        admin_users=admin_users,
    )


def _valid_admin_username(u: str) -> bool:
    """
    Admin usernames: keep it boring and safe.
    - 3..32 chars
    - letters/numbers/underscore only
    """
    u = (u or "").strip()
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,32}", u))


@app.route("/admin/action", methods=["POST"])
@login_required
def admin_action():
    """
    POST-only admin actions.

    Existing behavior preserved:
      - set_override: saves override, NO immediate refresh.

    New additions:
      - ban_ip / unban_ip
      - clear_access_log / clear_audit_log
      - add_admin / remove_admin / set_admin_password (SUPER-ADMIN ONLY)
    """
    require_csrf()

    action = (request.form.get("action") or "").strip()

    # ---- Existing action (unchanged behavior)
    if action == "set_override":
        username = (request.form.get("username") or "").strip()
        amount_raw = (request.form.get("amount") or "").strip()

        if not username:
            return redirect(url_for("admin"))

        with _store_lock:
            store = store_load()
            store.setdefault("overrides", {})

            if amount_raw == "":
                before = store["overrides"].get(username)
                store["overrides"].pop(username, None)
                audit_log_add(store, "override_remove", {"username": username, "before": before})
            else:
                new_amt = float(parse_money_to_float(amount_raw))
                before = store["overrides"].get(username)
                store["overrides"][username] = float(new_amt)
                audit_log_add(store, "override_set", {"username": username, "before": before, "after": new_amt})

            store["updated_at"] = int(time.time())
            store_save(store)

        # No refresh here: changes apply on next tick (your current behavior)
        return redirect(url_for("admin"))

    # ---- Security controls (any logged-in admin can do these)
    if action in {"ban_ip", "unban_ip", "clear_access_log", "clear_audit_log"}:
        with _store_lock:
            store = store_load()
            store.setdefault("banned_ips", [])
            store.setdefault("access_log", [])
            store.setdefault("audit_log", [])

            if action == "ban_ip":
                ip = (request.form.get("ip") or "").strip()
                if ip:
                    if ip not in store["banned_ips"]:
                        store["banned_ips"].append(ip)
                    audit_log_add(store, "ban_ip", {"banned": ip})
                store["updated_at"] = int(time.time())
                store_save(store)
                return redirect(url_for("admin"))

            if action == "unban_ip":
                ip = (request.form.get("ip") or "").strip()
                if ip:
                    store["banned_ips"] = [x for x in store["banned_ips"] if x != ip]
                    audit_log_add(store, "unban_ip", {"unbanned": ip})
                store["updated_at"] = int(time.time())
                store_save(store)
                return redirect(url_for("admin"))

            if action == "clear_access_log":
                store["access_log"] = []
                audit_log_add(store, "clear_access_log", {})
                store["updated_at"] = int(time.time())
                store_save(store)
                return redirect(url_for("admin"))

            if action == "clear_audit_log":
                store["audit_log"] = []
                # Keep a record that it was cleared (first entry)
                audit_log_add(store, "clear_audit_log", {})
                store["updated_at"] = int(time.time())
                store_save(store)
                return redirect(url_for("admin"))

    # ---- Admin user management (SUPER-ADMIN ONLY)
    if action in {"add_admin", "remove_admin", "set_admin_password"}:
        if not is_superadmin():
            abort(403)

        with _store_lock:
            store = store_load()
            store.setdefault("users", {})

            if action == "add_admin":
                new_user = (request.form.get("new_username") or "").strip()
                new_pw = (request.form.get("new_password") or "")
                if not _valid_admin_username(new_user):
                    audit_log_add(store, "add_admin_reject", {"reason": "bad_username", "username": new_user})
                    store_save(store)
                    return redirect(url_for("admin"))

                if not new_pw:
                    audit_log_add(store, "add_admin_reject", {"reason": "empty_password", "username": new_user})
                    store_save(store)
                    return redirect(url_for("admin"))

                # Do not allow overwriting gingrsnaps here (that is forced elsewhere anyway)
                if new_user == ADMIN_USER:
                    audit_log_add(store, "add_admin_reject", {"reason": "attempted_superadmin", "username": new_user})
                    store_save(store)
                    return redirect(url_for("admin"))

                if new_user in store["users"]:
                    audit_log_add(store, "add_admin_reject", {"reason": "already_exists", "username": new_user})
                    store_save(store)
                    return redirect(url_for("admin"))

                store["users"][new_user] = {
                    "pw_hash": generate_password_hash(new_pw),
                    "created_at": int(time.time()),
                    "created_by": ADMIN_USER,
                }
                audit_log_add(store, "add_admin_ok", {"username": new_user})
                store["updated_at"] = int(time.time())
                store_save(store)
                return redirect(url_for("admin"))

            if action == "remove_admin":
                rm_user = (request.form.get("rm_username") or "").strip()
                if rm_user and rm_user != ADMIN_USER:
                    existed = rm_user in store["users"]
                    store["users"].pop(rm_user, None)
                    audit_log_add(store, "remove_admin", {"username": rm_user, "existed": existed})
                    store["updated_at"] = int(time.time())
                    store_save(store)
                return redirect(url_for("admin"))

            if action == "set_admin_password":
                target = (request.form.get("pw_username") or "").strip()
                pw = (request.form.get("pw_password") or "")
                if not target or not pw:
                    audit_log_add(store, "set_admin_password_reject", {"reason": "missing_fields"})
                    store_save(store)
                    return redirect(url_for("admin"))

                # Super-admin password is forced by ADMIN_PASS_HASH; changing it here would be overwritten.
                if target == ADMIN_USER:
                    audit_log_add(store, "set_admin_password_reject", {"reason": "superadmin_forced"})
                    store_save(store)
                    return redirect(url_for("admin"))

                if target not in store["users"]:
                    audit_log_add(store, "set_admin_password_reject", {"reason": "no_such_user", "username": target})
                    store_save(store)
                    return redirect(url_for("admin"))

                store["users"][target]["pw_hash"] = generate_password_hash(pw)
                store["users"][target]["updated_at"] = int(time.time())
                audit_log_add(store, "set_admin_password_ok", {"username": target})
                store["updated_at"] = int(time.time())
                store_save(store)
                return redirect(url_for("admin"))

    # Unknown action => no-op redirect (keeps behavior "safe")
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


@app.errorhandler(403)
def forbidden(_e):
    return (
        "Forbidden (403)\n\n"
        "If you were banned by IP, remove it from admin_store.json -> banned_ips.\n",
        403,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


@app.errorhandler(404)
def nf(_e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    print(f"Listening on http://0.0.0.0:{PORT}")
    app.run(host="0.0.0.0", port=PORT)

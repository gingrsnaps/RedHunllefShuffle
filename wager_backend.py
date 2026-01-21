# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import logging
import math
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
# Logging (console output)
# -------------------------
# NOTE:
# - DigitalOcean App Platform will capture stdout/stderr.
# - LOG_LEVEL can be set to DEBUG/INFO/WARNING/ERROR via env if you want.
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper().strip()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)

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

# -------------------------
# Admin credentials (forced)
# -------------------------
# Hard-restricted to ONE admin account by request.
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

# Ensure Flask logger matches our global logging level
try:
    app.logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
except Exception:
    pass

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
    """
    Atomic write to admin_store.json.

    Why atomic:
    - Write to a temp file first, then os.replace().
    - Prevents partial writes if the process is interrupted mid-write.
    """
    tmp = ADMIN_STORE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)
    os.replace(tmp, ADMIN_STORE_PATH)


def store_load() -> Dict[str, Any]:
    """
    Loads admin_store.json with self-healing defaults.

    IMPORTANT CHANGE (fixes freezing):
    - The previous behavior rewrote admin_store.json on *every* load.
      That causes heavy disk I/O and can “freeze” requests under load.
    - Now we only write back to disk when we actually had to repair/add fields
      (dirty flag), or when the file is missing/corrupt.
    """
    if not os.path.exists(ADMIN_STORE_PATH):
        store = store_default()
        store_save(store)
        app.logger.warning("[store] admin_store.json missing -> created fresh default store")
        return store

    try:
        with open(ADMIN_STORE_PATH, "r", encoding="utf-8") as f:
            store = json.load(f)
        if not isinstance(store, dict):
            raise ValueError("Store root not a dict")
    except Exception as e:
        store = store_default()
        store_save(store)
        app.logger.error(f"[store] admin_store.json unreadable/corrupt -> reset to default. err={e!r}")
        return store

    dirty = False

    # Preserve any extra keys you already have (settings/injections/manual_entries/etc).
    # We only ensure the required keys exist and are sane.
    if "version" not in store:
        store["version"] = 1
        dirty = True

    if "secret_key" not in store or not store.get("secret_key"):
        store["secret_key"] = secrets.token_hex(32)
        dirty = True

    if "users" not in store or not isinstance(store.get("users"), dict):
        store["users"] = {}
        dirty = True

    if "overrides" not in store or not isinstance(store.get("overrides"), dict):
        store["overrides"] = {}
        dirty = True

    if "updated_at" not in store or not isinstance(store.get("updated_at"), int):
        store["updated_at"] = int(time.time())
        dirty = True

    # Force the *single* allowed admin to exist + correct hash.
    # We do NOT delete other users from disk to avoid unexpected data loss,
    # but we DO prevent them from logging in (see admin login checks below).
    users = store["users"]
    if ADMIN_USER not in users or not isinstance(users.get(ADMIN_USER), dict):
        users[ADMIN_USER] = {"pw_hash": ADMIN_PASS_HASH, "created_at": int(time.time())}
        dirty = True
        app.logger.warning(f"[store] added missing forced admin user {ADMIN_USER!r}")

    if users[ADMIN_USER].get("pw_hash") != ADMIN_PASS_HASH:
        users[ADMIN_USER]["pw_hash"] = ADMIN_PASS_HASH
        dirty = True
        app.logger.warning(f"[store] repaired pw_hash for forced admin user {ADMIN_USER!r}")

    if dirty:
        store_save(store)
        app.logger.info("[store] repaired store and wrote changes to disk (dirty=True)")

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
    """Format a float as USD with commas + 2 decimals."""
    return f"${float(amount):,.2f}"


def parse_money_to_float(s: str) -> float:
    """
    Robust amount parser for admin override input.

    Accepts examples:
      - 25000
      - 25,000
      - $25,000
      - 25000.5
      - $25,000.50
      - "  $ 25,000  "

    Rules:
      - Strips $ and commas and whitespace and any non-digit/non-dot chars.
      - If you did NOT type a decimal point, we parse as int first (cleaner path).
      - If there are multiple dots, we keep the first and remove the rest.
      - Returns 0.0 for invalid / negative / non-finite values.
    """
    raw = str(s or "").strip()
    if not raw:
        return 0.0

    # Remove common formatting first (commas), then strip anything except digits and dot.
    tmp = raw.replace(",", "")
    tmp = re.sub(r"[^0-9.]", "", tmp)

    # Handle weird input like "12.3.4" -> keep first dot only => "12.34"
    if tmp.count(".") > 1:
        first, rest = tmp.split(".", 1)
        rest = rest.replace(".", "")
        tmp = first + "." + rest

    # Edge cases like "." or "" => invalid
    if not tmp or tmp == ".":
        return 0.0

    try:
        if "." not in tmp:
            # If no decimals were used, treat it as an integer dollar amount
            val = float(int(tmp))
        else:
            val = float(tmp)
    except Exception:
        return 0.0

    if not math.isfinite(val) or val < 0:
        return 0.0

    return val


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
    """
    IMPORTANT CHANGE:
    - Only treat the session as logged-in if the session user == ADMIN_USER.
    - This hard-locks admin access to 'gingrsnaps' only (per your requirement).
    """
    u = session.get("admin_user")
    return u if u == ADMIN_USER else None


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
    except Exception as e:
        # Keep failures from nuking the admin panel; caller handles cache preservation.
        app.logger.warning(f"[shuffle] fetch failed; preserving cache. err={e!r}")
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

    NOTE:
    - Overrides are injected into the same pool and then sorted,
      so a forced override value will naturally move up/down in rank
      as other players surpass or fall below it.
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
        except Exception as e:
            app.logger.error(f"[cache] refresh loop error (ignored): {e!r}")
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

    IMPORTANT CHANGE:
      - Only 'gingrsnaps' is allowed to login (ADMIN_USER).
      - Even if other users exist in admin_store.json, they are blocked here.
    """
    csrf_token()

    if admin_user():
        return render_admin_panel()

    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "")

        # Hard-restrict who can login.
        if username != ADMIN_USER:
            app.logger.warning(f"[auth] blocked login attempt for non-admin username={username!r} ip={request.remote_addr!r}")
            error = "Invalid username or password."
        else:
            with _store_lock:
                store = store_load()

            # Only check record for ADMIN_USER (even if someone tries other names).
            urec = (store.get("users") or {}).get(ADMIN_USER)

            if not urec or not check_password_hash(urec.get("pw_hash", ""), password):
                app.logger.warning(f"[auth] failed login for {ADMIN_USER!r} ip={request.remote_addr!r}")
                error = "Invalid username or password."
            else:
                session.permanent = True  # persistent cookie support
                session["admin_user"] = ADMIN_USER  # force session user to ADMIN_USER only
                session["csrf_token"] = secrets.token_urlsafe(32)
                app.logger.info(f"[auth] login success for {ADMIN_USER!r} ip={request.remote_addr!r}")
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

    IMPORTANT CHANGE:
    - Amount parsing is hardened so inputs like:
        "$25,000"
        "25,000"
        "25000"
      are safely accepted without causing weird float edge cases.
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
            # Blank amount removes the override.
            store["overrides"].pop(username, None)
            app.logger.info(f"[override] removed user={username!r} by_admin={admin_user()!r}")
        else:
            # Robust parsing: ignores $ and commas; treats no-decimal inputs as int.
            parsed = parse_money_to_float(amount_raw)
            store["overrides"][username] = float(parsed)
            app.logger.info(
                f"[override] set user={username!r} raw={amount_raw!r} parsed={parsed!r} by_admin={admin_user()!r}"
            )

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

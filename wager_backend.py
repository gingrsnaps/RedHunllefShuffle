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
from typing import Any, Dict, List, Optional, Tuple, Union

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
# NOTE: Only this username is allowed to log in (hard-gate in /admin POST).
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
        # overrides supports TWO formats:
        #   1) fixed float: {"ExactUsername": 12345.67}
        #   2) rank-lock dict: {"ExactUsername": {"mode":"rank","rank":5}}
        "overrides": {},
        "updated_at": int(time.time()),
    }


def store_save(store: Dict[str, Any]) -> None:
    """Atomic write to admin_store.json."""
    tmp = ADMIN_STORE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)
    os.replace(tmp, ADMIN_STORE_PATH)


def store_load() -> Dict[str, Any]:
    """
    Loads admin_store.json safely. If missing/corrupt, recreates it.

    IMPORTANT:
    - We DO NOT delete extra keys in the store file (so your existing fields remain).
    - We force the ADMIN_USER to exist and have the correct password hash.
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

    # Ensure required keys exist
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
    """Render currency with commas and 2 decimals (e.g., $12,345.67)."""
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
# Override parsing + rank-lock math
# -------------------------
_RANK_SPEC_RE = re.compile(r"^(?:rank|place)\s*[:=]\s*(\d+)\s*$", re.IGNORECASE)
_HASH_RANK_RE = re.compile(r"^#\s*(\d+)\s*$")


def parse_override_spec(raw: str) -> Union[float, Dict[str, Any]]:
    """
    Supports two admin input styles:

    1) Fixed amount:
        "12345.67"
        "$12,345.67"
        "12,345.67"

    2) Rank lock:
        "rank:5"
        "place=5"
        "#5"

    Returned value is either:
      - float
      - dict like {"mode":"rank","rank":5}
    """
    s = (raw or "").strip()
    m = _RANK_SPEC_RE.match(s) or _HASH_RANK_RE.match(s)
    if m:
        r = int(m.group(1))
        if r < 1:
            r = 1
        return {"mode": "rank", "rank": r}

    # Default: treat as money
    return float(parse_money_to_float(s))


def _sort_entries(entries: List[dict]) -> None:
    """
    Deterministic ordering:
      1) wagerAmount desc
      2) username asc (so ties are stable and predictable)
    """
    def w(e: dict) -> float:
        try:
            return float(e.get("wagerAmount", 0) or 0)
        except Exception:
            return 0.0

    entries.sort(key=lambda e: (-w(e), str(e.get("username", "")).lower()))


def _compute_amount_for_rank(target_rank_1_based: int, entries_sorted_desc: List[dict], epsilon: float = 0.01) -> float:
    """
    Compute a wager amount that places a user at the desired rank in a descending list.

    Strategy:
      - If target is #1: set just ABOVE current #1.
      - If target is in the middle: set just ABOVE the user currently at that rank,
        but also ensure it stays BELOW the user above (if gap is too small, put it mid-gap).
      - If target is beyond the end: set just BELOW the last user.

    This recalculates every refresh tick -> keeps placement stable even when others move.
    """
    # Convert to 0-based index
    idx = max(0, int(target_rank_1_based) - 1)

    def w(e: dict) -> float:
        try:
            return float(e.get("wagerAmount", 0) or 0)
        except Exception:
            return 0.0

    n = len(entries_sorted_desc)

    # No data at all -> pick 0
    if n == 0:
        return 0.0

    # Clamp "insert position" to [0..n]
    # idx == n means "after the last element" (i.e., bottom)
    if idx > n:
        idx = n

    above_amt = w(entries_sorted_desc[idx - 1]) if idx - 1 >= 0 and (idx - 1) < n else None
    below_amt = w(entries_sorted_desc[idx]) if idx < n else None

    # Desired placement:
    # - rank #1: above_amt=None, below_amt=current top
    # - middle: above_amt = amt at rank-1, below_amt = amt at rank
    # - bottom: above_amt = last amt, below_amt=None
    if above_amt is None and below_amt is None:
        candidate = 0.0
    elif above_amt is None:
        # Place above current top
        candidate = below_amt + epsilon
    elif below_amt is None:
        # Place below last
        candidate = max(0.0, above_amt - epsilon)
    else:
        # Place between above and below
        # Primary attempt: just above "below"
        candidate = below_amt + epsilon

        # If rounding/ties causes collision with "above", place mid-gap.
        if candidate >= above_amt:
            # If there's any real gap, go mid-gap; otherwise, step just below above.
            mid = (above_amt + below_amt) / 2.0
            candidate = mid if mid < above_amt and mid > below_amt else (above_amt - epsilon)

    # Ensure cents precision (matches money formatting and avoids float noise)
    candidate = round(max(0.0, float(candidate)), 2)
    return candidate


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
    except Exception as e:
        print(f"[shuffle] fetch failed: {e}")
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

    Overrides:
      - Fixed: forces exact wagerAmount
      - Rank-lock: recalculates wagerAmount each refresh to keep the requested rank
    """
    base = fetch_from_shuffle()
    by_name = dedupe_max_by_username(base)

    # Load overrides safely (do not hold lock while doing network calls; this is after fetch).
    with _store_lock:
        store = store_load()
    overrides = store.get("overrides") or {}

    # Split overrides into:
    #  - fixed_overrides: username -> float
    #  - rank_overrides: username -> rank (int)
    fixed_overrides: Dict[str, float] = {}
    rank_overrides: List[Tuple[str, int]] = []

    for uname, spec in (overrides or {}).items():
        u = str(uname).strip()
        if not u:
            continue

        # Back-compat: old store values are floats
        if isinstance(spec, (int, float)):
            fixed_overrides[u] = float(spec)
            continue

        # New: dict spec
        if isinstance(spec, dict) and str(spec.get("mode", "")).lower() == "rank":
            try:
                r = int(spec.get("rank", 1))
            except Exception:
                r = 1
            if r < 1:
                r = 1
            rank_overrides.append((u, r))
            continue

        # Anything else -> ignore safely
        print(f"[override] ignored invalid override spec for '{u}': {spec!r}")

    # Apply FIXED overrides immediately
    for u, amt in fixed_overrides.items():
        by_name[u] = {"username": u, "wagerAmount": float(amt), "campaignCode": "Red"}

    # Build base entries list (campaignCode==Red)
    entries = [e for e in by_name.values() if e.get("campaignCode") == "Red"]
    _sort_entries(entries)

    # Apply RANK-LOCK overrides (sorted best-rank first so interactions are consistent)
    if rank_overrides:
        rank_overrides.sort(key=lambda t: t[1])
        for u, desired_rank in rank_overrides:
            # Remove current instance of u (if present) before computing placement
            entries = [e for e in entries if str(e.get("username", "")).strip() != u]
            _sort_entries(entries)

            new_amt = _compute_amount_for_rank(desired_rank, entries_sorted_desc=entries, epsilon=0.01)

            # Save into the working structures
            by_name[u] = {"username": u, "wagerAmount": float(new_amt), "campaignCode": "Red"}
            entries.append(by_name[u])
            _sort_entries(entries)

            print(f"[override] rank-lock applied user='{u}' rank=#{desired_rank} computed_amount={new_amt}")

    # Now build outputs from top 11
    podium: List[dict] = []
    others: List[dict] = []
    admin_top: List[dict] = []

    for i, e in enumerate(entries[:11], start=1):
        full = str(e.get("username", "Unknown"))
        try:
            amt = float(e.get("wagerAmount", 0) or 0)
        except Exception:
            amt = 0.0
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
        print("[refresh] empty result from shuffle; keeping previous cache")
        return

    now = int(time.time())
    with _cache_lock:
        DATA_CACHE.update(public)
    with _admin_cache_lock:
        ADMIN_CACHE["top"] = admin_top
        ADMIN_CACHE["last_refresh"] = now

    print(f"[refresh] updated caches at {fmt_et(now)} (top11={len(admin_top)})")


def refresh_loop() -> None:
    """Background loop: refresh every REFRESH_SECONDS."""
    while True:
        try:
            refresh_cache_once()
        except Exception as e:
            print(f"[refresh] loop error: {e}")
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

    HARD RULE:
      - Only ADMIN_USER is allowed to log in (gingrsnaps).
        Even if other users exist in admin_store.json, they are blocked here.
    """
    csrf_token()

    if admin_user():
        return render_admin_panel()

    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "")

        # Hard gate: only gingrsnaps can log in
        if username != ADMIN_USER:
            error = "Invalid username or password."
        else:
            with _store_lock:
                store = store_load()
            urec = (store.get("users") or {}).get(username)

            if not urec or not check_password_hash(urec.get("pw_hash", ""), password):
                error = "Invalid username or password."
            else:
                session.permanent = True  # persistent cookie support
                session["admin_user"] = username
                session["csrf_token"] = secrets.token_urlsafe(32)
                print(f"[admin] login success user='{username}'")
                return redirect(url_for("admin"))

        print(f"[admin] login failed user='{username}'")

    return render_template("admin_login.html", csrf_token=csrf_token(), error=error)


@app.route("/admin/logout")
def admin_logout():
    u = admin_user()
    session.clear()
    print(f"[admin] logout user='{u}'")
    return redirect(url_for("admin"))


def override_display(spec: Any) -> str:
    """
    Convert stored override value into a human-friendly display string.
    """
    if isinstance(spec, (int, float)):
        return money(float(spec))
    if isinstance(spec, dict) and str(spec.get("mode", "")).lower() == "rank":
        try:
            r = int(spec.get("rank", 1))
        except Exception:
            r = 1
        if r < 1:
            r = 1
        return f"LOCKED TO RANK #{r}"
    return str(spec)


def render_admin_panel():
    with _store_lock:
        store = store_load()
    with _admin_cache_lock:
        top = list(ADMIN_CACHE.get("top") or [])
        last_refresh = int(ADMIN_CACHE.get("last_refresh") or 0)

    next_refresh = last_refresh + int(REFRESH_SECONDS) if last_refresh else 0

    raw_overrides = store.get("overrides") or {}
    overrides_for_ui = {k: override_display(v) for k, v in raw_overrides.items()}

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
        overrides=overrides_for_ui,
    )


@app.route("/admin/action", methods=["POST"])
@login_required
def admin_action():
    """
    Saves an override. DOES NOT refresh caches immediately.
    Public/admin snapshot changes appear on the next scheduled refresh tick.

    Override input formats:
      - Fixed: 12345.67, $12,345.67, 12,345.67
      - Rank-lock: rank:5  (or #5)  => keeps that user at rank #5 on every refresh
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
            # Remove override
            removed = store["overrides"].pop(username, None)
            print(f"[admin] override removed user='{username}' prior={removed!r}")
        else:
            # Add/update override (fixed or rank-lock)
            spec = parse_override_spec(amount_raw)
            store["overrides"][username] = spec
            print(f"[admin] override set user='{username}' spec={spec!r}")

        store["updated_at"] = int(time.time())
        store_save(store)

    # No refresh here: changes apply on next tick
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

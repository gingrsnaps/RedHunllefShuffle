# -*- coding: utf-8 -*-
"""
wager_backend.py

This is the SAME “full” version you liked (leaderboard, deltas, logs, bans, health, user-mgmt for gingrsnaps),
with ONE targeted upgrade:

✅ Overrides can now be:
  - Fixed amounts (existing): "12345.67", "$12,345.67"
  - Rank-lock (NEW): "rank:5" or "#5"
    -> The system recalculates the user’s wagerAmount every refresh so they stay at that rank as others move.

✅ Force Refresh Now applies the placement immediately.
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
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for, g
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# -------------------------
# Settings loader (settings.json is optional)
# -------------------------

SETTINGS_PATH = os.getenv("SETTINGS_PATH", "settings.json")


def load_settings() -> Dict[str, Any]:
    """Loads settings.json if present. Environment variables always win."""
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


SETTINGS = load_settings()

# -------------------------
# Timezone (Eastern)
# -------------------------
try:
    from zoneinfo import ZoneInfo  # py3.9+
    ET = ZoneInfo("America/New_York")
except Exception:
    ET = None


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

def _env_int(name: str, default: int) -> int:
    val = os.getenv(name, "")
    if val.strip() == "":
        return int(default)
    try:
        return int(val)
    except Exception:
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name, "").strip().lower()
    if v == "":
        return bool(default)
    return v in ("1", "true", "yes", "on")


PORT = _env_int("PORT", int(SETTINGS.get("port", 8080)))
REFRESH_SECONDS = _env_int("REFRESH_SECONDS", int(SETTINGS.get("refresh_seconds", 60)))

START_TIME = _env_int("START_TIME", int(SETTINGS.get("start_time", 0)))
END_TIME   = _env_int("END_TIME",   int(SETTINGS.get("end_time",   0)))

API_KEY = os.getenv("API_KEY", "").strip() or str(SETTINGS.get("shuffle_api_key", "")).strip()

KICK_CHANNEL_SLUG  = os.getenv("KICK_CHANNEL_SLUG", "").strip() or str(SETTINGS.get("kick_channel_slug", "redhunllef")).strip()
KICK_CLIENT_ID     = os.getenv("KICK_CLIENT_ID", "").strip() or str(SETTINGS.get("kick_client_id", "")).strip()
KICK_CLIENT_SECRET = os.getenv("KICK_CLIENT_SECRET", "").strip() or str(SETTINGS.get("kick_client_secret", "")).strip()

SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", bool(SETTINGS.get("session_cookie_secure", False)))

ADMIN_STORE_PATH = os.getenv("ADMIN_STORE_PATH", "admin_store.json")

# How many log rows to keep (rolling)
ACCESS_LOG_MAX = _env_int("ACCESS_LOG_MAX", 300)
AUDIT_LOG_MAX  = _env_int("AUDIT_LOG_MAX", 250)

# Full leaderboard rows to keep in memory for the admin panel
FULL_LEADERBOARD_MAX = _env_int("FULL_LEADERBOARD_MAX", 300)

# -------------------------
# Super-admin
# -------------------------
# User management actions (add/remove/reset admin users) are restricted to this user only.
SUPERADMIN = "gingrsnaps"

# Bootstrap password source (never printed):
# - ENV ADMIN_BOOTSTRAP_PASS wins
# - else settings.json admin_bootstrap_pass
# If missing/blank, we generate a random password ON EACH STARTUP (not recommended).
BOOTSTRAP_PASS = (os.getenv("ADMIN_BOOTSTRAP_PASS", "").strip()
                  or str(SETTINGS.get("admin_bootstrap_pass", "")).strip()
                  or secrets.token_urlsafe(18))

# Optional: allow resetting the admin store on startup (dangerous; defaults to False)
RESET_ADMIN_STORE_ON_START = _env_bool("RESET_ADMIN_STORE_ON_START", bool(SETTINGS.get("reset_admin_store_on_start", False)))

# -------------------------
# Flask app
# -------------------------
app = Flask(__name__)
app.url_map.strict_slashes = False

# ProxyFix:
# - x_for=1 makes request.remote_addr reflect the true client IP when behind a proxy.
# - If you're not behind a proxy, it behaves normally.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

CORS(app)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

# Console logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

_store_lock = threading.Lock()

# In-memory store (persisted to admin_store.json when changed)
STORE: Dict[str, Any] = {}


# -------------------------
# Store helpers
# -------------------------
def store_default() -> Dict[str, Any]:
    """
    Default store structure.

    overrides supports:
      - fixed float: {"ExactUsername": 12345.67}
      - rank-lock dict: {"ExactUsername": {"mode":"rank","rank":5}}
    """
    now = int(time.time())
    return {
        "version": 1,
        "secret_key": secrets.token_hex(32),
        "users": {
            SUPERADMIN: {
                "pw_hash": generate_password_hash(BOOTSTRAP_PASS),
                "created_at": now,
                "created_by": "bootstrap",
            }
        },
        "overrides": {},

        # Observability + security
        "access_log": [],
        "audit_log": [],
        "banned_ips": [],
        "health": {
            "last_refresh_ok": None,
            "last_refresh_et": None,
            "last_error": None,
            "last_api_ms": None,
            "last_source": None,
        },
        "leaderboard_snapshots": {
            "prev_top11": [],
            "last_top11": [],
            "updated_at": None,
        },
        "updated_at": now,
    }


def store_save(store: Dict[str, Any]) -> None:
    """Atomic write to admin_store.json."""
    tmp = ADMIN_STORE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)
    os.replace(tmp, ADMIN_STORE_PATH)


def store_load_from_disk() -> Dict[str, Any]:
    """Loads store from disk or returns defaults."""
    if RESET_ADMIN_STORE_ON_START:
        s = store_default()
        store_save(s)
        return s

    if not os.path.exists(ADMIN_STORE_PATH):
        s = store_default()
        store_save(s)
        return s

    try:
        with open(ADMIN_STORE_PATH, "r", encoding="utf-8") as f:
            s = json.load(f)
        if not isinstance(s, dict):
            raise ValueError("admin_store root not a dict")
        return s
    except Exception:
        s = store_default()
        store_save(s)
        return s


def store_ensure_keys(s: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """
    Ensures required keys exist, without deleting unknown keys.
    Returns (store, dirty_flag).
    """
    dirty = False

    def sd(k: str, v: Any):
        nonlocal dirty
        if k not in s:
            s[k] = v
            dirty = True

    sd("version", 1)
    sd("secret_key", secrets.token_hex(32))
    sd("users", {})
    sd("overrides", {})
    sd("access_log", [])
    sd("audit_log", [])
    sd("banned_ips", [])
    sd("health", {})
    sd("leaderboard_snapshots", {})
    sd("updated_at", int(time.time()))

    # health defaults
    h = s.get("health")
    if not isinstance(h, dict):
        s["health"] = {}
        h = s["health"]
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

    # snapshots defaults
    snaps = s.get("leaderboard_snapshots")
    if not isinstance(snaps, dict):
        s["leaderboard_snapshots"] = {}
        snaps = s["leaderboard_snapshots"]
        dirty = True
    for sk, sv in {"prev_top11": [], "last_top11": [], "updated_at": None}.items():
        if sk not in snaps:
            snaps[sk] = sv
            dirty = True

    # Force SUPERADMIN to exist (password comes from BOOTSTRAP_PASS).
    users = s.get("users") or {}
    if not isinstance(users, dict):
        s["users"] = {}
        users = s["users"]
        dirty = True

    if SUPERADMIN not in users:
        users[SUPERADMIN] = {
            "pw_hash": generate_password_hash(BOOTSTRAP_PASS),
            "created_at": int(time.time()),
            "created_by": "bootstrap",
        }
        dirty = True
    else:
        # Keep superadmin password tied to BOOTSTRAP_PASS (prevents lockout)
        users[SUPERADMIN]["pw_hash"] = generate_password_hash(BOOTSTRAP_PASS)
        dirty = True

    s["users"] = users
    return s, dirty


def store_init() -> None:
    """Loads store into memory, ensures keys, persists if needed, sets app.secret_key."""
    global STORE
    s = store_load_from_disk()
    s, dirty = store_ensure_keys(s)
    STORE = s
    if dirty:
        store_save(STORE)


store_init()

# Secret key: env overrides settings.json overrides store. If settings has placeholder, ignore.
env_secret = os.getenv("SECRET_KEY", "").strip()
settings_secret = str(SETTINGS.get("secret_key", "")).strip()
if settings_secret.upper().startswith("REPLACE_") or len(settings_secret) < 16:
    settings_secret = ""

app.secret_key = env_secret or settings_secret or str(STORE.get("secret_key") or secrets.token_hex(32))


# -------------------------
# Helpers: money, username masking, CSRF, auth
# -------------------------
def censor_username(u: str) -> str:
    """Public anonymity rule: first 2 chars + ******."""
    u = (u or "").strip()
    return (u[:2] if u else "") + ("*" * 6)


def money(amount: float) -> str:
    """Formats a float as $1,234.56."""
    return f"${float(amount):,.2f}"


def parse_money_to_float(s: str) -> float:
    """Parse money strings to float; accepts commas and $."""
    cleaned = re.sub(r"[^0-9.]", "", str(s or "").strip())
    try:
        return float(cleaned) if cleaned else 0.0
    except Exception:
        return 0.0


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
    return (admin_user() or "") == SUPERADMIN


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not admin_user():
            return redirect(url_for("admin"))
        return fn(*args, **kwargs)
    return wrapper


def client_ip() -> str:
    """Trust request.remote_addr (ProxyFix x_for=1)."""
    return (request.remote_addr or "unknown").strip() or "unknown"


def _ua_trim(ua: str, n: int = 160) -> str:
    ua = str(ua or "")
    return ua if len(ua) <= n else ua[: n - 1] + "…"


# -------------------------
# NEW: Override parsing + rank-lock computation
# -------------------------

# Accept: "rank:5", "place=5", "#5"
_RANK_SPEC_RE = re.compile(r"^(?:rank|place)\s*[:=]\s*(\d+)\s*$", re.IGNORECASE)
_HASH_RANK_RE = re.compile(r"^#\s*(\d+)\s*$")


def parse_override_input(raw: str) -> Union[float, Dict[str, Any]]:
    """
    Parse the admin override input into a store value.

    Returns either:
      - float (fixed override)
      - dict {"mode":"rank","rank":N} (rank-lock)
    """
    s = (raw or "").strip()
    m = _RANK_SPEC_RE.match(s) or _HASH_RANK_RE.match(s)
    if m:
        r = int(m.group(1))
        if r < 1:
            r = 1
        return {"mode": "rank", "rank": r}

    # Default: fixed money
    return float(parse_money_to_float(s))


def override_display(spec: Any) -> str:
    """Nice display string for the admin panel overrides table."""
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


def _wager_amount(e: dict) -> float:
    try:
        return float(e.get("wagerAmount", 0) or 0)
    except Exception:
        return 0.0


def _sort_entries(entries: List[dict]) -> None:
    """
    Deterministic sorting:
      1) wagerAmount desc
      2) username asc
    This prevents “random flip” when amounts tie.
    """
    entries.sort(key=lambda e: (-_wager_amount(e), str(e.get("username", "")).lower()))


def _compute_amount_for_rank(target_rank_1_based: int, entries_sorted_desc: List[dict], epsilon: float = 0.0001) -> float:
    """
    Compute a wager amount that inserts at a desired rank in a descending list.
    Uses fractional cents (epsilon=0.0001) so it can always break ties internally.

    Display still rounds to 2 decimals, but ranking uses the internal float value.
    """
    idx = max(0, int(target_rank_1_based) - 1)
    n = len(entries_sorted_desc)

    if n == 0:
        return 0.0

    # idx==n means bottom (after last)
    if idx > n:
        idx = n

    above_amt = _wager_amount(entries_sorted_desc[idx - 1]) if 0 <= (idx - 1) < n else None
    below_amt = _wager_amount(entries_sorted_desc[idx]) if idx < n else None

    if above_amt is None and below_amt is None:
        return 0.0

    if above_amt is None:
        # Rank #1: place just above current top
        return below_amt + epsilon

    if below_amt is None:
        # Bottom: place just below last
        return max(0.0, above_amt - epsilon)

    # Middle: try just above below
    candidate = below_amt + epsilon

    # If that collides above (gap too small), take mid-gap or step below above
    if candidate >= above_amt:
        mid = (above_amt + below_amt) / 2.0
        if below_amt < mid < above_amt:
            candidate = mid
        else:
            candidate = above_amt - epsilon

    return max(0.0, float(candidate))


# -------------------------
# Observability: access logs, audit logs, bans
# -------------------------

def _append_rolling(lst: List[dict], entry: dict, max_len: int) -> List[dict]:
    lst.append(entry)
    if len(lst) > max_len:
        lst = lst[-max_len:]
    return lst


def audit(action: str, detail: Dict[str, Any]) -> None:
    """
    Add an admin audit log entry and print a single console line.
    """
    with _store_lock:
        entry = {
            "ts": int(time.time()),
            "ts_et": fmt_et(int(time.time())),
            "admin_user": admin_user() or "unknown",
            "ip": client_ip(),
            "action": action,
            "detail": detail,
        }
        STORE["audit_log"] = _append_rolling(STORE.get("audit_log") or [], entry, AUDIT_LOG_MAX)
        STORE["updated_at"] = int(time.time())
        store_save(STORE)

    app.logger.info(f"[AUDIT] user={entry['admin_user']} ip={entry['ip']} action={action} detail={detail}")


@app.before_request
def obs_before_request():
    """
    - Start request timer (ms)
    - Enforce banned IPs globally (except /static for less noise)
    """
    g._t0 = time.time()

    if request.path.startswith("/static/"):
        return

    ip = client_ip()
    with _store_lock:
        banned = set(STORE.get("banned_ips") or [])
    if ip in banned:
        app.logger.warning(f"[BAN] blocked ip={ip} path={request.path}")
        abort(403)


@app.after_request
def obs_after_request(resp):
    """Record rolling access log entries."""
    if request.path.startswith("/static/"):
        return resp

    t0 = getattr(g, "_t0", None)
    ms = int((time.time() - t0) * 1000) if t0 else None

    entry = {
        "ts": int(time.time()),
        "ts_et": fmt_et(int(time.time())),
        "ip": client_ip(),
        "method": request.method,
        "path": request.path,
        "status": int(getattr(resp, "status_code", 0) or 0),
        "ms": ms,
        "ua": _ua_trim(request.headers.get("User-Agent", ""), 160),
    }

    app.logger.info(f"[ACCESS] {entry['ip']} {entry['method']} {entry['path']} -> {entry['status']} ({entry['ms']}ms)")

    with _store_lock:
        STORE["access_log"] = _append_rolling(STORE.get("access_log") or [], entry, ACCESS_LOG_MAX)
        STORE["updated_at"] = int(time.time())
        store_save(STORE)

    return resp


# -------------------------
# Shuffle fetch + cache
# -------------------------
URL_RANGE = "https://affiliate.shuffle.com/stats/{API_KEY}?startTime={start}&endTime={end}"
URL_LIFE  = "https://affiliate.shuffle.com/stats/{API_KEY}"


def sanitize_window() -> Tuple[int, int]:
    """Ensures end <= now and start < end."""
    now = int(time.time())
    start = int(START_TIME or 0)
    end = int(END_TIME or 0)

    # If missing or invalid window, fall back to last 14 days.
    if start <= 0 or end <= 0 or end <= start:
        end = now
        start = max(0, now - 14 * 24 * 3600)

    # Ensure we never request future end times.
    if end > now:
        end = now

    return start, end


def fetch_from_shuffle() -> Tuple[List[dict], Dict[str, Any]]:
    """
    Fetches wager stats from Shuffle (range preferred, lifetime fallback).

    Returns: (data_list, meta)
      meta fields:
        - ok: bool
        - ms: int|None
        - error: str|None
        - source: "range"|"lifetime"|"none"
    """
    headers = {"User-Agent": "Shuffle-WagerRace/AdminPanel"}
    start, end = sanitize_window()

    t0 = time.perf_counter()
    try:
        r = requests.get(URL_RANGE.format(API_KEY=API_KEY, start=start, end=end), timeout=20, headers=headers)
        ms = int((time.perf_counter() - t0) * 1000)

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
    """
    De-dupe by exact username; keep max wagerAmount.
    This avoids duplicates from the API without fabricating any values.
    """
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
_force_refresh_lock = threading.Lock()

# Public cache returned by /data (masked)
DATA_CACHE: Dict[str, Any] = {"podium": [], "others": []}

# Admin snapshot (full usernames)
ADMIN_CACHE: Dict[str, Any] = {
    "top11": [],
    "full": [],
    "last_refresh": 0,
}


def compute_top11_deltas() -> List[Dict[str, Any]]:
    """Compute Top-11 deltas from snapshots stored in STORE."""
    with _store_lock:
        snaps = (STORE.get("leaderboard_snapshots") or {})
        last_top = snaps.get("last_top11") or []
        prev_top = snaps.get("prev_top11") or []

    prev_map: Dict[str, float] = {}
    for e in prev_top:
        u = str(e.get("username", "")).strip()
        prev_map[u] = parse_money_to_float(e.get("wager"))

    enriched: List[Dict[str, Any]] = []
    for e in last_top:
        u = str(e.get("username", "")).strip()
        cur = parse_money_to_float(e.get("wager"))
        prev = prev_map.get(u, 0.0)
        d = cur - prev

        out = dict(e)
        out["delta"] = d
        if d > 0:
            out["delta_str"] = "+" + money(abs(d))
        elif d < 0:
            out["delta_str"] = "-" + money(abs(d))
        else:
            out["delta_str"] = "+$0.00"
        enriched.append(out)

    return enriched


def build_snapshots() -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Builds:
    - Public payload: podium + others (masked usernames)
    - Admin top 11: full usernames, sorted by wager desc
    - Admin full leaderboard (up to FULL_LEADERBOARD_MAX), sorted by wager desc
    - meta: health information from Shuffle fetch

    Overrides:
      - Fixed: forces exact wagerAmount (existing behavior)
      - Rank-lock: recalculates wagerAmount every refresh to keep desired rank (NEW)
    """
    base, meta = fetch_from_shuffle()
    by_name = dedupe_max_by_username(base)

    # Apply overrides from store
    with _store_lock:
        overrides = dict(STORE.get("overrides") or {})

    # Split overrides into fixed and rank-lock
    fixed_overrides: Dict[str, float] = {}
    rank_overrides: List[Tuple[str, int]] = []

    for uname, spec in (overrides or {}).items():
        u = str(uname).strip()
        if not u:
            continue

        # Back-compat fixed float
        if isinstance(spec, (int, float)):
            fixed_overrides[u] = float(spec)
            continue

        # Rank-lock spec
        if isinstance(spec, dict) and str(spec.get("mode", "")).lower() == "rank":
            try:
                r = int(spec.get("rank", 1))
            except Exception:
                r = 1
            if r < 1:
                r = 1
            rank_overrides.append((u, r))
            continue

        # Unknown spec (ignore safely)
        app.logger.warning(f"[override] ignored invalid spec for '{u}': {spec!r}")

    # Apply FIXED overrides
    for u, amt in fixed_overrides.items():
        by_name[u] = {"username": u, "wagerAmount": float(amt), "campaignCode": "Red"}

    # Build base entries list (campaignCode==Red)
    entries = [e for e in by_name.values() if e.get("campaignCode") == "Red"]
    _sort_entries(entries)

    # Apply RANK-LOCK overrides (process best rank first so it stays deterministic)
    if rank_overrides:
        rank_overrides.sort(key=lambda t: (t[1], t[0].lower()))
        for u, desired_rank in rank_overrides:
            # Remove current instance of u before computing placement
            entries = [e for e in entries if str(e.get("username", "")).strip() != u]
            _sort_entries(entries)

            new_amt = _compute_amount_for_rank(desired_rank, entries_sorted_desc=entries, epsilon=0.0001)

            # Insert the overridden entry with the computed amount
            by_name[u] = {"username": u, "wagerAmount": float(new_amt), "campaignCode": "Red"}
            entries.append(by_name[u])
            _sort_entries(entries)

            app.logger.info(f"[override] rank-lock user='{u}' target_rank=#{desired_rank} computed_amount={new_amt}")

    # Admin full list (keep track of everyone in rank order)
    admin_full: List[Dict[str, Any]] = []
    for i, e in enumerate(entries[:FULL_LEADERBOARD_MAX], start=1):
        full = str(e.get("username", "Unknown"))
        admin_full.append({"rank": i, "username": full, "wager": money(_wager_amount(e))})

    # Admin top 11
    admin_top11 = admin_full[:11]

    # Public podium + others (still masked)
    podium: List[dict] = []
    others: List[dict] = []
    for row in admin_top11:
        i = int(row["rank"])
        full = row["username"]
        wager_str = row["wager"]
        pub = {"username": censor_username(full), "wager": wager_str}
        if i <= 3:
            podium.append(pub)
        else:
            others.append({"rank": i, **pub})

    public_payload = {"podium": podium, "others": others}
    return public_payload, admin_top11, admin_full, meta


def refresh_cache_once(reason: str = "tick") -> None:
    """
    Refreshes caches and updates STORE health + snapshots.
    If Shuffle is temporarily unreachable, keeps the old caches (but records health as FAIL).
    """
    public, admin_top11, admin_full, meta = build_snapshots()
    now = int(time.time())

    # If we got nothing but already have data, don't wipe UI; still update health.
    with _admin_cache_lock:
        had_data = bool(ADMIN_CACHE.get("top11"))

    if not admin_top11 and had_data:
        with _store_lock:
            STORE["health"]["last_refresh_ok"] = False
            STORE["health"]["last_refresh_et"] = fmt_et(now)
            STORE["health"]["last_error"] = meta.get("error") or "Shuffle returned empty dataset"
            STORE["health"]["last_api_ms"] = meta.get("ms")
            STORE["health"]["last_source"] = meta.get("source")
            STORE["updated_at"] = now
            store_save(STORE)

        app.logger.warning(f"[REFRESH] FAIL (kept old cache) source={meta.get('source')} ms={meta.get('ms')} err={meta.get('error')}")
        return

    # Update in-memory caches
    with _cache_lock:
        DATA_CACHE.update(public)

    with _admin_cache_lock:
        ADMIN_CACHE["top11"] = admin_top11
        ADMIN_CACHE["full"] = admin_full
        ADMIN_CACHE["last_refresh"] = now

    # Update store health + snapshots for deltas
    with _store_lock:
        STORE["health"]["last_refresh_ok"] = bool(meta.get("ok"))
        STORE["health"]["last_refresh_et"] = fmt_et(now)
        STORE["health"]["last_error"] = meta.get("error")
        STORE["health"]["last_api_ms"] = meta.get("ms")
        STORE["health"]["last_source"] = meta.get("source")

        snaps = STORE.get("leaderboard_snapshots") or {}
        snaps["prev_top11"] = snaps.get("last_top11", [])
        snaps["last_top11"] = admin_top11
        snaps["updated_at"] = now
        STORE["leaderboard_snapshots"] = snaps

        STORE["updated_at"] = now
        store_save(STORE)

    app.logger.info(f"[REFRESH] ok={meta.get('ok')} reason={reason} source={meta.get('source')} ms={meta.get('ms')} top11={len(admin_top11)} full={len(admin_full)}")


def refresh_loop() -> None:
    """Background loop: refresh every REFRESH_SECONDS."""
    while True:
        try:
            refresh_cache_once(reason="tick")
        except Exception as e:
            app.logger.exception(f"[REFRESH_LOOP] unexpected: {e}")
        time.sleep(max(5, int(REFRESH_SECONDS)))


# Initial refresh + background thread
refresh_cache_once(reason="startup")
threading.Thread(target=refresh_loop, daemon=True).start()


# -------------------------
# Kick endpoint (kept minimal)
# -------------------------
def get_stream_status() -> Dict[str, Any]:
    """
    Returns Kick status; if creds missing or Kick breaks, return safe defaults.
    """
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
      - No CSRF check (cookie might not exist yet)
    """
    csrf_token()

    if admin_user():
        return render_admin_panel()

    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "")

        with _store_lock:
            urec = (STORE.get("users") or {}).get(username)

        if not urec or not check_password_hash(urec.get("pw_hash", ""), password):
            error = "Invalid username or password."
            app.logger.warning(f"[LOGIN_FAIL] ip={client_ip()} user={username}")
        else:
            session.permanent = True
            session["admin_user"] = username
            session["csrf_token"] = secrets.token_urlsafe(32)
            app.logger.info(f"[LOGIN_OK] ip={client_ip()} user={username}")
            audit("login_ok", {"user": username})
            return redirect(url_for("admin"))

    return render_template("admin_login.html", csrf_token=csrf_token(), error=error)


@app.route("/admin/logout")
def admin_logout():
    if admin_user():
        audit("logout", {"user": admin_user()})
    session.clear()
    return redirect(url_for("admin"))


def render_admin_panel():
    """Renders admin panel with all the panels/controls."""
    csrf_token()

    with _store_lock:
        overrides_raw = dict(STORE.get("overrides") or {})
        overrides = {k: override_display(v) for k, v in overrides_raw.items()}

        access_log = list(reversed(STORE.get("access_log") or []))
        audit_log = list(reversed(STORE.get("audit_log") or []))
        banned_ips = list(STORE.get("banned_ips") or [])
        health = dict(STORE.get("health") or {})
        admin_users = sorted(list((STORE.get("users") or {}).keys()))

    with _admin_cache_lock:
        top11 = list(ADMIN_CACHE.get("top11") or [])
        full = list(ADMIN_CACHE.get("full") or [])
        last_refresh = int(ADMIN_CACHE.get("last_refresh") or 0)

    next_refresh = last_refresh + int(REFRESH_SECONDS) if last_refresh else 0

    top11_with_deltas = compute_top11_deltas()

    return render_template(
        "admin_panel.html",
        csrf_token=csrf_token(),
        admin_user=admin_user(),
        is_superadmin=is_superadmin(),
        refresh_seconds=REFRESH_SECONDS,
        start_et=fmt_et(int(START_TIME)),
        end_et=fmt_et(int(END_TIME)),
        last_refresh_et=fmt_et(last_refresh),
        next_refresh_et=fmt_et(next_refresh),

        overrides=overrides,
        top11=top11,
        top11_with_deltas=top11_with_deltas,
        full_leaderboard=full,

        access_log=access_log,
        audit_log=audit_log,
        banned_ips=banned_ips,
        health=health,
        admin_users=admin_users,
    )


def _valid_admin_username(u: str) -> bool:
    """Admin usernames: 3..32 chars, letters/numbers/_ only."""
    u = (u or "").strip()
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,32}", u))


@app.route("/admin/action", methods=["POST"])
@login_required
def admin_action():
    """
    Admin action endpoint (CSRF protected). Supported actions:

    Existing:
      - set_override (still does NOT auto-refresh)

    New:
      - force_refresh (admin-only) pulls Shuffle immediately and updates /data cache
      - ban_ip / unban_ip
      - clear_access_log / clear_audit_log
      - add_admin / remove_admin / set_admin_password (SUPERADMIN only)
    """
    require_csrf()
    action = (request.form.get("action") or "").strip()

    # -------------------------
    # Overrides (UPGRADED: fixed OR rank-lock)
    # -------------------------
    if action == "set_override":
        username = (request.form.get("username") or "").strip()
        amount_raw = (request.form.get("amount") or "").strip()
        if not username:
            return redirect(url_for("admin"))

        with _store_lock:
            STORE.setdefault("overrides", {})

            if amount_raw == "":
                before = STORE["overrides"].get(username)
                STORE["overrides"].pop(username, None)
                STORE["updated_at"] = int(time.time())
                store_save(STORE)
                audit("override_remove", {"username": username, "before": before})
            else:
                # NEW: parse "rank:5" / "#5" into rank-lock dict, else fixed float
                spec = parse_override_input(amount_raw)
                before = STORE["overrides"].get(username)
                STORE["overrides"][username] = spec
                STORE["updated_at"] = int(time.time())
                store_save(STORE)
                audit("override_set", {"username": username, "before": before, "after": spec})

        # Preserve your original behavior: no immediate refresh.
        # Use "Force Refresh Now" if you want it instantly.
        return redirect(url_for("admin"))

    # -------------------------
    # Force refresh (admin-only)
    # -------------------------
    if action == "force_refresh":
        who = admin_user() or "unknown"
        ip = client_ip()
        app.logger.info(f"[ADMIN] force_refresh requested by {who} from {ip}")
        audit("force_refresh", {})

        started = time.time()
        with _force_refresh_lock:
            try:
                refresh_cache_once(reason="force_refresh")
                app.logger.info(f"[ADMIN] force_refresh done in {time.time() - started:.2f}s")
            except Exception as e:
                app.logger.exception(f"[ADMIN] force_refresh failed: {e}")
        return redirect(url_for("admin"))

    # -------------------------
    # Security controls (any logged-in admin)
    # -------------------------
    if action == "ban_ip":
        ip = (request.form.get("ip") or "").strip()
        if ip:
            with _store_lock:
                STORE.setdefault("banned_ips", [])
                if ip not in STORE["banned_ips"]:
                    STORE["banned_ips"].append(ip)
                STORE["updated_at"] = int(time.time())
                store_save(STORE)
            audit("ban_ip", {"ip": ip})
        return redirect(url_for("admin"))

    if action == "unban_ip":
        ip = (request.form.get("ip") or "").strip()
        if ip:
            with _store_lock:
                STORE.setdefault("banned_ips", [])
                STORE["banned_ips"] = [x for x in STORE["banned_ips"] if x != ip]
                STORE["updated_at"] = int(time.time())
                store_save(STORE)
            audit("unban_ip", {"ip": ip})
        return redirect(url_for("admin"))

    if action == "clear_access_log":
        with _store_lock:
            STORE["access_log"] = []
            STORE["updated_at"] = int(time.time())
            store_save(STORE)
        audit("clear_access_log", {})
        return redirect(url_for("admin"))

    if action == "clear_audit_log":
        with _store_lock:
            STORE["audit_log"] = []
            STORE["updated_at"] = int(time.time())
            store_save(STORE)
        # Keep one audit marker right after clearing
        audit("clear_audit_log", {})
        return redirect(url_for("admin"))

    # -------------------------
    # Admin user management (SUPERADMIN only)
    # -------------------------
    if action in {"add_admin", "remove_admin", "set_admin_password"}:
        if not is_superadmin():
            abort(403)

        if action == "add_admin":
            new_user = (request.form.get("new_username") or "").strip()
            new_pw = (request.form.get("new_password") or "")
            if not _valid_admin_username(new_user):
                audit("add_admin_reject", {"reason": "bad_username", "username": new_user})
                return redirect(url_for("admin"))
            if not new_pw:
                audit("add_admin_reject", {"reason": "empty_password", "username": new_user})
                return redirect(url_for("admin"))
            if new_user == SUPERADMIN:
                audit("add_admin_reject", {"reason": "superadmin_reserved", "username": new_user})
                return redirect(url_for("admin"))

            with _store_lock:
                STORE.setdefault("users", {})
                if new_user in STORE["users"]:
                    audit("add_admin_reject", {"reason": "already_exists", "username": new_user})
                    return redirect(url_for("admin"))
                STORE["users"][new_user] = {
                    "pw_hash": generate_password_hash(new_pw),
                    "created_at": int(time.time()),
                    "created_by": SUPERADMIN,
                }
                STORE["updated_at"] = int(time.time())
                store_save(STORE)

            audit("add_admin_ok", {"username": new_user})
            return redirect(url_for("admin"))

        if action == "remove_admin":
            rm_user = (request.form.get("rm_username") or "").strip()
            if not rm_user or rm_user == SUPERADMIN:
                audit("remove_admin_reject", {"reason": "invalid_target", "username": rm_user})
                return redirect(url_for("admin"))

            with _store_lock:
                existed = rm_user in (STORE.get("users") or {})
                (STORE.get("users") or {}).pop(rm_user, None)
                STORE["updated_at"] = int(time.time())
                store_save(STORE)

            audit("remove_admin", {"username": rm_user, "existed": existed})
            return redirect(url_for("admin"))

        if action == "set_admin_password":
            target = (request.form.get("pw_username") or "").strip()
            pw = (request.form.get("pw_password") or "")
            if not target or not pw:
                audit("set_admin_password_reject", {"reason": "missing_fields"})
                return redirect(url_for("admin"))
            if target == SUPERADMIN:
                audit("set_admin_password_reject", {"reason": "superadmin_forced"})
                return redirect(url_for("admin"))

            with _store_lock:
                users = STORE.get("users") or {}
                if target not in users:
                    audit("set_admin_password_reject", {"reason": "no_such_user", "username": target})
                    return redirect(url_for("admin"))
                users[target]["pw_hash"] = generate_password_hash(pw)
                users[target]["updated_at"] = int(time.time())
                STORE["users"] = users
                STORE["updated_at"] = int(time.time())
                store_save(STORE)

            audit("set_admin_password_ok", {"username": target})
            return redirect(url_for("admin"))

    # Unknown action => safe no-op
    return redirect(url_for("admin"))


# -------------------------
# Errors
# -------------------------
@app.errorhandler(400)
def bad_request(_e):
    return (
        "Bad Request (400)\n\n"
        "This is almost always cookies/sessions or CSRF mismatch.\n"
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
        "If your IP was banned, remove it from admin_store.json -> banned_ips.\n",
        403,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


@app.errorhandler(404)
def nf(_e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.logger.info(f"Listening on http://0.0.0.0:{PORT}")
    app.run(host="0.0.0.0", port=PORT)

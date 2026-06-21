"""
Master-password hashing and verification using PBKDF2-HMAC-SHA256.
The master password gates app access; per-folder PINs gate encryption.
"""

import hashlib
import os
import time
from pathlib import Path

KDF_ITERS       = 600_000
MAX_LOGIN_TRIES = 5
LOCKOUT_SECS    = 600        # 10 minutes

_LOCKOUT_FILE = Path(os.environ.get("APPDATA", Path.home())) / "FolderLock" / ".login_lockout"


# ── Hashing ───────────────────────────────────────────────────────────────────

def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Return (hex_hash, hex_salt). Generates random salt if not provided."""
    if salt is None:
        salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, KDF_ITERS)
    return dk.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    try:
        salt = bytes.fromhex(stored_salt)
        computed, _ = hash_password(password, salt)
        return computed == stored_hash
    except Exception:
        return False


# ── Login lockout ─────────────────────────────────────────────────────────────

def _read_lockout() -> dict:
    try:
        import json
        if _LOCKOUT_FILE.exists():
            return json.loads(_LOCKOUT_FILE.read_text())
    except Exception:
        pass
    return {"attempts": 0, "locked_until": 0}


def _write_lockout(data: dict) -> None:
    try:
        import json
        _LOCKOUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        _LOCKOUT_FILE.write_text(json.dumps(data))
    except Exception:
        pass


def get_login_status() -> tuple[bool, int, int]:
    """Returns (is_locked, seconds_remaining, attempts_used)."""
    d = _read_lockout()
    attempts     = d.get("attempts", 0)
    locked_until = d.get("locked_until", 0)
    now = time.time()
    if locked_until and now < locked_until:
        return True, int(locked_until - now), attempts
    return False, 0, attempts


def record_login_failure() -> tuple[bool, int]:
    """Record a failed login attempt. Returns (now_locked, seconds)."""
    d = _read_lockout()
    attempts = d.get("attempts", 0) + 1
    locked_until = 0
    if attempts >= MAX_LOGIN_TRIES:
        locked_until = time.time() + LOCKOUT_SECS
        attempts = 0
    _write_lockout({"attempts": attempts, "locked_until": locked_until})
    is_locked, secs, _ = get_login_status()
    return is_locked, secs


def reset_login_lockout() -> None:
    try:
        if _LOCKOUT_FILE.exists():
            _LOCKOUT_FILE.unlink()
    except Exception:
        pass


def password_strength(pw: str) -> tuple[int, str]:
    """Returns (score 0-4, label). Used during setup."""
    score = 0
    if len(pw) >= 8:  score += 1
    if len(pw) >= 12: score += 1
    if any(c.isupper() for c in pw) and any(c.islower() for c in pw): score += 1
    if any(c.isdigit() for c in pw): score += 1
    labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
    return score, labels[score]

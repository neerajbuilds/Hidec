"""
PIN storage: hashed with PBKDF2-HMAC-SHA256 + per-vault salt.
Lockout: 5 wrong attempts → 10 minute lockout.
"""

import json
import os
import hashlib
import time
from pathlib import Path

VAULT_META      = ".vaultmeta"
LOCKOUT_FILE    = ".lockout"
META_SALT_SIZE  = 32
META_KDF_ITERS  = 600_000
MAX_ATTEMPTS    = 5
LOCKOUT_SECONDS = 600


def _hash_pin(pin: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, META_KDF_ITERS)
    return dk.hex()


def save_pin(folder: Path, pin: str) -> None:
    salt = os.urandom(META_SALT_SIZE)
    meta = {
        "salt": salt.hex(),
        "pin_hash": _hash_pin(pin, salt),
        "version": 1,
    }
    meta_path = folder / VAULT_META
    meta_path.write_text(json.dumps(meta))
    _hide_file(meta_path)
    _reset_lockout(folder)


def get_lockout_status(folder: Path):
    """
    Returns (is_locked, seconds_remaining, attempts_used).
    """
    lock_path = folder / LOCKOUT_FILE
    if not lock_path.exists():
        return False, 0, 0
    try:
        data = json.loads(lock_path.read_text())
        attempts = data.get("attempts", 0)
        locked_until = data.get("locked_until", 0)
        now = time.time()
        if locked_until and now < locked_until:
            return True, int(locked_until - now), attempts
        return False, 0, attempts
    except Exception:
        return False, 0, 0


def verify_pin(folder: Path, pin: str):
    """
    Returns True on success.
    Returns (False, seconds_remaining) if locked out.
    Returns False if wrong PIN.
    Raises RuntimeError if no PIN set.
    """
    meta_path = folder / VAULT_META
    if not meta_path.exists():
        raise RuntimeError("No PIN set for this folder.")

    is_locked, secs, attempts = get_lockout_status(folder)
    if is_locked:
        return False, secs

    meta = json.loads(meta_path.read_text())
    salt = bytes.fromhex(meta["salt"])
    correct = _hash_pin(pin, salt) == meta["pin_hash"]

    if correct:
        _reset_lockout(folder)
        return True
    else:
        _record_failure(folder, attempts)
        _, secs, _ = get_lockout_status(folder)
        if secs:
            return False, secs
        return False


def has_pin(folder: Path) -> bool:
    return (folder / VAULT_META).exists()


def _reset_lockout(folder: Path) -> None:
    lock_path = folder / LOCKOUT_FILE
    if lock_path.exists():
        lock_path.unlink()


def _record_failure(folder: Path, current_attempts: int) -> None:
    new_attempts = current_attempts + 1
    lock_path = folder / LOCKOUT_FILE
    data: dict = {"attempts": new_attempts, "locked_until": 0}
    if new_attempts >= MAX_ATTEMPTS:
        data["locked_until"] = time.time() + LOCKOUT_SECONDS
        data["attempts"] = 0
    lock_path.write_text(json.dumps(data))
    _hide_file(lock_path)


def _hide_file(path: Path) -> None:
    import sys
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(path), 2)
        except Exception:
            pass

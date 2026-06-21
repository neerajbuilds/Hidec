"""
SQLite database layer for FolderLock.
Stores app config, protected folder metadata, and activity logs.
"""

import os
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path

APP_DIR    = Path(os.environ.get("APPDATA", Path.home())) / "FolderLock"
DB_PATH    = APP_DIR / "folderlock.db"
BACKUP_DIR = APP_DIR / "backups"
OLD_JSON   = APP_DIR / "folders.json"   # migration target


# ── Connection helper ─────────────────────────────────────────────────────────

def _conn() -> sqlite3.Connection:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


# ── Schema ────────────────────────────────────────────────────────────────────

def init_db() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    con = _conn()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS app_config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS protected_folders (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT    NOT NULL,
            original_path TEXT    NOT NULL UNIQUE,
            status        TEXT    NOT NULL DEFAULT 'unlocked',
            added_at      TEXT    NOT NULL,
            locked_at     TEXT,
            last_access   TEXT,
            notes         TEXT
        );

        CREATE TABLE IF NOT EXISTS activity_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            action    TEXT    NOT NULL,
            folder    TEXT,
            details   TEXT,
            success   INTEGER NOT NULL DEFAULT 1
        );
    """)
    con.commit()
    con.close()
    _migrate_from_json()


def _migrate_from_json() -> None:
    """One-time import of old folders.json into SQLite."""
    if not OLD_JSON.exists():
        return
    try:
        import json
        paths = json.loads(OLD_JSON.read_text(encoding="utf-8"))
        for p in paths:
            folder = Path(p)
            if folder.exists():
                add_folder(folder)
        OLD_JSON.rename(OLD_JSON.with_suffix(".json.migrated"))
    except Exception:
        pass


# ── App config (master password) ──────────────────────────────────────────────

def is_first_run() -> bool:
    con = _conn()
    row = con.execute("SELECT value FROM app_config WHERE key='master_hash'").fetchone()
    con.close()
    return row is None


def save_master(pw_hash: str, salt: str) -> None:
    con = _conn()
    now = datetime.now().isoformat()
    for k, v in [("master_hash", pw_hash), ("master_salt", salt), ("setup_date", now)]:
        con.execute("INSERT OR REPLACE INTO app_config(key,value) VALUES(?,?)", (k, v))
    con.commit()
    con.close()


def get_master() -> tuple[str | None, str | None]:
    con = _conn()
    h = con.execute("SELECT value FROM app_config WHERE key='master_hash'").fetchone()
    s = con.execute("SELECT value FROM app_config WHERE key='master_salt'").fetchone()
    con.close()
    return (h[0] if h else None, s[0] if s else None)


def get_config(key: str, default: str = "") -> str:
    con = _conn()
    row = con.execute("SELECT value FROM app_config WHERE key=?", (key,)).fetchone()
    con.close()
    return row[0] if row else default


def set_config(key: str, value: str) -> None:
    con = _conn()
    con.execute("INSERT OR REPLACE INTO app_config(key,value) VALUES(?,?)", (key, value))
    con.commit()
    con.close()


# ── Folder CRUD ───────────────────────────────────────────────────────────────

def add_folder(path: Path) -> None:
    con = _conn()
    now = datetime.now().isoformat()
    con.execute("""
        INSERT OR IGNORE INTO protected_folders(name, original_path, status, added_at, last_access)
        VALUES (?,?,?,?,?)
    """, (path.name, str(path), "unlocked", now, now))
    con.commit()
    con.close()


def update_status(path: Path, status: str) -> None:
    con = _conn()
    now = datetime.now().isoformat()
    if status == "locked":
        con.execute("""UPDATE protected_folders
                       SET status=?, locked_at=?, last_access=?
                       WHERE original_path=?""", (status, now, now, str(path)))
    else:
        con.execute("""UPDATE protected_folders
                       SET status=?, last_access=?
                       WHERE original_path=?""", (status, now, str(path)))
    con.commit()
    con.close()


def remove_folder(path: Path) -> None:
    con = _conn()
    con.execute("DELETE FROM protected_folders WHERE original_path=?", (str(path),))
    con.commit()
    con.close()


def get_all_folders() -> list[sqlite3.Row]:
    con = _conn()
    rows = con.execute(
        "SELECT * FROM protected_folders ORDER BY added_at DESC"
    ).fetchall()
    con.close()
    return rows


def get_folder(path: Path) -> sqlite3.Row | None:
    con = _conn()
    row = con.execute(
        "SELECT * FROM protected_folders WHERE original_path=?", (str(path),)
    ).fetchone()
    con.close()
    return row


# ── Activity log ──────────────────────────────────────────────────────────────

def log(action: str, folder: str = None, details: str = None, success: bool = True) -> None:
    try:
        con = _conn()
        con.execute("""
            INSERT INTO activity_log(timestamp, action, folder, details, success)
            VALUES (?,?,?,?,?)
        """, (datetime.now().isoformat(), action, folder, details, 1 if success else 0))
        con.commit()
        con.close()
    except Exception:
        pass


def get_logs(limit: int = 200) -> list[sqlite3.Row]:
    con = _conn()
    rows = con.execute(
        "SELECT * FROM activity_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    con.close()
    return rows


def export_logs(dest: Path) -> int:
    rows = get_logs(10_000)
    lines = ["timestamp,action,folder,details,success"]
    for r in rows:
        def _q(v): return f'"{v}"' if v else ""
        lines.append(f"{r['timestamp']},{r['action']},{_q(r['folder'])},{_q(r['details'])},{r['success']}")
    dest.write_text("\n".join(lines), encoding="utf-8")
    return len(rows)


# ── Backup ────────────────────────────────────────────────────────────────────

def backup() -> None:
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        dst = BACKUP_DIR / f"folderlock_{ts}.db"
        shutil.copy2(DB_PATH, dst)
        old_backups = sorted(BACKUP_DIR.glob("*.db"))
        for b in old_backups[:-5]:
            b.unlink(missing_ok=True)
    except Exception:
        pass

"""
Hidec 2026 — Production-ready secure folder encryption
Master Password · PIN per folder · AES-256-GCM · Auto-lock · Backup/Restore
"""

import os
import shutil
import subprocess
import threading
import time
import zipfile
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

import auth
import database as db
from encryption import encrypt_folder, decrypt_folder, folder_is_locked
from pin_manager import save_pin, verify_pin, has_pin, get_lockout_status, MAX_ATTEMPTS

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ── Palette ───────────────────────────────────────────────────────────────────
INDIGO  = "#6366F1"
IND_DK  = "#4F46E5"
IND_GL  = "#818CF8"
RED     = "#EF4444"
RED_DK  = "#DC2626"
GREEN   = "#22C55E"
AMBER   = "#F59E0B"

# Muted tint colors — (light, dark) tuples, safe for tkinter (no 8-char RGBA)
IND_MUTED   = ("#EEF2FF", "#1E1B4B")
RED_MUTED   = ("#FEE2E2", "#3B0F0F")
GREEN_MUTED = ("#DCFCE7", "#052E16")
AMB_MUTED   = ("#FFFBEB", "#3B2000")

BG    = ("#F8F8F8", "#0F0F0F")
SURF  = ("#FFFFFF", "#1A1A1A")
CARD  = ("#FFFFFF", "#242424")
CARD2 = ("#F3F4F6", "#2E2E2E")
BDR   = ("#E5E7EB", "#333333")
TXT   = ("#111111", "#F5F5F5")
MUTED = ("#6B7280", "#737373")

FONT = "Segoe UI Variable"

LOCK_OPTIONS = {
    "Off":        0,
    "1 minute":   60,
    "5 minutes":  300,
    "10 minutes": 600,
    "30 minutes": 1800,
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_str() -> str:
    return datetime.now().strftime("%d %b %Y  %H:%M")


def _open_explorer(path: Path) -> None:
    try:
        subprocess.Popen(["explorer", str(path)])
    except Exception:
        pass


def _eye_toggle(entry: ctk.CTkEntry, btn: ctk.CTkButton) -> None:
    """Toggle show/hide on a CTkEntry and update the button icon."""
    hidden = entry.cget("show") != ""
    entry.configure(show="" if hidden else "●")
    btn.configure(text="🙈" if hidden else "👁")


def _labeled_entry(parent, label: str, var: ctk.StringVar,
                   show: bool = False, border_color=None, pady_top=0) -> ctk.CTkEntry:
    """Render label + [entry | 👁 button]. Returns the CTkEntry."""
    if border_color is None:
        border_color = BDR
    ctk.CTkLabel(parent, text=label,
                 font=ctk.CTkFont(family=FONT, size=11),
                 text_color=MUTED).pack(anchor="w", pady=(pady_top, 0))
    row = ctk.CTkFrame(parent, fg_color="transparent")
    row.pack(fill="x", pady=(4, 0))
    entry = ctk.CTkEntry(row, textvariable=var,
                         show="●" if show else "",
                         height=40, font=ctk.CTkFont(size=14),
                         border_color=border_color, border_width=1, fg_color=CARD2)
    entry.pack(side="left", fill="x", expand=True)
    if show:
        toggle = ctk.CTkButton(row, text="👁", width=42, height=40,
                                fg_color=CARD2, hover_color=BDR, text_color=MUTED,
                                border_width=1, border_color=BDR,
                                font=ctk.CTkFont(size=15),
                                command=lambda e=entry: None)
        toggle.pack(side="right", padx=(4, 0))
        toggle.configure(command=lambda e=entry, b=toggle: _eye_toggle(e, b))
    return entry


# ══════════════════════════════════════════════════════════════════════════════
#  PIN Dialog
# ══════════════════════════════════════════════════════════════════════════════

class PINDialog(ctk.CTkToplevel):
    def __init__(self, parent, title: str, subtitle: str = "", confirm: bool = False):
        super().__init__(parent)
        self.title("Hidec")
        self.resizable(False, False)
        self.grab_set()
        self.result: str | None = None
        h = 360 if confirm else 300
        self.geometry(f"430x{h}")
        self._center(parent)
        self.configure(fg_color=CARD)
        self._build(title, subtitle, confirm)
        self.lift()
        self.focus_force()

    def _center(self, parent):
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - 430) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - 360) // 2
        self.geometry(f"+{x}+{y}")

    def _build(self, title, subtitle, confirm):
        ctk.CTkFrame(self, height=4, fg_color=INDIGO, corner_radius=0).pack(fill="x")
        body = ctk.CTkFrame(self, fg_color=CARD, corner_radius=0)
        body.pack(fill="both", expand=True, padx=28, pady=20)

        ctk.CTkLabel(body, text="🔐 " + title,
                     font=ctk.CTkFont(family=FONT, size=17, weight="bold"),
                     text_color=TXT).pack(anchor="w")
        if subtitle:
            ctk.CTkLabel(body, text=subtitle,
                         font=ctk.CTkFont(family=FONT, size=11),
                         text_color=MUTED).pack(anchor="w", pady=(2, 0))
        ctk.CTkFrame(body, height=1, fg_color=BDR).pack(fill="x", pady=14)

        self._pin_var = ctk.StringVar()
        self._pin_e = _labeled_entry(body, "PIN  (4 – 12 digits)", self._pin_var,
                                      show=True, border_color=INDIGO)
        self._pin_e.focus()

        self._confirm_mode = confirm
        if confirm:
            self._conf_var = ctk.StringVar()
            _labeled_entry(body, "Confirm PIN", self._conf_var,
                           show=True, pady_top=12)

        self._err = ctk.CTkLabel(body, text="",
                                  font=ctk.CTkFont(family=FONT, size=11), text_color=RED)
        self._err.pack(anchor="w", pady=(8, 0))

        row = ctk.CTkFrame(self, fg_color=CARD, corner_radius=0)
        row.pack(fill="x", padx=28, pady=(0, 20))
        ctk.CTkButton(row, text="Cancel", width=90, height=36,
                      fg_color=CARD2, hover_color=BDR, text_color=TXT,
                      font=ctk.CTkFont(family=FONT, size=12),
                      command=self.destroy).pack(side="right", padx=(8, 0))
        ctk.CTkButton(row, text="Set PIN" if confirm else "Unlock",
                      width=110, height=36, fg_color=INDIGO, hover_color=IND_DK,
                      font=ctk.CTkFont(family=FONT, size=12, weight="bold"),
                      command=self._submit).pack(side="right")
        self.bind("<Return>", lambda _: self._submit())

    def _submit(self):
        pin = self._pin_var.get().strip()
        if not pin.isdigit() or not (4 <= len(pin) <= 12):
            self._err.configure(text="⚠  PIN must be 4–12 digits only")
            return
        if self._confirm_mode:
            if pin != getattr(self, "_conf_var", ctk.StringVar()).get().strip():
                self._err.configure(text="⚠  PINs do not match")
                return
        self.result = pin
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
#  Folder Details Dialog
# ══════════════════════════════════════════════════════════════════════════════

class DetailsDialog(ctk.CTkToplevel):
    def __init__(self, parent, folder: Path):
        super().__init__(parent)
        self.title("Folder Details — Hidec")
        self.resizable(False, False)
        self.grab_set()
        self.geometry("480x360")
        self._center(parent)
        self.configure(fg_color=CARD)
        self._build(folder)
        self.lift()

    def _center(self, parent):
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - 480) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - 360) // 2
        self.geometry(f"+{x}+{y}")

    def _build(self, folder: Path):
        ctk.CTkFrame(self, height=4, fg_color=INDIGO, corner_radius=0).pack(fill="x")
        body = ctk.CTkFrame(self, fg_color=CARD, corner_radius=0)
        body.pack(fill="both", expand=True, padx=28, pady=20)

        locked = folder_is_locked(folder)
        ctk.CTkLabel(body, text=("🔒  " if locked else "📂  ") + folder.name,
                     font=ctk.CTkFont(family=FONT, size=16, weight="bold"),
                     text_color=TXT).pack(anchor="w")
        ctk.CTkFrame(body, height=1, fg_color=BDR).pack(fill="x", pady=12)

        row = db.get_folder(folder)

        def _field(label, value, color=None):
            f = ctk.CTkFrame(body, fg_color="transparent")
            f.pack(fill="x", pady=3)
            ctk.CTkLabel(f, text=label, width=120, anchor="w",
                         font=ctk.CTkFont(family=FONT, size=11),
                         text_color=MUTED).pack(side="left")
            ctk.CTkLabel(f, text=value, anchor="w",
                         font=ctk.CTkFont(family=FONT, size=11),
                         text_color=color or TXT).pack(side="left")

        _field("Status:",  "🔒 ENCRYPTED" if locked else "✓  Unlocked",
               RED if locked else GREEN)
        _field("Path:",    str(folder))
        _field("On disk:", "✓  Found" if folder.exists() else "⚠  Not found",
               GREEN if folder.exists() else AMBER)
        if row:
            def _fmt(v): return v[:19].replace("T", "  ") if v else "—"
            _field("Added:",      _fmt(row["added_at"]))
            _field("Locked at:",  _fmt(row["locked_at"]))
            _field("Last used:",  _fmt(row["last_access"]))

        ctk.CTkButton(self, text="Close", width=100, height=34,
                      fg_color=INDIGO, hover_color=IND_DK,
                      font=ctk.CTkFont(family=FONT, size=12),
                      command=self.destroy).pack(pady=(0, 20))


# ══════════════════════════════════════════════════════════════════════════════
#  Activity Log Dialog
# ══════════════════════════════════════════════════════════════════════════════

class LogDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Activity Log — Hidec")
        self.geometry("700x520")
        self.minsize(520, 380)
        self.grab_set()
        self.configure(fg_color=BG)
        self._build()
        self.lift()

    def _build(self):
        ctk.CTkFrame(self, height=4, fg_color=INDIGO, corner_radius=0).pack(fill="x")
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(14, 0))
        ctk.CTkLabel(hdr, text="📋  Activity Log",
                     font=ctk.CTkFont(family=FONT, size=16, weight="bold"),
                     text_color=TXT).pack(side="left")
        ctk.CTkButton(hdr, text="⬇  Export CSV", width=120, height=30,
                      fg_color=INDIGO, hover_color=IND_DK,
                      font=ctk.CTkFont(family=FONT, size=11),
                      command=self._export).pack(side="right")

        box = ctk.CTkScrollableFrame(self, fg_color=SURF, corner_radius=10)
        box.pack(fill="both", expand=True, padx=20, pady=12)

        logs = db.get_logs(200)
        if not logs:
            ctk.CTkLabel(box, text="No activity recorded yet.",
                         font=ctk.CTkFont(family=FONT, size=12),
                         text_color=MUTED).pack(pady=40)
            return

        for row in logs:
            ok     = row["success"] == 1
            ts     = row["timestamp"][:19].replace("T", "  ")
            action = row["action"]
            folder = row["folder"] or ""
            detail = row["details"] or ""

            card = ctk.CTkFrame(box, fg_color=CARD, corner_radius=8)
            card.pack(fill="x", pady=3, padx=4)
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=12, pady=(8, 2))
            ctk.CTkLabel(top,
                         text=("✅" if ok else "❌") + f"  {action}",
                         font=ctk.CTkFont(family=FONT, size=12, weight="bold"),
                         text_color=TXT if ok else RED).pack(side="left")
            ctk.CTkLabel(top, text=ts,
                         font=ctk.CTkFont(family=FONT, size=10),
                         text_color=MUTED).pack(side="right")
            sub = (folder + ("  —  " + detail if detail else "")) or detail
            if sub:
                ctk.CTkLabel(card, text=f"  {sub}",
                             font=ctk.CTkFont(family=FONT, size=10),
                             text_color=MUTED).pack(anchor="w", padx=12, pady=(0, 8))
            else:
                ctk.CTkFrame(card, height=6, fg_color="transparent").pack()

    def _export(self):
        dest = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="folderlock_log.csv")
        if dest:
            count = db.export_logs(Path(dest))
            messagebox.showinfo("Exported", f"✅  {count} entries saved.")


# ══════════════════════════════════════════════════════════════════════════════
#  Change Master Password Dialog
# ══════════════════════════════════════════════════════════════════════════════

class ChangePasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Change Master Password — Hidec")
        self.resizable(False, False)
        self.grab_set()
        self.geometry("440x380")
        self._center(parent)
        self.configure(fg_color=CARD)
        self._build()
        self.lift()
        self.focus_force()

    def _center(self, parent):
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - 440) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - 380) // 2
        self.geometry(f"+{x}+{y}")

    def _build(self):
        ctk.CTkFrame(self, height=4, fg_color=INDIGO, corner_radius=0).pack(fill="x")
        body = ctk.CTkFrame(self, fg_color=CARD, corner_radius=0)
        body.pack(fill="both", expand=True, padx=28, pady=20)

        ctk.CTkLabel(body, text="🔑  Change Master Password",
                     font=ctk.CTkFont(family=FONT, size=16, weight="bold"),
                     text_color=TXT).pack(anchor="w")
        ctk.CTkFrame(body, height=1, fg_color=BDR).pack(fill="x", pady=14)

        self._cur_var = ctk.StringVar()
        self._cur_e   = _labeled_entry(body, "Current Password", self._cur_var, show=True,
                                        border_color=INDIGO)
        self._cur_e.focus()

        self._new_var = ctk.StringVar()
        _labeled_entry(body, "New Password  (min 6 chars)", self._new_var,
                       show=True, pady_top=12)

        self._conf_var = ctk.StringVar()
        _labeled_entry(body, "Confirm New Password", self._conf_var,
                       show=True, pady_top=10)

        self._err = ctk.CTkLabel(body, text="",
                                  font=ctk.CTkFont(family=FONT, size=11), text_color=RED)
        self._err.pack(anchor="w", pady=(8, 0))

        btns = ctk.CTkFrame(self, fg_color=CARD, corner_radius=0)
        btns.pack(fill="x", padx=28, pady=(0, 20))
        ctk.CTkButton(btns, text="Cancel", width=90, height=36,
                      fg_color=CARD2, hover_color=BDR, text_color=TXT,
                      font=ctk.CTkFont(family=FONT, size=12),
                      command=self.destroy).pack(side="right", padx=(8, 0))
        ctk.CTkButton(btns, text="Save Password", width=130, height=36,
                      fg_color=INDIGO, hover_color=IND_DK,
                      font=ctk.CTkFont(family=FONT, size=12, weight="bold"),
                      command=self._submit).pack(side="right")
        self.bind("<Return>", lambda _: self._submit())

    def _submit(self):
        cur  = self._cur_var.get()
        new  = self._new_var.get()
        conf = self._conf_var.get()
        h, s = db.get_master()
        if not auth.verify_password(cur, h, s):
            self._err.configure(text="⚠  Current password is incorrect")
            return
        if len(new) < 6:
            self._err.configure(text="⚠  New password must be at least 6 characters")
            return
        if new != conf:
            self._err.configure(text="⚠  Passwords do not match")
            return
        pw_hash, salt = auth.hash_password(new)
        db.save_master(pw_hash, salt)
        db.log("PASSWORD_CHANGED", details="Master password updated")
        messagebox.showinfo("Success", "✅  Master password updated successfully.")
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
#  Settings Dialog
# ══════════════════════════════════════════════════════════════════════════════

class SettingsDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Settings — Hidec")
        self.resizable(False, False)
        self.grab_set()
        self.geometry("480x500")
        self._center(parent)
        self.configure(fg_color=BG)
        self._build()
        self.lift()

    def _center(self, parent):
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - 480) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - 500) // 2
        self.geometry(f"+{x}+{y}")

    def _section(self, parent, title: str):
        ctk.CTkLabel(parent, text=title,
                     font=ctk.CTkFont(family=FONT, size=10, weight="bold"),
                     text_color=MUTED).pack(anchor="w", padx=20, pady=(16, 4))
        card = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=10)
        card.pack(fill="x", padx=20, pady=(0, 4))
        return card

    def _row(self, parent, label: str, widget_fn):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=10)
        ctk.CTkLabel(row, text=label, anchor="w",
                     font=ctk.CTkFont(family=FONT, size=12),
                     text_color=TXT).pack(side="left", fill="x", expand=True)
        widget_fn(row)

    def _build(self):
        ctk.CTkFrame(self, height=4, fg_color=INDIGO, corner_radius=0).pack(fill="x")
        ctk.CTkLabel(self, text="⚙  Settings",
                     font=ctk.CTkFont(family=FONT, size=18, weight="bold"),
                     text_color=TXT).pack(anchor="w", padx=20, pady=(16, 0))

        body = ctk.CTkScrollableFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)

        # ── Security ─────────────────────────────────────────────────────────
        sec = self._section(body, "SECURITY")

        saved_timeout = int(db.get_config("auto_lock_timeout", "300"))
        saved_label   = next((k for k, v in LOCK_OPTIONS.items() if v == saved_timeout),
                              "5 minutes")
        self._lock_var = ctk.StringVar(value=saved_label)

        def _make_lock_menu(row):
            ctk.CTkOptionMenu(row, values=list(LOCK_OPTIONS.keys()),
                              variable=self._lock_var, width=140, height=32,
                              fg_color=CARD2, button_color=CARD2,
                              button_hover_color=BDR,
                              font=ctk.CTkFont(family=FONT, size=12),
                              command=self._save_timeout).pack(side="right")
        self._row(sec, "Auto-lock timeout", _make_lock_menu)

        ctk.CTkFrame(sec, height=1, fg_color=BDR).pack(fill="x", padx=16)

        def _make_pw_btn(row):
            ctk.CTkButton(row, text="Change…", width=100, height=32,
                          fg_color=INDIGO, hover_color=IND_DK,
                          font=ctk.CTkFont(family=FONT, size=11),
                          command=lambda: ChangePasswordDialog(self)).pack(side="right")
        self._row(sec, "Master password", _make_pw_btn)

        # ── Backup & Restore ─────────────────────────────────────────────────
        bak = self._section(body, "BACKUP & RESTORE")

        def _make_backup_btn(row):
            ctk.CTkButton(row, text="Export…", width=100, height=32,
                          fg_color=GREEN, hover_color="#16A34A",
                          font=ctk.CTkFont(family=FONT, size=11),
                          command=self._backup).pack(side="right")
        self._row(bak, "Export encrypted backup", _make_backup_btn)

        ctk.CTkFrame(bak, height=1, fg_color=BDR).pack(fill="x", padx=16)

        def _make_restore_btn(row):
            ctk.CTkButton(row, text="Import…", width=100, height=32,
                          fg_color=AMBER, hover_color="#D97706",
                          font=ctk.CTkFont(family=FONT, size=11, weight="bold"),
                          command=self._restore).pack(side="right")
        self._row(bak, "Restore from backup", _make_restore_btn)

        ctk.CTkLabel(bak,
                     text="  Backup saves your vault database and folder list.\n"
                          "  Restore will overwrite current data — use carefully.",
                     font=ctk.CTkFont(family=FONT, size=9),
                     text_color=MUTED, justify="left").pack(anchor="w", padx=16, pady=(0, 10))

        # ── About ────────────────────────────────────────────────────────────
        about = self._section(body, "ABOUT")
        for label, val in [("Version", "2.0 · 2026"),
                            ("Encryption", "AES-256-GCM"),
                            ("Key derivation", "PBKDF2-SHA256  ·  600 000 iterations"),
                            ("Storage", "SQLite  ·  AppData\\FolderLock")]:
            def _make_val(v):
                def _w(row):
                    ctk.CTkLabel(row, text=v, anchor="e",
                                 font=ctk.CTkFont(family=FONT, size=11),
                                 text_color=MUTED).pack(side="right")
                return _w
            self._row(about, label, _make_val(val))

        ctk.CTkFrame(body, height=12, fg_color="transparent").pack()

    def _save_timeout(self, label: str):
        secs = LOCK_OPTIONS.get(label, 300)
        db.set_config("auto_lock_timeout", str(secs))

    def _backup(self):
        dest = filedialog.asksaveasfilename(
            defaultextension=".flbak",
            filetypes=[("Hidec backup", "*.flbak"), ("Zip", "*.zip")],
            initialfile=f"folderlock_backup_{datetime.now().strftime('%Y%m%d')}.flbak")
        if not dest:
            return
        try:
            src = db.APP_DIR
            with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
                for f in src.rglob("*"):
                    if f.is_file() and f.suffix not in (".migrated",):
                        z.write(f, f.relative_to(src))
            db.log("BACKUP_CREATED", details=dest)
            messagebox.showinfo("Backup Created",
                                f"✅  Backup saved to:\n{dest}\n\n"
                                "Keep this file safe — it contains your vault database.")
        except Exception as e:
            messagebox.showerror("Backup Failed", f"Could not create backup:\n{e}")

    def _restore(self):
        src = filedialog.askopenfilename(
            filetypes=[("Hidec backup", "*.flbak"), ("Zip", "*.zip")])
        if not src:
            return
        if not messagebox.askyesno(
                "Restore Backup",
                "⚠  This will overwrite your current vault database.\n\n"
                "All existing data will be replaced by the backup.\n\n"
                "Continue?"):
            return
        try:
            with zipfile.ZipFile(src, "r") as z:
                z.extractall(db.APP_DIR)
            db.log("BACKUP_RESTORED", details=src)
            messagebox.showinfo("Restored",
                                "✅  Backup restored.\n\nRestart Hidec to reload your vaults.")
        except Exception as e:
            messagebox.showerror("Restore Failed", f"Could not restore backup:\n{e}")


# ══════════════════════════════════════════════════════════════════════════════
#  Folder Card
# ══════════════════════════════════════════════════════════════════════════════

class FolderCard(ctk.CTkFrame):
    def __init__(self, parent, folder: Path, app_ref):
        super().__init__(parent, fg_color=CARD, border_color=BDR,
                         border_width=1, corner_radius=12)
        self.folder   = folder
        self._app     = app_ref
        self._locked  = folder_is_locked(folder)
        self._has_pin = has_pin(folder)
        self._render()

    def _render(self):
        for w in self.winfo_children():
            w.destroy()

        locked = self._locked
        is_lo, lo_secs, _ = get_lockout_status(self.folder)

        ctk.CTkFrame(self, height=3, corner_radius=0,
                     fg_color=RED if locked else INDIGO).pack(fill="x")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="x", padx=16, pady=12)

        icon_bg = ctk.CTkFrame(body, width=46, height=46, corner_radius=10,
                                fg_color=IND_MUTED if not locked else RED_MUTED)
        icon_bg.pack(side="left")
        icon_bg.pack_propagate(False)
        ctk.CTkLabel(icon_bg, text="🔒" if locked else "📂",
                     font=ctk.CTkFont(size=22)).place(relx=.5, rely=.5, anchor="center")

        info = ctk.CTkFrame(body, fg_color="transparent")
        info.pack(side="left", fill="x", expand=True, padx=14)

        nr = ctk.CTkFrame(info, fg_color="transparent")
        nr.pack(fill="x")
        ctk.CTkLabel(nr, text=self.folder.name,
                     font=ctk.CTkFont(family=FONT, size=14, weight="bold"),
                     text_color=TXT, anchor="w").pack(side="left")

        if is_lo:
            m, s = lo_secs // 60, lo_secs % 60
            b = ctk.CTkFrame(nr, fg_color=AMB_MUTED, corner_radius=4)
            b.pack(side="right")
            ctk.CTkLabel(b, text=f"⏱ {m}m {s}s",
                         font=ctk.CTkFont(family=FONT, size=10, weight="bold"),
                         text_color=AMBER).pack(padx=8, pady=2)
        elif locked:
            b = ctk.CTkFrame(nr, fg_color=RED_MUTED, corner_radius=4)
            b.pack(side="right")
            ctk.CTkLabel(b, text="⚿  ENCRYPTED",
                         font=ctk.CTkFont(family=FONT, size=10, weight="bold"),
                         text_color=RED).pack(padx=8, pady=2)
        else:
            b = ctk.CTkFrame(nr, fg_color=GREEN_MUTED, corner_radius=4)
            b.pack(side="right")
            ctk.CTkLabel(b, text="✓  UNLOCKED",
                         font=ctk.CTkFont(family=FONT, size=10, weight="bold"),
                         text_color=GREEN).pack(padx=8, pady=2)

        ctk.CTkLabel(info, text=str(self.folder),
                     font=ctk.CTkFont(family=FONT, size=10),
                     text_color=MUTED, anchor="w", wraplength=380).pack(fill="x", pady=(2, 0))

        ctk.CTkFrame(self, height=1, fg_color=BDR).pack(fill="x", padx=16)

        # Progress bar
        self._prog_wrap = ctk.CTkFrame(self, fg_color="transparent")
        self._prog_bar  = ctk.CTkProgressBar(self._prog_wrap, height=3,
                                              progress_color=INDIGO, fg_color=CARD2)
        self._prog_bar.set(0)
        self._prog_bar.pack(fill="x", padx=16, pady=(8, 0))
        self._prog_lbl = ctk.CTkLabel(self._prog_wrap, text="",
                                       font=ctk.CTkFont(family=FONT, size=10), text_color=MUTED)
        self._prog_lbl.pack(anchor="w", padx=16, pady=(2, 6))

        # Buttons
        br = ctk.CTkFrame(self, fg_color="transparent")
        br.pack(fill="x", padx=16, pady=(8, 12))

        if locked:
            ctk.CTkButton(br, text="🔓 Unlock", width=100, height=32,
                          fg_color=INDIGO, hover_color=IND_DK,
                          font=ctk.CTkFont(family=FONT, size=12, weight="bold"),
                          command=self._unlock).pack(side="left", padx=(0, 6))
        else:
            label = "🔒 Lock" if self._has_pin else "🔒 Lock & Encrypt"
            ctk.CTkButton(br, text=label, width=120, height=32,
                          fg_color=RED, hover_color=RED_DK,
                          font=ctk.CTkFont(family=FONT, size=12, weight="bold"),
                          command=self._lock).pack(side="left", padx=(0, 6))
            ctk.CTkButton(br, text="📂 Open", width=80, height=32,
                          fg_color=INDIGO, hover_color=IND_DK,
                          font=ctk.CTkFont(family=FONT, size=11),
                          command=lambda: _open_explorer(self.folder)).pack(side="left", padx=(0, 6))

        ctk.CTkButton(br, text="Details", width=70, height=32,
                      fg_color="transparent", border_width=1, border_color=BDR,
                      text_color=MUTED, hover_color=CARD2,
                      font=ctk.CTkFont(family=FONT, size=11),
                      command=self._details).pack(side="left", padx=(0, 6))
        ctk.CTkButton(br, text="Remove", width=70, height=32,
                      fg_color="transparent", border_width=1, border_color=BDR,
                      text_color=MUTED, hover_color=CARD2,
                      font=ctk.CTkFont(family=FONT, size=11),
                      command=self._remove).pack(side="right")

    def _show_progress(self):
        self._prog_wrap.pack(fill="x", before=self.winfo_children()[-1])

    def _hide_progress(self):
        self._prog_wrap.pack_forget()

    def _progress_cb(self, done, total):
        pct = done / total if total else 1.0
        self.after(0, lambda: self._prog_bar.set(pct))
        self.after(0, lambda: self._prog_lbl.configure(text=f"  {done}/{total} files…"))

    def _lock(self):
        top = self.winfo_toplevel()
        if not self._has_pin:
            dlg = PINDialog(top, "Set Encryption PIN",
                            "Choose a PIN to protect this folder", confirm=True)
        else:
            dlg = PINDialog(top, "Re-lock Folder",
                            "Enter your current PIN to re-encrypt")
        self.wait_window(dlg)
        if not dlg.result:
            return
        pin = dlg.result
        if not self._has_pin:
            save_pin(self.folder, pin)
        else:
            result = verify_pin(self.folder, pin)
            if result is not True:
                if isinstance(result, tuple):
                    m, s = result[1] // 60, result[1] % 60
                    messagebox.showerror("Locked Out", f"Too many attempts. Wait {m}m {s}s.")
                else:
                    messagebox.showerror("Wrong PIN", "Incorrect PIN — cannot lock.")
                return
        self._show_progress()

        def worker():
            try:
                count = encrypt_folder(self.folder, pin, self._progress_cb)
                db.update_status(self.folder, "locked")
                db.log("FOLDER_LOCKED", self.folder.name, f"{count} files encrypted")
                self.after(0, lambda: self._after_lock(count))
            except PermissionError:
                db.log("FOLDER_LOCKED", self.folder.name, "Permission denied", success=False)
                self.after(0, lambda: messagebox.showerror(
                    "Permission Error",
                    "Cannot encrypt — a file is open or protected.\n"
                    "Close all files in this folder and try again."))
                self.after(0, self._hide_progress)
            except Exception as e:
                db.log("FOLDER_LOCKED", self.folder.name, str(e), success=False)
                self.after(0, lambda: messagebox.showerror("Encryption Failed", str(e)))
                self.after(0, self._hide_progress)

        threading.Thread(target=worker, daemon=True).start()

    def _after_lock(self, count):
        self._hide_progress()
        self._locked  = True
        self._has_pin = True
        self._render()
        self._app.refresh_stats()
        messagebox.showinfo("Encrypted", f"✅  {count} file(s) encrypted with AES-256-GCM.")

    def _unlock(self):
        is_lo, lo_secs, _ = get_lockout_status(self.folder)
        if is_lo:
            m, s = lo_secs // 60, lo_secs % 60
            messagebox.showerror("Locked Out",
                                 f"Too many failed attempts.\nWait {m}m {s}s and try again.")
            return
        dlg = PINDialog(self.winfo_toplevel(), "Unlock Folder",
                        "Enter your PIN to decrypt this folder")
        self.wait_window(dlg)
        if not dlg.result:
            return
        result = verify_pin(self.folder, dlg.result)
        if result is True:
            self._show_progress()
            pin = dlg.result

            def worker():
                try:
                    count = decrypt_folder(self.folder, pin, self._progress_cb)
                    db.update_status(self.folder, "unlocked")
                    db.log("FOLDER_UNLOCKED", self.folder.name, f"{count} files decrypted")
                    self.after(0, lambda: self._after_unlock(count))
                except Exception as e:
                    db.log("FOLDER_UNLOCKED", self.folder.name, str(e), success=False)
                    self.after(0, lambda: messagebox.showerror(
                        "Decryption Failed",
                        "Wrong PIN or files are corrupted.\n\n"
                        "Make sure you entered the correct PIN."))
                    self.after(0, self._hide_progress)

            threading.Thread(target=worker, daemon=True).start()
        elif isinstance(result, tuple):
            m, s = result[1] // 60, result[1] % 60
            db.log("LOGIN_FAILED", self.folder.name, "Too many attempts — locked", False)
            messagebox.showerror("Locked Out",
                                 f"Too many wrong PINs ({MAX_ATTEMPTS} attempts).\n"
                                 f"Try again in {m}m {s}s.")
            self._render()
        else:
            _, _, attempts = get_lockout_status(self.folder)
            left = MAX_ATTEMPTS - attempts
            db.log("LOGIN_FAILED", self.folder.name, f"Wrong PIN ({left} left)", False)
            messagebox.showerror("Wrong PIN",
                                 f"Incorrect PIN.\n{left} attempt(s) left before lockout.")

    def _after_unlock(self, count):
        self._hide_progress()
        self._locked = False
        self._render()
        self._app.refresh_stats()
        messagebox.showinfo("Decrypted", f"✅  {count} file(s) restored successfully.")

    def _details(self):
        DetailsDialog(self.winfo_toplevel(), self.folder)

    def _remove(self):
        if not folder_is_locked(self.folder):
            confirm = messagebox.askyesno(
                "Remove Protection",
                f"Remove '{self.folder.name}' from Hidec?\n\n"
                "The folder is currently unlocked and will be left as-is.")
        else:
            confirm = messagebox.askyesno(
                "Remove Protection",
                f"Remove '{self.folder.name}' from Hidec?\n\n"
                "⚠  This folder is still ENCRYPTED.\n"
                "You will need your PIN to decrypt it manually later.")
        if confirm:
            db.remove_folder(self.folder)
            db.log("FOLDER_REMOVED", self.folder.name)
            self._app.refresh()


# ══════════════════════════════════════════════════════════════════════════════
#  Setup Wizard (first run)
# ══════════════════════════════════════════════════════════════════════════════

class SetupFrame(ctk.CTkFrame):
    def __init__(self, parent, on_done):
        super().__init__(parent, fg_color=BG, corner_radius=0)
        self._on_done = on_done
        self._build()

    def _build(self):
        outer = ctk.CTkFrame(self, fg_color=CARD, corner_radius=16,
                              border_width=1, border_color=BDR, width=520, height=560)
        outer.place(relx=.5, rely=.5, anchor="center")
        outer.pack_propagate(False)

        ctk.CTkFrame(outer, height=5, fg_color=INDIGO, corner_radius=0).pack(fill="x")
        body = ctk.CTkFrame(outer, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=44, pady=28)

        logo_f = ctk.CTkFrame(body, width=56, height=56, corner_radius=14, fg_color=INDIGO)
        logo_f.pack()
        logo_f.pack_propagate(False)
        ctk.CTkLabel(logo_f, text="📁", font=ctk.CTkFont(size=26),
                     text_color="white").place(relx=.5, rely=.42, anchor="center")
        ctk.CTkLabel(logo_f, text="🔒", font=ctk.CTkFont(size=13),
                     text_color="white").place(relx=.5, rely=.76, anchor="center")

        ctk.CTkLabel(body, text="Welcome to Hidec",
                     font=ctk.CTkFont(family=FONT, size=22, weight="bold"),
                     text_color=TXT).pack(pady=(14, 4))
        ctk.CTkLabel(body, text="Create a Master Password to protect your dashboard",
                     font=ctk.CTkFont(family=FONT, size=12), text_color=MUTED).pack()
        ctk.CTkFrame(body, height=1, fg_color=BDR).pack(fill="x", pady=18)

        self._pw_var   = ctk.StringVar()
        self._conf_var = ctk.StringVar()

        self._pw_e = _labeled_entry(body, "Master Password  (min 6 chars)", self._pw_var,
                                     show=True, border_color=INDIGO)
        self._pw_e.focus()
        self._pw_var.trace_add("write", self._update_strength)

        self._strength_bar = ctk.CTkProgressBar(body, height=4, fg_color=CARD2,
                                                  progress_color=GREEN)
        self._strength_bar.set(0)
        self._strength_bar.pack(fill="x", pady=(6, 0))
        self._strength_lbl = ctk.CTkLabel(body, text="",
                                           font=ctk.CTkFont(family=FONT, size=10),
                                           text_color=MUTED)
        self._strength_lbl.pack(anchor="w")

        _labeled_entry(body, "Confirm Password", self._conf_var, show=True, pady_top=12)

        self._err = ctk.CTkLabel(body, text="",
                                  font=ctk.CTkFont(family=FONT, size=11), text_color=RED)
        self._err.pack(anchor="w", pady=(8, 0))

        ctk.CTkButton(body, text="Create Password & Get Started",
                      height=44, fg_color=INDIGO, hover_color=IND_DK, corner_radius=8,
                      font=ctk.CTkFont(family=FONT, size=13, weight="bold"),
                      command=self._submit).pack(fill="x", pady=(10, 0))
        self._pw_e.bind("<Return>", lambda _: self._submit())

    def _update_strength(self, *_):
        pw    = self._pw_var.get()
        score, label = auth.password_strength(pw)
        colors = ["#EF4444", "#F59E0B", "#F59E0B", "#22C55E", "#22C55E"]
        self._strength_bar.set(score / 4)
        self._strength_bar.configure(progress_color=colors[score])
        self._strength_lbl.configure(text=f"Strength: {label}" if pw else "")

    def _submit(self):
        pw   = self._pw_var.get()
        conf = self._conf_var.get()
        if len(pw) < 6:
            self._err.configure(text="⚠  Password must be at least 6 characters")
            return
        if pw != conf:
            self._err.configure(text="⚠  Passwords do not match")
            return
        pw_hash, salt = auth.hash_password(pw)
        db.save_master(pw_hash, salt)
        db.log("MASTER_PASSWORD_SET", details="Initial master password created")
        self._on_done()


# ══════════════════════════════════════════════════════════════════════════════
#  Login Screen
# ══════════════════════════════════════════════════════════════════════════════

class LoginFrame(ctk.CTkFrame):
    def __init__(self, parent, on_success, auto_locked: bool = False):
        super().__init__(parent, fg_color=BG, corner_radius=0)
        self._on_success  = on_success
        self._auto_locked = auto_locked
        self._build()

    def _build(self):
        outer = ctk.CTkFrame(self, fg_color=CARD, corner_radius=16,
                              border_width=1, border_color=BDR, width=440, height=380)
        outer.place(relx=.5, rely=.5, anchor="center")
        outer.pack_propagate(False)

        ctk.CTkFrame(outer, height=5, fg_color=INDIGO, corner_radius=0).pack(fill="x")
        body = ctk.CTkFrame(outer, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=36, pady=28)

        logo_f = ctk.CTkFrame(body, width=52, height=52, corner_radius=13, fg_color=INDIGO)
        logo_f.pack()
        logo_f.pack_propagate(False)
        ctk.CTkLabel(logo_f, text="📁", font=ctk.CTkFont(size=24),
                     text_color="white").place(relx=.5, rely=.42, anchor="center")
        ctk.CTkLabel(logo_f, text="🔒", font=ctk.CTkFont(size=12),
                     text_color="white").place(relx=.5, rely=.76, anchor="center")

        ctk.CTkLabel(body, text="Hidec",
                     font=ctk.CTkFont(family=FONT, size=20, weight="bold"),
                     text_color=TXT).pack(pady=(12, 2))

        subtitle = "🔒  Session locked due to inactivity" if self._auto_locked \
                   else "Enter your Master Password to continue"
        self._sub = ctk.CTkLabel(body, text=subtitle,
                                  font=ctk.CTkFont(family=FONT, size=11),
                                  text_color=AMBER if self._auto_locked else MUTED)
        self._sub.pack()
        ctk.CTkFrame(body, height=1, fg_color=BDR).pack(fill="x", pady=16)

        self._pw_var = ctk.StringVar()
        self._pw_e   = _labeled_entry(body, "Master Password", self._pw_var,
                                       show=True, border_color=INDIGO)
        self._pw_e.focus()

        self._err = ctk.CTkLabel(body, text="",
                                  font=ctk.CTkFont(family=FONT, size=11), text_color=RED)
        self._err.pack(anchor="w", pady=(8, 0))

        ctk.CTkButton(body, text="Unlock App", height=42,
                      fg_color=INDIGO, hover_color=IND_DK, corner_radius=8,
                      font=ctk.CTkFont(family=FONT, size=13, weight="bold"),
                      command=self._submit).pack(fill="x")
        self._pw_e.bind("<Return>", lambda _: self._submit())
        self._check_lockout()

    def _check_lockout(self):
        is_locked, secs, _ = auth.get_login_status()
        if is_locked:
            m, s = secs // 60, secs % 60
            self._sub.configure(text=f"⏱  Too many attempts — wait {m}m {s}s",
                                 text_color=AMBER)
            self.after(1000, self._check_lockout)
        else:
            if self._auto_locked:
                self._sub.configure(text="🔒  Session locked — enter password to continue",
                                     text_color=AMBER)

    def _submit(self):
        is_locked, secs, _ = auth.get_login_status()
        if is_locked:
            m, s = secs // 60, secs % 60
            self._err.configure(text=f"⏱  Locked. Wait {m}m {s}s.")
            return
        pw = self._pw_var.get()
        stored_hash, stored_salt = db.get_master()
        if auth.verify_password(pw, stored_hash, stored_salt):
            auth.reset_login_lockout()
            db.log("MASTER_LOGIN_SUCCESS")
            self._on_success()
        else:
            now_locked, secs = auth.record_login_failure()
            db.log("MASTER_LOGIN_FAILED", details="Wrong master password", success=False)
            if now_locked:
                m, s = secs // 60, secs % 60
                self._err.configure(text=f"⚠  Too many attempts. Locked {m}m {s}s.")
                self._check_lockout()
            else:
                _, _, attempts = auth.get_login_status()
                left = auth.MAX_LOGIN_TRIES - attempts
                self._err.configure(text=f"⚠  Wrong password. {left} attempt(s) left.")
            self._pw_var.set("")


# ══════════════════════════════════════════════════════════════════════════════
#  Dashboard
# ══════════════════════════════════════════════════════════════════════════════

class DashboardFrame(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=BG, corner_radius=0)
        self._all_folders: list[Path] = []
        self._search_var  = ctk.StringVar()
        self._sort_var    = ctk.StringVar(value="Date Added")
        self._build()
        self.after(100, self.refresh)

    def _build(self):
        # ── Sidebar ──────────────────────────────────────────────────────────
        sb = ctk.CTkFrame(self, width=236, fg_color=SURF, corner_radius=0)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)

        logo = ctk.CTkFrame(sb, fg_color="transparent")
        logo.pack(fill="x", padx=20, pady=(24, 0))
        ib = ctk.CTkFrame(logo, width=44, height=44, corner_radius=10, fg_color=INDIGO)
        ib.pack(side="left")
        ib.pack_propagate(False)
        ctk.CTkLabel(ib, text="📁", font=ctk.CTkFont(size=20),
                     text_color="white").place(relx=.5, rely=.42, anchor="center")
        ctk.CTkLabel(ib, text="🔒", font=ctk.CTkFont(size=11),
                     text_color="white").place(relx=.5, rely=.76, anchor="center")
        tc = ctk.CTkFrame(logo, fg_color="transparent")
        tc.pack(side="left", padx=10)
        ctk.CTkLabel(tc, text="Hidec",
                     font=ctk.CTkFont(family=FONT, size=15, weight="bold"),
                     text_color=TXT).pack(anchor="w")
        ctk.CTkLabel(tc, text="Secure & Protect",
                     font=ctk.CTkFont(family=FONT, size=9), text_color=MUTED).pack(anchor="w")

        ctk.CTkFrame(sb, height=1, fg_color=BDR).pack(fill="x", padx=20, pady=18)

        ctk.CTkButton(sb, text="＋   Add Folder", height=40, anchor="w",
                      fg_color=INDIGO, hover_color=IND_DK, corner_radius=8,
                      font=ctk.CTkFont(family=FONT, size=13, weight="bold"),
                      command=self._add_folder).pack(fill="x", padx=20)

        ctk.CTkFrame(sb, height=1, fg_color=BDR).pack(fill="x", padx=20, pady=18)

        ctk.CTkLabel(sb, text="THEME",
                     font=ctk.CTkFont(family=FONT, size=9, weight="bold"),
                     text_color=MUTED).pack(anchor="w", padx=20)
        self._theme_var = ctk.StringVar(value="Dark")
        for label, val in [("Dark  (default)", "Dark"),
                            ("Light", "Light"),
                            ("System", "System")]:
            ctk.CTkRadioButton(sb, text=label, variable=self._theme_var, value=val,
                               font=ctk.CTkFont(family=FONT, size=12),
                               text_color=TXT, fg_color=INDIGO, border_color=BDR,
                               command=lambda v=val: ctk.set_appearance_mode(v)
                               ).pack(anchor="w", padx=24, pady=3)

        ctk.CTkFrame(sb, height=1, fg_color=BDR).pack(fill="x", padx=20, pady=14)

        info = ctk.CTkFrame(sb, fg_color=CARD, corner_radius=8)
        info.pack(fill="x", padx=20)
        ctk.CTkLabel(info, text="🛡  AES-256-GCM",
                     font=ctk.CTkFont(family=FONT, size=11, weight="bold"),
                     text_color=IND_GL).pack(anchor="w", padx=12, pady=(10, 2))
        ctk.CTkLabel(info, text="PBKDF2-SHA256  ·  600k iter\n5-attempt PIN lockout",
                     font=ctk.CTkFont(family=FONT, size=9),
                     text_color=MUTED, justify="left").pack(anchor="w", padx=12, pady=(0, 10))

        # Bottom sidebar buttons
        ctk.CTkFrame(sb, height=1, fg_color=BDR).pack(fill="x", padx=20, pady=14)

        ctk.CTkButton(sb, text="⚙  Settings", height=32,
                      fg_color="transparent", border_width=1, border_color=BDR,
                      text_color=MUTED, hover_color=CARD2,
                      font=ctk.CTkFont(family=FONT, size=11),
                      command=self._open_settings).pack(fill="x", padx=20, pady=(0, 6))

        ctk.CTkButton(sb, text="📋  Activity Log", height=32,
                      fg_color="transparent", border_width=1, border_color=BDR,
                      text_color=MUTED, hover_color=CARD2,
                      font=ctk.CTkFont(family=FONT, size=11),
                      command=self._show_log).pack(fill="x", padx=20)

        # ── Main area ─────────────────────────────────────────────────────────
        main = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        main.pack(side="left", fill="both", expand=True)

        hdr = ctk.CTkFrame(main, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(22, 0))
        ctk.CTkLabel(hdr, text="My Protected Folders",
                     font=ctk.CTkFont(family=FONT, size=22, weight="bold"),
                     text_color=TXT).pack(side="left")
        self._count_lbl = ctk.CTkLabel(hdr, text="",
                                        font=ctk.CTkFont(family=FONT, size=11),
                                        text_color=MUTED)
        self._count_lbl.pack(side="right")

        self._stats = ctk.CTkFrame(main, fg_color="transparent")
        self._stats.pack(fill="x", padx=24, pady=(6, 0))

        bar = ctk.CTkFrame(main, fg_color="transparent")
        bar.pack(fill="x", padx=24, pady=(12, 0))
        ctk.CTkEntry(bar, textvariable=self._search_var,
                     placeholder_text="🔍  Search by folder name or path…",
                     height=36, font=ctk.CTkFont(family=FONT, size=12),
                     border_color=BDR, fg_color=CARD2).pack(
                         side="left", fill="x", expand=True, padx=(0, 10))
        self._search_var.trace_add("write", lambda *_: self._apply_filter())

        ctk.CTkLabel(bar, text="Sort:", font=ctk.CTkFont(family=FONT, size=11),
                     text_color=MUTED).pack(side="left", padx=(0, 4))
        ctk.CTkOptionMenu(bar, values=["Date Added", "Name A–Z", "Locked first"],
                          variable=self._sort_var, width=140, height=36,
                          fg_color=CARD2, button_color=CARD2, button_hover_color=BDR,
                          font=ctk.CTkFont(family=FONT, size=11),
                          command=lambda _: self._apply_filter()).pack(side="left")

        self._scroll = ctk.CTkScrollableFrame(main, fg_color="transparent")
        self._scroll.pack(fill="both", expand=True, padx=24, pady=12)

    # ── Stats ─────────────────────────────────────────────────────────────────

    def refresh_stats(self):
        for w in self._stats.winfo_children():
            w.destroy()
        locked_n   = sum(1 for f in self._all_folders if folder_is_locked(f))
        unlocked_n = len(self._all_folders) - locked_n

        def pill(icon, text, fg, text_color):
            p = ctk.CTkFrame(self._stats, fg_color=fg, corner_radius=6)
            p.pack(side="left", padx=(0, 8))
            ctk.CTkLabel(p, text=f"{icon} {text}",
                         font=ctk.CTkFont(family=FONT, size=11, weight="bold"),
                         text_color=text_color).pack(padx=10, pady=4)

        if locked_n:   pill("🔒", f"{locked_n} Locked",   RED_MUTED,   RED)
        if unlocked_n: pill("📂", f"{unlocked_n} Unlocked", GREEN_MUTED, GREEN)
        if not self._all_folders:
            ctk.CTkLabel(self._stats, text="Add a folder to get started",
                         font=ctk.CTkFont(family=FONT, size=11),
                         text_color=MUTED).pack(side="left")

    # ── Folder list ───────────────────────────────────────────────────────────

    def refresh(self):
        rows = db.get_all_folders()
        self._all_folders = [Path(r["original_path"]) for r in rows
                             if Path(r["original_path"]).exists()]
        # Also show missing-from-disk folders with a warning
        missing = [Path(r["original_path"]) for r in rows
                   if not Path(r["original_path"]).exists()]
        if missing:
            for m in missing:
                db.log("FOLDER_MISSING", m.name, "Folder not found on disk", success=False)
        self.refresh_stats()
        self._apply_filter()
        n = len(self._all_folders)
        self._count_lbl.configure(text=f"{n} folder{'s' if n != 1 else ''}" if n else "")

    def _apply_filter(self):
        query = self._search_var.get().lower().strip()
        sort  = self._sort_var.get()
        folders = [f for f in self._all_folders
                   if query in f.name.lower() or query in str(f).lower()]
        if sort == "Name A–Z":
            folders.sort(key=lambda f: f.name.lower())
        elif sort == "Locked first":
            folders.sort(key=lambda f: (0 if folder_is_locked(f) else 1, f.name.lower()))
        self._render_list(folders)

    def _render_list(self, folders: list[Path]):
        for w in self._scroll.winfo_children():
            w.destroy()
        if not folders:
            self._show_empty()
            return

        locked_f   = [f for f in folders if folder_is_locked(f)]
        unlocked_f = [f for f in folders if not folder_is_locked(f)]

        def section(icon, label, color, count):
            row = ctk.CTkFrame(self._scroll, fg_color="transparent")
            row.pack(fill="x", pady=(14, 4))
            ctk.CTkLabel(row, text=f"{icon}  {label}",
                         font=ctk.CTkFont(family=FONT, size=12, weight="bold"),
                         text_color=color).pack(side="left")
            ctk.CTkLabel(row, text=f"({count})",
                         font=ctk.CTkFont(family=FONT, size=11),
                         text_color=MUTED).pack(side="left", padx=6)
            ctk.CTkFrame(row, height=1, fg_color=BDR).pack(
                side="left", fill="x", expand=True, padx=(4, 0))

        if locked_f:
            section("🔒", "LOCKED & ENCRYPTED", RED, len(locked_f))
            for f in locked_f:
                FolderCard(self._scroll, f, self).pack(fill="x", pady=4)
        if unlocked_f:
            section("📂", "UNLOCKED FOLDERS", GREEN, len(unlocked_f))
            for f in unlocked_f:
                FolderCard(self._scroll, f, self).pack(fill="x", pady=4)

    def _show_empty(self):
        empty = ctk.CTkFrame(self._scroll, fg_color=SURF, corner_radius=14,
                              border_width=1, border_color=BDR)
        empty.pack(fill="both", expand=True, pady=20)
        ctk.CTkLabel(empty, text="📁",
                     font=ctk.CTkFont(size=52), text_color=INDIGO).pack(pady=(48, 0))
        ctk.CTkLabel(empty, text="🔒",
                     font=ctk.CTkFont(size=24), text_color=IND_GL).pack(pady=(0, 8))
        ctk.CTkLabel(empty, text="No folders added yet",
                     font=ctk.CTkFont(family=FONT, size=15, weight="bold"),
                     text_color=TXT).pack()
        ctk.CTkLabel(empty,
                     text='Click  "+ Add Folder"  in the sidebar to get started',
                     font=ctk.CTkFont(family=FONT, size=11),
                     text_color=MUTED).pack(pady=(4, 48))

    # ── Actions ───────────────────────────────────────────────────────────────

    def _add_folder(self):
        path = filedialog.askdirectory(title="Select folder to protect")
        if not path:
            return
        folder = Path(path)
        if folder in self._all_folders:
            messagebox.showinfo("Already Added", "This folder is already in Hidec.")
            return
        if not folder.exists():
            messagebox.showerror("Not Found", "The selected folder does not exist.")
            return
        db.add_folder(folder)
        db.log("FOLDER_ADDED", folder.name, str(folder))
        self.refresh()

    def _open_settings(self):
        SettingsDialog(self.winfo_toplevel())

    def _show_log(self):
        LogDialog(self.winfo_toplevel())


# ══════════════════════════════════════════════════════════════════════════════
#  App — orchestrates Setup → Login → Dashboard + auto-lock
# ══════════════════════════════════════════════════════════════════════════════

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Hidec")
        self.geometry("960x680")
        self.minsize(780, 560)
        self.configure(fg_color=BG)

        db.init_db()
        db.backup()
        db.log("APP_START", details=f"Started · {_now_str()}")

        self._current_frame: ctk.CTkFrame | None = None
        self._last_activity = time.time()
        self._lock_job: str | None = None

        # Reset activity on any mouse/key event
        self.bind_all("<Motion>",     self._reset_activity)
        self.bind_all("<KeyPress>",   self._reset_activity)
        self.bind_all("<ButtonPress>", self._reset_activity)

        if db.is_first_run():
            self._show_setup()
        else:
            self._show_login()

    def _reset_activity(self, event=None):
        self._last_activity = time.time()

    def _start_lock_timer(self):
        if self._lock_job:
            self.after_cancel(self._lock_job)
        self._lock_job = self.after(15_000, self._check_auto_lock)

    def _check_auto_lock(self):
        timeout = int(db.get_config("auto_lock_timeout", "300"))
        if (timeout > 0
                and isinstance(self._current_frame, DashboardFrame)
                and time.time() - self._last_activity >= timeout):
            db.log("AUTO_LOCK", details="Session auto-locked due to inactivity")
            self._show_login(auto_locked=True)
        else:
            self._lock_job = self.after(15_000, self._check_auto_lock)

    def _swap(self, frame: ctk.CTkFrame):
        if self._current_frame:
            self._current_frame.destroy()
        self._current_frame = frame
        frame.pack(fill="both", expand=True)

    def _show_setup(self):
        if self._lock_job:
            self.after_cancel(self._lock_job)
        self._swap(SetupFrame(self, on_done=self._show_login))

    def _show_login(self, auto_locked: bool = False):
        if self._lock_job:
            self.after_cancel(self._lock_job)
            self._lock_job = None
        self._swap(LoginFrame(self, on_success=self._show_dashboard,
                               auto_locked=auto_locked))

    def _show_dashboard(self):
        self._swap(DashboardFrame(self))
        self._last_activity = time.time()
        self._start_lock_timer()


if __name__ == "__main__":
    app = App()
    app.mainloop()

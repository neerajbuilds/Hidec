# FolderLock

A Windows 11 folder-encryption tool with a PIN. Encrypts every file in a folder using **AES-256-GCM**. PINs are never stored — only a PBKDF2-SHA256 hash (600 000 iterations) is saved inside the vault.

---

## Features

| Feature | Detail |
|---|---|
| Encryption | AES-256-GCM (authenticated encryption) |
| Key derivation | PBKDF2-HMAC-SHA256, 600 000 iterations, 32-byte random salt per vault |
| PIN storage | Salted PBKDF2 hash only — PIN is never stored in plaintext |
| Per-file nonce | 12-byte random nonce per file — identical files encrypt differently |
| Modern GUI | CustomTkinter — supports Windows 11 light & dark mode |
| Threading | Encryption/decryption runs off the UI thread — progress bar stays live |

---

## Quick Start (run from source)

```
# Requires Python 3.11+
pip install -r requirements.txt
python main.py
```

---

## Build .exe on Windows

**Option A — with a custom icon (requires `assets/icon.ico`):**
```
build.bat
```

**Option B — no icon required:**
```
build_no_icon.bat
```

The finished executable will be at `dist\FolderLock.exe`.  
It is a single self-contained file — no Python installation needed to run it.

---

## How it works

1. **Add Folder** — select any folder on your PC.
2. **Lock & Encrypt** — set a 4–12 digit PIN. Every file inside (recursively) is encrypted and renamed with a `.locked` extension. The original files are deleted.
3. **Unlock** — enter the correct PIN. Files are decrypted and restored to their original names and content.

### File format (`.locked`)

```
[ 32 bytes ] random PBKDF2 salt
[ 12 bytes ] AES-GCM nonce
[  2 bytes ] original filename length (big-endian uint16)
[  N bytes ] original filename (UTF-8)
[  R bytes ] AES-256-GCM ciphertext + 16-byte GCM auth tag
```

The GCM auth tag protects against tampering — decryption will fail if even a single byte is modified.

---

## Security notes

- The `--onefile` PyInstaller build bundles the Python runtime; antivirus software may flag it. Add an exclusion for `FolderLock.exe` if needed.
- FolderLock does **not** prevent deletion of encrypted files — use Windows file permissions or a separate backup for critical data.
- If you forget your PIN, your files **cannot be recovered**. There is no backdoor.

---

## Requirements (source)

```
customtkinter>=5.2.2
cryptography>=42.0.0
Pillow>=10.0.0
pyinstaller>=6.0.0   # build only
```

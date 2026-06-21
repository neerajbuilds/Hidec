"""
AES-256-GCM encryption/decryption for folder lock application.
Each file gets a unique random nonce; the encrypted payload includes
the nonce prepended so decryption is self-contained.
"""

import os
import struct
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_SIZE = 32
NONCE_SIZE = 12
KDF_ITERATIONS = 600_000
ENCRYPTED_EXTENSION = ".locked"


def derive_key(pin: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(pin.encode("utf-8"))


def encrypt_file(filepath: Path, pin: str) -> Path:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(pin, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)

    plaintext = filepath.read_bytes()
    original_name = filepath.name.encode("utf-8")
    name_len = struct.pack(">H", len(original_name))

    associated_data = name_len + original_name
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    out_path = filepath.with_suffix(filepath.suffix + ENCRYPTED_EXTENSION)
    with open(out_path, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(name_len)
        f.write(original_name)
        f.write(ciphertext)

    filepath.unlink()
    return out_path


def decrypt_file(filepath: Path, pin: str) -> Path:
    with open(filepath, "rb") as f:
        salt = f.read(SALT_SIZE)
        nonce = f.read(NONCE_SIZE)
        name_len = struct.unpack(">H", f.read(2))[0]
        original_name = f.read(name_len).decode("utf-8")
        ciphertext = f.read()

    key = derive_key(pin, salt)
    aesgcm = AESGCM(key)

    associated_data = struct.pack(">H", name_len) + original_name.encode("utf-8")
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)

    out_path = filepath.parent / original_name
    out_path.write_bytes(plaintext)
    filepath.unlink()
    return out_path


EXCLUDED_FILES = {".vaultmeta", ".lockout"}


def encrypt_folder(folder: Path, pin: str, progress_cb=None):
    files = [f for f in folder.rglob("*") if f.is_file() and not f.suffix.endswith(ENCRYPTED_EXTENSION) and f.name not in EXCLUDED_FILES]
    total = len(files)
    for i, f in enumerate(files):
        encrypt_file(f, pin)
        if progress_cb:
            progress_cb(i + 1, total)
    return total


def decrypt_folder(folder: Path, pin: str, progress_cb=None):
    files = [f for f in folder.rglob("*") if f.is_file() and f.suffix.endswith(ENCRYPTED_EXTENSION)]
    total = len(files)
    for i, f in enumerate(files):
        decrypt_file(f, pin)
        if progress_cb:
            progress_cb(i + 1, total)
    return total


def folder_is_locked(folder: Path) -> bool:
    return any(f.suffix.endswith(ENCRYPTED_EXTENSION) for f in folder.rglob("*") if f.is_file())

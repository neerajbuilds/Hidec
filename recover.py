"""
One-time recovery script: restores the encrypted .vaultmeta file
so the main app can verify the PIN again.
Run once, then use FolderLock normally to unlock.
"""
import sys
import struct
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_SIZE = 32
NONCE_SIZE = 12
KDF_ITERATIONS = 600_000

def derive_key(pin: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERATIONS)
    return kdf.derive(pin.encode("utf-8"))

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

if len(sys.argv) != 3:
    print("Usage: py recover.py \"C:\\path\\to\\your\\folder\" YOUR_PIN")
    sys.exit(1)

folder = Path(sys.argv[1])
pin = sys.argv[2]

meta_locked = folder / ".vaultmeta.locked"
if not meta_locked.exists():
    print("No .vaultmeta.locked found — nothing to recover.")
    sys.exit(0)

try:
    recovered = decrypt_file(meta_locked, pin)
    print(f"Recovered: {recovered}")
    print("Done! Now open FolderLock, add your folder, and unlock with your PIN.")
except Exception as e:
    print(f"Failed — PIN may be wrong or file is corrupted: {e}")

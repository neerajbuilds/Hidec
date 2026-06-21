"""
Emergency unlock script — decrypts ALL .locked files in a folder.
Usage: py unlock_all.py "C:\Your Folder" YOUR_PIN
"""
import sys
import struct
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

if len(sys.argv) != 3:
    print('Usage: py unlock_all.py "C:\\Your Folder" YOUR_PIN')
    sys.exit(1)

folder = Path(sys.argv[1])
pin = sys.argv[2]

files = [f for f in folder.rglob("*") if f.is_file() and f.name.endswith(".locked")]
print(f"Found {len(files)} locked file(s) in {folder}")

ok = 0
fail = 0
for f in files:
    try:
        data = f.read_bytes()
        salt = data[:32]
        nonce = data[32:44]
        nl = struct.unpack(">H", data[44:46])[0]
        name = data[46:46+nl].decode()
        ct = data[46+nl:]
        key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=salt, iterations=600000).derive(pin.encode())
        pt = AESGCM(key).decrypt(nonce, ct, data[44:46] + name.encode())
        out = f.parent / name
        out.write_bytes(pt)
        f.unlink()
        print(f"  Unlocked: {name}")
        ok += 1
    except Exception as e:
        print(f"  FAILED: {f.name} — {e}")
        fail += 1

print(f"\nDone. {ok} unlocked, {fail} failed.")
if fail > 0:
    print("Failed files may have a different PIN or be corrupted.")

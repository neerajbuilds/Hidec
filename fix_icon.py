"""
Finds any image file inside the assets/ folder (regardless of its name
or extension - even a mislabeled .ico that's secretly a .png) and
converts it into a proper, multi-resolution .ico file that Windows
and PyInstaller will actually recognize as an icon.
"""
from pathlib import Path
from PIL import Image
import sys

ASSETS = Path(__file__).parent / "assets"

if not ASSETS.exists():
    print(f"ERROR: 'assets' folder not found at {ASSETS}")
    print("Create a folder named 'assets' next to this script first.")
    sys.exit(1)

source = None
for f in sorted(ASSETS.iterdir()):
    if not f.is_file():
        continue
    try:
        img = Image.open(f)
        img.verify()
        source = f
        break
    except Exception:
        continue

if source is None:
    print("ERROR: No valid image file found inside the 'assets' folder.")
    print("Put your icon picture (any image file) inside assets/ and run this again.")
    sys.exit(1)

print(f"Found image: {source.name}")

img = Image.open(source).convert("RGBA")
out_path = ASSETS / "icon.ico"
sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
img.save(out_path, format="ICO", sizes=sizes)

print(f"Created a real .ico file: {out_path}")
print("Done! Now run build.bat (or build_no_icon.bat) to rebuild your app.")

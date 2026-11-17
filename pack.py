"""
Make a clean copy of Squidbrake to put on a server or a friend's PC:  python pack.py
-> dist/squidbrake.zip  (everything except your keys, history and local Python environment)
"""
import zipfile
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
SKIP_DIRS = {".venv", "data", "dist", "__pycache__", ".pytest_cache", ".git", "squidbreak-site"}
SKIP_FILES = {".env"}


def private(name: str) -> bool:
    """Your own files: MY_KEYS.txt, MY_CLOUD_KEYS.txt, MY_SERVER.md, ... (anything starting with MY_), and .env files."""
    return name.upper().startswith("MY_") or name in SKIP_FILES or (name.startswith(".env") and name != ".env.example")

out = BASE / "dist" / "squidbrake.zip"
out.parent.mkdir(exist_ok=True)
count = 0
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for p in sorted(BASE.rglob("*")):
        rel = p.relative_to(BASE)
        if p.is_dir() or rel.parts[0] in SKIP_DIRS or any(part in SKIP_DIRS for part in rel.parts) or private(p.name) \
                or p.suffix in (".pyc", ".bak") or ".bak-" in p.name:
            continue
        info = zipfile.ZipInfo(f"squidbrake/{rel.as_posix()}", datetime.fromtimestamp(p.stat().st_mtime).timetuple()[:6])
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (0o755 if p.suffix == ".sh" else 0o644) << 16  # keep scripts runnable on Linux/macOS
        z.writestr(info, p.read_bytes())
        count += 1
print(f"{out}  ({count} files, {out.stat().st_size // 1024} KB) - no keys, no history")

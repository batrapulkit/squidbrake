"""Add "Install this version" to a GitHub release's notes, once (a marker keeps it from being added twice).

    python .github/scripts/install_notes.py v0.8.0          # prints the new notes; the workflow passes them to gh
"""
import subprocess
import sys

MARK = "<!-- install-this-version -->"
REPO = "batrapulkit/squidbrake"
SERVER = "https://pilots.squidbrake.com"


def block(version: str) -> str:
    return f"""{MARK}
### Install this version ({version})

Windows (PowerShell):
```powershell
$env:SQUIDBRAKE_VERSION="{version}"; irm {SERVER}/install.ps1 | iex
```
macOS / Linux:
```bash
curl -fsSL {SERVER}/install.sh | SQUIDBRAKE_VERSION={version} sh
```
With pip: `pip install squidbrake=={version}` · Docker: `docker pull ghcr.io/{REPO}:{version}`

Running the line again without `SQUIDBRAKE_VERSION` goes back to the newest. Every version:
https://github.com/{REPO}/releases
"""


def notes(tag: str, body: str) -> str | None:
    """The notes with the install block added, or None if they already have it."""
    if MARK in body:
        return None
    return body.rstrip() + "\n\n" + block(tag.lstrip("v")) + "\n"


def main(tag: str) -> int:
    body = subprocess.run(["gh", "release", "view", tag, "--repo", REPO, "--json", "body", "-q", ".body"],
                          capture_output=True, text=True, check=True).stdout
    new = notes(tag, body)
    if new is None:
        print(f"{tag}: already has the install block")
        return 0
    subprocess.run(["gh", "release", "edit", tag, "--repo", REPO, "--notes-file", "-"], input=new, text=True, check=True)
    print(f"{tag}: added the install block")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

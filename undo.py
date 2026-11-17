"""
An undo for what an agent deletes or overwrites on this machine.

Right before an allowed command runs, the hook keeps a copy of what it would destroy:

  rm -r / Remove-Item / rmdir /s / del   the files and folders it names (copied to ~/.squidbrake/undo/ID)
  git reset --hard, checkout --, restore uncommitted changes, kept as a git stash commit under refs/squidbrake/undo/ID
  git clean -f                           the untracked files it would delete (copied, like a delete)

  squidbrake undo              lists the last backups (newest first)
  squidbrake undo ID           puts one back: missing files are restored, files changed since are left alone
                               (--force overwrites them); git changes are re-applied with `git stash apply`

Build outputs and caches (node_modules, dist, .venv...) are rebuilt by the next build, so they aren't copied.
A backup is skipped when it would be bigger than MAX_FILES files or MAX_BYTES; the agent is told it was skipped.
Backups older than KEEP_DAYS are removed. Nothing here sends anything anywhere.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import commands
import effects

MAX_FILES = 5000
MAX_BYTES = 500 * 1024 * 1024
KEEP_DAYS = 14
GIT_OVERWRITES = ("reset", "checkout", "restore")


def store() -> Path:
    return Path(os.getenv("SQUIDBRAKE_HOME") or Path.home() / ".squidbrake") / "undo"


def _git(cwd: str, *args: str) -> str | None:
    try:
        r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=10,
                           env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def _new_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S-") + os.urandom(2).hex()


def _regenerable(p: Path) -> bool:
    return p.name in commands.REGENERABLE


def _stored_name(p: Path) -> str:
    """Where a file's copy lives inside the backup: its absolute path, made safe for a folder name."""
    s = str(p.resolve())
    return s.replace(":", "").lstrip("\\/")


def _git_targets(words: list[str]) -> bool:
    sub = words[1] if len(words) > 1 else ""
    if sub == "reset":
        return "--hard" in words
    if sub == "checkout":
        return "--" in words or "." in words[2:]
    return sub == "restore" and not ("--staged" in words and "--worktree" not in words)


def _clean_files(words: list[str], cwd: str) -> list[Path]:
    if not any(w == "--force" or (w.startswith("-") and not w.startswith("--") and "f" in w) for w in words[2:]):
        return []  # without -f git clean deletes nothing
    flags = []
    for f in [w for w in words[2:] if w.startswith("-")]:
        if not f.startswith("--"):
            rest = "".join(c for c in f[1:] if c not in "fni")
            if rest:
                flags.append("-" + rest)
    out = _git(cwd, "clean", "-n", *flags, *[w for w in words[2:] if not w.startswith("-")]) or ""
    return [Path(cwd) / l.removeprefix("Would remove ").strip() for l in out.splitlines() if l.strip()]


def snapshot(line: str, cwd: str | None = None) -> dict | None:
    """Back up what this command line would destroy. Returns the backup's manifest, or None if nothing to keep.
    Never raises: a backup that can't be made must not stop the agent (the decision was already made)."""
    try:
        return _snapshot(line, cwd or os.getcwd())
    except Exception as e:  # pragma: no cover - best effort by design
        return {"skipped": f"backup failed ({e.__class__.__name__})"}


def _snapshot(line: str, cwd: str) -> dict | None:
    reading = commands.read(line)
    paths: list[Path] = []
    git_repos: list[str] = []
    for cmd in reading.commands:
        if cmd.program == "git" and len(cmd.words) > 1:
            if cmd.words[1] == "clean":
                paths += _clean_files(cmd.words, cwd)
            elif _git_targets(cmd.words):
                git_repos.append(cwd)
        else:
            paths += [p for p in effects.delete_targets(cmd, cwd) if not _regenerable(p)]
    return _keep(paths, git_repos, cwd, line)


def snapshot_files(paths: list[str], cwd: str | None = None, what: str = "edit") -> dict | None:
    """Back up files an agent is about to overwrite or edit (Claude Code's Write / Edit). Files that don't exist yet
    have nothing to keep. Never raises; restore with `squidbrake undo ID --force` (the file exists again)."""
    try:
        cwd = cwd or os.getcwd()
        found = [p for p in (Path(cwd) / x if not Path(x).is_absolute() else Path(x) for x in paths if x)
                 if p.is_file() and not p.is_symlink()]
        return _keep(found, [], cwd, f"{what}: {', '.join(str(p) for p in found)}") if found else None
    except Exception as e:  # pragma: no cover - best effort by design
        return {"skipped": f"backup failed ({e.__class__.__name__})"}


def _keep(paths: list[Path], git_repos: list[str], cwd: str, line: str) -> dict | None:
    if not paths and not git_repos:
        return None
    files, size, complete = effects.walk(paths, time.monotonic() + 5)
    if not complete or files > MAX_FILES or size > MAX_BYTES:
        return {"skipped": f"too big to back up ({files:,}{'+' if not complete else ''} files, "
                           f"{effects._size(size)}); limit {MAX_FILES:,} files / {effects._size(MAX_BYTES)}"}
    bid = _new_id()
    root = store() / bid
    manifest: dict = {"id": bid, "created": datetime.now().isoformat(timespec="seconds"), "cwd": cwd,
                      "command": line[:2000], "files": [], "git": []}
    for p in paths:
        dest = root / "files" / _stored_name(p)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if p.is_dir() and not p.is_symlink():
            shutil.copytree(p, dest, symlinks=True, dirs_exist_ok=True)
        else:
            shutil.copy2(p, dest, follow_symlinks=False)
        manifest["files"].append({"path": str(p.resolve()), "stored": _stored_name(p), "dir": p.is_dir()})
    for repo in dict.fromkeys(git_repos):
        top = _git(repo, "rev-parse", "--show-toplevel")
        if not top:
            continue
        head = _git(top, "rev-parse", "HEAD")
        sha = _git(top, "stash", "create")  # a commit of the uncommitted changes; the work tree is untouched
        if sha:
            _git(top, "update-ref", f"refs/squidbrake/undo/{bid}", sha)  # keeps it from being garbage-collected
        manifest["git"].append({"repo": top, "stash": sha or None, "head": head})
    if not manifest["files"] and not any(g["stash"] or g["head"] for g in manifest["git"]):
        return None
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    prune()
    return manifest


def describe(m: dict) -> str:
    """One line for the agent / the person: what was kept and how to get it back."""
    if m.get("skipped"):
        return f"Squidbrake: no undo for this one, {m['skipped']}."
    what = []
    if m["files"]:
        what.append(f"{len(m['files'])} path{'s' if len(m['files']) != 1 else ''}")
    if any(g["stash"] for g in m["git"]):
        what.append("your uncommitted changes")
    if not what:
        what.append("the commit you were on")
    return f"Squidbrake backed up {' and '.join(what)} first. To undo: squidbrake undo {m['id']}"


def prune(now: float | None = None) -> None:
    cutoff = (now or time.time()) - KEEP_DAYS * 86400
    for d in store().glob("*"):
        try:
            if d.is_dir() and d.stat().st_mtime < cutoff:
                shutil.rmtree(d, ignore_errors=True)
        except OSError:
            pass


def backups() -> list[dict]:
    out = []
    for f in store().glob("*/manifest.json"):
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
    return sorted(out, key=lambda m: m["id"], reverse=True)


def restore(bid: str, force: bool = False) -> list[str]:
    """Put a backup back. Returns what happened, line by line."""
    root = store() / bid
    try:
        m = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ValueError(f"no backup '{bid}' (see: squidbrake undo)")
    out = []
    for f in m["files"]:
        src, dest = root / "files" / f["stored"], Path(f["path"])
        if not src.exists():
            out.append(f"missing from the backup: {dest}")
            continue
        if src.is_dir():
            restored = kept = 0
            for s in src.rglob("*"):
                if s.is_dir():
                    continue
                d = dest / s.relative_to(src)
                if d.exists() and not force:
                    kept += 1
                    continue
                d.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(s, d, follow_symlinks=False)
                restored += 1
            out.append(f"restored {restored} file{'s' if restored != 1 else ''} in {dest}"
                       + (f" ({kept} already there, left alone; --force overwrites)" if kept else ""))
        elif dest.exists() and not force:
            out.append(f"left alone, it exists again: {dest} (--force overwrites)")
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest, follow_symlinks=False)
            out.append(f"restored {dest}")
    for g in m["git"]:
        if g["stash"]:
            ok = _git(g["repo"], "stash", "apply", g["stash"]) is not None
            out.append(f"re-applied your uncommitted changes in {g['repo']}" if ok else
                       f"couldn't re-apply the changes in {g['repo']} cleanly; run: git stash apply {g['stash']}")
        if g["head"]:
            out.append(f"the commit you were on in {g['repo']} was {g['head'][:12]} "
                       f"(git reset --hard {g['head'][:12]} goes back to it)")
    return out


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    force = "--force" in argv
    args = [a for a in argv if a != "--force"]
    if args[:1] in (["-h"], ["--help"]):
        print(__doc__)
        return 0
    if not args or args[0] == "list":
        items = backups()[:20]
        if not items:
            print("No backups yet. Squidbrake keeps one each time an agent deletes or overwrites files.")
            return 0
        for m in items:
            n = len(m["files"]) + sum(1 for g in m["git"] if g["stash"])
            print(f"  {m['id']}  {m['created'].replace('T', ' ')}  {n} item{'s' if n != 1 else ''}  {m['command'][:70]}")
        print("\nUndo one with: squidbrake undo ID")
        return 0
    try:
        for line in restore(args[0], force):
            print(line)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
What an agent does when Squidbrake can't be reached: each rule says (rules.yaml `when_unreachable: block | allow`,
default block), and the agent's computer keeps a copy of those answers so it can follow them while the gateway is down.

  rules.yaml
    when_unreachable: block          # everything not listed below: blocked while the gateway is down (the default)
                                     # block_risky: what the rules allow still runs; anything that would wait for a
                                     # person or be blocked, and commands that can't be undone, are blocked
    rules:
      - id: reads
        action: allow
        when_unreachable: allow      # reading files is fine without the gateway
        match: { name: "Read" }

The hooks (claude_hook.py, agent_hook.py), the MCP connectors (gw_async.py) and client.py fetch the copy from
GET /v1/policy/offline at most every REFRESH_SECONDS while the gateway answers, and keep it in
~/.squidbrake/offline-policy-<gateway>.json. The first matching rule decides, exactly as on the gateway; with no copy
yet, everything is blocked. GATEWAY_FAIL_OPEN=1 on a machine still lets everything through there (the old switch).

What runs while the gateway is down is never recorded by it, so allow only what you'd accept unrecorded.
Standard library only, so it works wherever the hooks do.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

REFRESH_SECONDS = 600
MATCH_FIELDS = ("kind", "name", "source", "client", "session_id")
OPS = {"gt": lambda a, b: a > b, "gte": lambda a, b: a >= b, "lt": lambda a, b: a < b, "lte": lambda a, b: a <= b,
       "eq": lambda a, b: a == b, "ne": lambda a, b: a != b}


def _home() -> Path:
    return Path(os.getenv("SQUIDBRAKE_HOME") or Path.home() / ".squidbrake")


def key_path() -> Path:
    """Agent keys the hooks use, per gateway: ~/.squidbrake/data/hook-keys.json, 600, in the folder agents can't read
    (selfguard.py), so the key isn't in an agent's own settings for it to read."""
    return _home() / "data" / "hook-keys.json"


def save_key(url: str, key: str) -> None:
    path = key_path()
    try:
        keys = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        keys = {}
    keys[url.rstrip("/")] = key
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(keys, f)
    os.replace(tmp, path)
    _private(path)


def load_key(url: str) -> str:
    """The key for this gateway, or "". Says so (stderr) if others on this computer could read the file."""
    path = key_path()
    try:
        if os.name != "nt" and path.stat().st_mode & 0o077:
            import sys
            print(f"Squidbrake: {path} can be read by other users on this computer; run: chmod 600 {path}",
                  file=sys.stderr)
        return str(json.loads(path.read_text(encoding="utf-8")).get(url.rstrip("/")) or "")
    except (OSError, ValueError, AttributeError):
        return ""


def _private(path: Path) -> None:
    """Owner-only: 600 for files, 700 for folders (POSIX; on Windows the user's profile already is)."""
    if os.name == "nt":
        return
    try:
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
    except OSError:
        pass


def cache_path(url: str) -> Path:
    return Path(os.getenv("SQUIDBRAKE_OFFLINE_DIR") or _home()) / f"offline-policy-{hashlib.sha256(url.rstrip('/').encode()).hexdigest()[:10]}.json"


def load(url: str) -> dict | None:
    try:
        return json.loads(cache_path(url).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def save(url: str, policy: dict) -> None:
    path = cache_path(url)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({**policy, "saved_at": time.time()}), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass


def due(url: str) -> bool:
    """Is the saved copy missing or older than REFRESH_SECONDS?"""
    try:
        return time.time() - cache_path(url).stat().st_mtime > REFRESH_SECONDS
    except OSError:
        return True


def refresh(http, url: str) -> None:
    """With the hook's own httpx client, right after the gateway answered: keep the copy fresh. Never raises."""
    flush(http, url)
    if not due(url):
        return
    try:
        r = http.get("/v1/policy/offline", timeout=5)
        if r.status_code == 200:
            save(url, r.json())
    except Exception:
        pass


async def arefresh(http, url: str) -> None:
    if not due(url):
        return
    try:
        r = await http.get("/v1/policy/offline", timeout=5)
        if r.status_code == 200:
            save(url, r.json())
    except Exception:
        pass


def _number(input: Any, field: str) -> float | None:
    if isinstance(input, str):
        try:
            input = json.loads(input)
        except ValueError:
            return None
    for part in field.split("."):
        if not isinstance(input, dict) or part not in input:
            return None
        input = input[part]
    if isinstance(input, bool):
        return None
    try:
        n = float(input)
    except (TypeError, ValueError):
        return None
    return n if n == n else None


def matches(rule: dict, values: dict, input: Any) -> bool:
    m = rule.get("match") or {}
    for f in MATCH_FIELDS:
        if f in m:
            pats = [m[f]] if isinstance(m[f], str) else list(m[f])
            if not any(fnmatch.fnmatchcase((values.get(f) or "").lower(), str(p).lower()) for p in pats):
                return False
    if m.get("input_regex"):
        text = input if isinstance(input, str) else json.dumps(input, default=str, ensure_ascii=False)
        try:
            if not re.search(m["input_regex"], text or "", re.I | re.S):
                return False
        except re.error:
            return False
    for field, ops in (m.get("input") or {}).items():
        n = _number(input, field)
        if n is None or not all(op in OPS and OPS[op](n, v) for op, v in ops.items()):
            return False
    return True


def decide(url: str, *, name: str, kind: str = "tool_call", source: str | None = None, session_id: str | None = None,
           input: Any = None, fail_open: bool = False) -> tuple[bool, str]:
    """(run it?, why) while the gateway at `url` can't be reached."""
    if fail_open:
        return True, "GATEWAY_FAIL_OPEN is set on this computer, so it ran unrecorded"
    pol = load(url)
    if not pol:
        return False, "no copy of the rules' offline settings on this computer yet, so it was blocked"
    try:   # Squidbrake's own keys and approval path stay out of reach while it's down too
        import selfguard
        if (hit := selfguard.check(kind, name, input, None, _home() / "data")) is not None:
            return False, hit["message"]
    except ImportError:
        pass
    values = {"kind": kind, "name": name, "source": source, "client": pol.get("client"), "session_id": session_id}
    for rule in pol.get("rules") or []:
        if matches(rule, values, input):
            wu = rule.get("when_unreachable")
            if wu == "allow":
                return True, f"rule '{rule.get('id')}' says when_unreachable: allow, so it ran unrecorded"
            if wu == "warn":
                return _warn(url, name, kind, source, session_id, input)
            if wu == "block_risky":
                return _risky(pol, rule.get("action"), f"rule '{rule.get('id')}'", name, input)
            return False, f"rule '{rule.get('id')}' says to block it while Squidbrake is unreachable"
    if pol.get("default") == "allow":
        return True, "the rules say when_unreachable: allow, so it ran unrecorded"
    if pol.get("default") == "warn":
        return _warn(url, name, kind, source, session_id, input)
    if pol.get("default") == "block_risky":
        return _risky(pol, pol.get("default_action"), "the default", name, input)
    return False, "the rules block everything while Squidbrake is unreachable (when_unreachable: block)"


def _queue(url: str) -> Path:
    return cache_path(url).with_name(cache_path(url).stem + "-ran-unchecked.jsonl")


def _warn(url: str, name: str, kind: str, source, session_id, input) -> tuple[bool, str]:
    """when_unreachable: warn (opt-in): it runs, loudly, and is put on the record once Squidbrake answers again."""
    try:
        with _queue(url).open("a", encoding="utf-8") as f:
            f.write(json.dumps({"name": name, "kind": kind, "source": source, "session_id": session_id,
                                "input": input, "ran_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}) + "\n")
    except OSError:
        pass
    return True, ("WARNING: SQUIDBRAKE PROTECTION IS OFF. It can't be reached and when_unreachable is warn, so this ran "
                  "unchecked; it goes on the record when Squidbrake is back")


def flush(http, url: str) -> None:
    """Right after the gateway answered: record what ran unchecked while it was down (warn mode). Never raises."""
    q = _queue(url)
    try:
        lines = q.read_text(encoding="utf-8").splitlines() if q.exists() else []
        if not lines:
            return
        q.unlink()
        for line in lines[-500:]:
            ev = json.loads(line)
            http.post("/v1/events", json={**{k: ev.get(k) for k in ("name", "kind", "source", "session_id", "input")},
                                          "output": {"ran_while_squidbrake_was_unreachable": True},
                                          "metadata": {"while_unreachable": True, "ran_at": ev.get("ran_at")}}, timeout=5)
    except Exception:
        pass


def _risky(pol: dict, action: str | None, which: str, name: str, input: Any) -> tuple[bool, str]:
    """when_unreachable: block_risky: what the rules let run without a person still runs (unrecorded); anything that
    would wait for a person, be blocked, or is a command that can't be undone (or can't be read) is blocked."""
    if action != "allow":
        did = {"deny": "block it", "notify": "tell a person"}.get(action, "ask a person")
        return False, f"{which} would {did}, and Squidbrake is unreachable"
    if any(fnmatch.fnmatchcase(name.lower(), t.lower()) for t in pol.get("shell_tools") or []):
        try:
            import commands
            line = commands.command_of(input)
            kind = commands.read(line).kind if line else "other"
        except Exception:
            kind = "hidden"                     # can't read it: treat it as risky
        if kind in ("catastrophic", "irreversible", "hidden", "secret", "rename"):
            return False, f"this command is {kind} and Squidbrake is unreachable, so it was blocked"
    return True, f"{which} allows it and it isn't risky (when_unreachable: block_risky), so it ran unrecorded"

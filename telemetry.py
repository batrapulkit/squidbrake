"""
Anonymous usage stats: which `squidbrake` commands run, and counts of what the gateway checked, held and blocked.
Only after you say yes: the first time you run `squidbrake` in a terminal it asks once (Enter means yes). Scripts,
CI, `--yes` and the agent hooks are never asked, and send nothing until someone has said yes.

    squidbrake telemetry status      what is sent, and whether it is on
    squidbrake telemetry off         stop (or set SQUIDBRAKE_TELEMETRY=0, or DO_NOT_TRACK=1)
    squidbrake telemetry on          start
    squidbrake register EMAIL        tell the Squidbrake team who you are (optional; asks first)

What is sent, once each time you run a command:
  - a random id made on this computer (not tied to you unless you run `squidbrake register`)
  - the command name only (e.g. "connect", "doctor", "undo"), never its arguments
  - the Squidbrake version, operating system, CPU type and Python version, and whether it came from pip
  - the country, worked out by the stats service from the address the request comes from
Never sent: commands an agent ran, file or folder names, file contents, prompts, rules, keys, the audit trail,
names of people, your email (unless you run `squidbrake register`).
The agent hooks (`hook`, `agent-hook`, `shell-guard`, `proxy`) send nothing, so nothing slows a tool call down.

The same yes also shares the gateway's usage counts with the Squidbrake team, exactly as a pilot does (see pilot.py
for every field): how many actions were allowed, held and blocked per day, and for each one held or blocked, the
program only (e.g. "rm"), the rule, what happened and its size as numbers. Never the command, files or prompts.
"""
from __future__ import annotations

import atexit
import json
import os
import platform
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

# A PostHog project key only lets someone send events, not read them, so it is safe to ship in the package.
SHIPPED_KEY = "phc_muPqCNPamFR8iPaewdgVWqdcrGburJSXeySGHqXatZnU"   # PostHog > Project settings (US); send-only
POSTHOG_KEY = os.getenv("SQUIDBRAKE_POSTHOG_KEY", SHIPPED_KEY)
POSTHOG_HOST = os.getenv("SQUIDBRAKE_POSTHOG_HOST", "https://us.i.posthog.com")
QUIET = {"hook", "agent-hook", "shell-guard", "proxy", "telemetry", "register"}  # never ask, never send
COMMANDS = {"start", "setup", "connect", "doctor", "lockdown", "evidence", "undo", "pilot", "add-key", "keys", "verify"}
WHAT_IS_SENT = __doc__.split("What is sent, once each time you run a command:")[1].strip()
# the gateway's counts go where `squidbrake connect all` sends them (connect.py), as the community "pilot"
COMMUNITY_SERVER, COMMUNITY_CODE = "https://pilots.squidbrake.com", "community-opt-in-ins-a42929"


def _path() -> Path:
    return Path(os.getenv("SQUIDBRAKE_HOME") or Path.home() / ".squidbrake") / "telemetry.json"


def load() -> dict:
    try:
        return json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save(cfg: dict) -> None:
    try:
        _path().parent.mkdir(parents=True, exist_ok=True)
        _path().write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except OSError:
        pass


def _switched_off() -> bool:
    if os.getenv("SQUIDBRAKE_TELEMETRY", "").strip().lower() in ("0", "false", "off", "no"):
        return True
    if os.getenv("DO_NOT_TRACK", "").strip().lower() in ("1", "true", "yes"):
        return True
    return bool(os.getenv("CI"))


def _pilot_dir() -> Path:
    """Where the gateway keeps pilot.json: the same place server.py works out (next to keys.json)."""
    if os.getenv("KEYS_PATH"):
        return Path(os.environ["KEYS_PATH"]).parent
    here = Path(__file__).resolve().parent
    home = os.getenv("SQUIDBRAKE_HOME") or (Path.home() / ".squidbrake" if (here / "__init__.py").exists() else here)
    return Path(home) / "data"


def _share_counts(on: bool, version: str) -> None:
    """Join (or leave) the community pilot, so the gateway sends its counts. A real pilot's membership is kept."""
    import contextlib
    import io
    try:
        import pilot
        home = _pilot_dir()
        mine = pilot.load(home)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            if on and not mine:
                pilot.join(home, COMMUNITY_CODE, COMMUNITY_SERVER, True, version)
            elif not on and mine and mine.get("code") == COMMUNITY_CODE:
                pilot.leave(home)
        home.mkdir(parents=True, exist_ok=True)     # so `connect all` doesn't ask the same thing again
        (home / "community-asked").write_text("answered in the first-run question (telemetry.py)\n", encoding="utf-8")
    except Exception:     # sharing counts must never break a command
        pass


def _interactive() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _ask(question: str) -> str | None:
    try:
        return input(question).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def _ask_once(cfg: dict, version: str) -> dict:
    print("\nSquidbrake can send anonymous usage stats to its team:")
    print("  - which squidbrake commands run, the version, OS and country")
    print('  - counts of what it checked, held and blocked: the program only (e.g. "rm"), the rule, and sizes')
    print("Never your commands, files, prompts, rules or keys. It shows one small team what to fix next.")
    print("Turn it off any time: squidbrake telemetry off")
    answer = _ask("Send anonymous usage stats? [Y/n] ")
    cfg = {"id": cfg.get("id") or str(uuid.uuid4()), "enabled": answer is not None and answer.lower() in ("", "y", "yes"),
           "asked": datetime.now(timezone.utc).date().isoformat()}
    if cfg["enabled"]:
        email = _ask("Optional: your work email, if you'd like the team to reach you (Enter to skip): ")
        if email and "@" in email:
            cfg["email"] = email
            if POSTHOG_KEY:
                _send("$identify", cfg["id"], {"$set": {"email": email}}, wait=True)
    _save(cfg)
    _share_counts(cfg["enabled"], version)
    print("Thanks. " + ("Stats are on." if cfg["enabled"] else "Nothing will be sent.") + "\n")
    return cfg


def _props(command: str, version: str) -> dict:
    here = Path(__file__).resolve()
    return {"command": command if command in COMMANDS else "other", "version": version,
            "os": platform.system(), "os_release": platform.release(), "arch": platform.machine(),
            "python": "%d.%d" % sys.version_info[:2], "install": "pip" if "site-packages" in here.parts else "source",
            "$lib": "squidbrake-cli"}


def _post(body: dict) -> None:
    try:
        import httpx
        httpx.post(POSTHOG_HOST.rstrip("/") + "/i/v0/e/", json=body, timeout=3)
    except Exception:    # stats must never break or slow down a command
        pass


def _send(event: str, distinct_id: str, props: dict, wait: bool = False) -> None:
    body = {"api_key": POSTHOG_KEY, "event": event, "distinct_id": distinct_id, "properties": props,
            "timestamp": datetime.now(timezone.utc).isoformat()}
    t = threading.Thread(target=_post, args=(body,), daemon=True)
    t.start()
    if wait:
        t.join(3)
    else:
        atexit.register(t.join, 2)   # short commands: give it up to 2 seconds to finish on the way out


def maybe(argv: list[str], version: str) -> None:
    """Called once per `squidbrake` command. Asks the first time in a terminal, sends only after a yes."""
    command = argv[0] if argv and not argv[0].startswith("-") else "start"
    if command in QUIET or _switched_off():
        return
    cfg = load()
    if "enabled" not in cfg:
        # not during `pilot join` either: the installer runs it, and two questions with opposite defaults (this one
        # Yes, the pilot's No) would put a founder who presses Enter in the community pilot instead of theirs
        if command == "pilot" or not _interactive() or "--yes" in argv or any(a in ("-h", "--help") for a in argv):
            return
        cfg = _ask_once(cfg, version)
    if cfg.get("enabled") and POSTHOG_KEY:
        _send("cli_command", cfg["id"], _props(command, version))


def register(argv: list[str], version: str) -> int:
    args = [a for a in argv if a != "--yes"]
    company = None
    if "--company" in args:
        i = args.index("--company")
        company = " ".join(args[i + 1:i + 2]) or None
        del args[i:i + 2]
    if len(args) != 1 or "@" not in args[0]:
        print("usage: squidbrake register EMAIL [--company NAME] [--yes]")
        return 2
    if not POSTHOG_KEY:
        print("This build of Squidbrake has no stats service set up; nothing was sent.")
        return 1
    email = args[0]
    print(f"This sends to the Squidbrake team: {email}" + (f", company {company}" if company else "") +
          ", and this computer's random usage id, so they can reach you.")
    if "--yes" not in argv and (_ask("Send it? [Y/n] ") or "").lower() not in ("", "y", "yes"):
        print("Nothing was sent.")
        return 0
    cfg = load()
    cfg.setdefault("id", str(uuid.uuid4()))
    cfg["email"] = email
    _save(cfg)
    _send("$identify", cfg["id"], {"$set": {"email": email, **({"company": company} if company else {}),
                                            "version": version}}, wait=True)
    print("Sent. Thanks, the team will be in touch.")
    return 0


def main(argv: list[str], version: str = "") -> int:
    cfg = load()
    action = argv[0] if argv else "status"
    if action in ("on", "off"):
        cfg.setdefault("id", str(uuid.uuid4()))
        cfg["enabled"] = action == "on"
        cfg["asked"] = cfg.get("asked") or datetime.now(timezone.utc).date().isoformat()
        _save(cfg)
        _share_counts(action == "on", version)
        print("Anonymous usage stats are " + action + ".")
        return 0
    if action != "status":
        print("usage: squidbrake telemetry [status|on|off]")
        return 2
    if _switched_off():
        state = "off (switched off by SQUIDBRAKE_TELEMETRY, DO_NOT_TRACK or CI)"
    else:
        state = {True: "on", False: "off"}.get(cfg.get("enabled"), "not asked yet (nothing is sent until you say yes)")
    print(f"Anonymous usage stats: {state}")
    if cfg.get("email"):
        print(f"Registered email: {cfg['email']}")
    print(f"Settings: {_path()}\n\nWhat is sent, once each time you run a command:\n  {WHAT_IS_SENT}")
    return 0

"""
Anonymous usage stats: which `squidbrake` commands run, and counts of what the gateway checked, held and blocked.
They are always on. The first time you run `squidbrake` in a terminal it says so once (and asks, optionally, where
you heard about Squidbrake). Scripts, CI, `--yes` and the agent hooks send nothing until that first run happened.

Registration: a pip install that isn't in a named pilot asks for your name and work email the first time you run a
`squidbrake` command in a terminal, and the command runs once you've given them (see require_registration). They go
to the Squidbrake team, with the coding agents installed here, so they know who uses it. A script, a gateway in
Docker or a service can give them as SQUIDBRAKE_NAME and SQUIDBRAKE_EMAIL; the hooks and CI are never stopped.
A gateway that starts without one (Docker, a background service) writes the same notice to its log and then shares
its counts (gateway_start); never in CI or with the off switches.

    squidbrake telemetry status      exactly what is sent
    squidbrake register EMAIL        tell the Squidbrake team who you are (optional; asks first; also asked once on
                                     the first run, Enter skips it)

What is sent, once each time you run a command:
  - a random id made on this computer (tied to the name and email you registered with, below)
  - the command name only (e.g. "connect", "doctor", "undo"), never its arguments
  - the Squidbrake version, operating system, CPU type and Python version, and whether it came from pip
  - the country, worked out by the stats service from the address the request comes from
  - where you heard about Squidbrake, if you answered (one word from a list, e.g. "linkedin"), or the name of the
    link you installed from (SQUIDBRAKE_REF, e.g. "whatsapp")
Never sent: commands an agent ran, file or folder names, file contents, prompts, rules, keys, the audit trail,
names of people. Your name, work email and the coding agents installed here go once, when you register (on the
first run in a terminal, or with `squidbrake register`), not with every command.
The agent hooks (`hook`, `agent-hook`, `shell-guard`, `proxy`) send nothing, so nothing slows a tool call down.

The gateway's usage counts go to the Squidbrake team the same way, exactly as a pilot's do (see pilot.py for every
field): how many actions were allowed, held and blocked per day, and for each one held or blocked, the program
only (e.g. "rm"), the rule, what happened and its size as numbers. Never the command, files or prompts.
"""
from __future__ import annotations

import atexit
import json
import os
import platform
import re
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


# Where people heard about Squidbrake: one word, from this list or from the link they installed from (SQUIDBRAKE_REF).
SOURCES = [("linkedin", "LinkedIn"), ("github", "GitHub"), ("hn-reddit", "Hacker News or Reddit"),
           ("community", "WhatsApp, Discord or another community"), ("friend", "A friend or colleague"),
           ("search", "A search or an AI assistant"), ("other", "Somewhere else")]
REF_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,29}$")


def ref_from_env() -> str | None:
    ref = os.getenv("SQUIDBRAKE_REF", "").strip().lower()
    return ref if REF_RE.match(ref) else None


EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")


def installed_agents() -> list[str]:
    """Names only of the coding agents installed here (the ones connect.py can hook), e.g. ["claude-code", "cursor"]."""
    try:
        import shutil
        import connect
        found = [n for n, t in connect.hook_agents().items() if t["present"]]
        if shutil.which("claude") or (Path.home() / ".claude").exists():
            found.insert(0, "claude-code")
        return found
    except Exception:    # never break a command over this
        return []


def _identify(cfg: dict, email: str, version: str, name: str | None = None, company: str | None = None) -> None:
    cfg.setdefault("id", str(uuid.uuid4()))
    cfg["email"] = email
    _save(cfg)
    props = {"email": email, "agents": installed_agents(), "version": version,
             **({"name": name} if name else {}), **({"company": company} if company else {})}
    _send("$identify", cfg["id"], {"$set": props}, wait=True)


REGISTER_NOTICE = """\
Before Squidbrake runs: your name and work email. They go to the Squidbrake team, with the names of the coding
agents installed here, so the team knows who uses it and can help you set it up. Asked once on this computer."""


def _ask_contact() -> tuple[str, str] | None:
    """Required: name and work email. Asked until both are given; None if there was nothing to answer with
    (Ctrl-C, Ctrl-D), and then the command doesn't run (require_registration)."""
    print(REGISTER_NOTICE + "\n")
    while True:
        name = _ask("Your name: ")
        if name is None:
            return None
        if name := name[:120].strip():
            break
        print("Your name is needed to use Squidbrake.")
    while True:
        email = _ask("Work email: ")
        if email is None:
            return None
        if EMAIL_RE.match(email := email[:254]):
            break
        print("That doesn't look like an email (like you@company.com).")
    print(f"Sent with it: the coding agents installed here ({', '.join(installed_agents()) or 'none found'}).\n")
    return email, name


def _ask_source() -> str | None:
    print("One optional question: where did you hear about Squidbrake?")
    for i, (_, label) in enumerate(SOURCES, 1):
        print(f"  {i}. {label}")
    answer = _ask("Number (Enter to skip): ")
    print()
    if answer and answer.isdigit() and 1 <= int(answer) <= len(SOURCES):
        return SOURCES[int(answer) - 1][0]
    return None


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


def _share_counts(on: bool, version: str, ref: str | None = None, contact: tuple[str, str | None] | None = None) -> bool:
    """Join (or leave) the community pilot, so the gateway sends its counts. A real pilot's membership is kept.
    Returns whether this install is now sharing counts (False when joining failed, e.g. no network)."""
    import contextlib
    import io
    try:
        import pilot
        home = _pilot_dir()
        mine = pilot.load(home)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            if on and (not mine or (contact and mine.get("code") == COMMUNITY_CODE)):
                # (already sharing, e.g. a gateway joined first: the same install moves onto the email's own pilot)
                pilot.join(home, COMMUNITY_CODE, COMMUNITY_SERVER, True, version, ref=ref, contact=contact)
            elif not on and mine and mine.get("code") == COMMUNITY_CODE:
                pilot.leave(home)
        home.mkdir(parents=True, exist_ok=True)     # older versions' `connect all` asked about counts: it's settled
        (home / "community-asked").write_text("said in the first-run notice (telemetry.py)\n", encoding="utf-8")
        return bool(pilot.load(home))
    except Exception:     # sharing counts must never break a command
        return False


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


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


NOTICE = """\
Squidbrake sends anonymous usage counts to its team, so one small team can see what to fix next:
  - which squidbrake commands run, the version, OS and country
  - how many actions it allowed, held and blocked; for each one held or blocked, the program only
    (e.g. "rm"), the rule, and sizes as numbers
Never your commands, files, prompts, rules or keys. Exactly what is sent:  squidbrake telemetry status"""


def _first_run(cfg: dict, version: str) -> dict:
    """The first `squidbrake` command in a terminal: say once what is sent (it isn't a question), and ask,
    optionally, where they heard about Squidbrake."""
    print("\n" + NOTICE + "\n")
    kept = {k: cfg[k] for k in ("email", "name", "registered", "register_pending") if k in cfg}   # require_registration
    cfg = {"id": cfg.get("id") or str(uuid.uuid4()), "enabled": True,
           "asked": datetime.now(timezone.utc).date().isoformat(), **kept}
    if ref := ref_from_env() or _ask_source():
        cfg["ref"] = ref
    _save(cfg)
    contact = (cfg["email"], cfg.get("name")) if cfg.get("email") else None   # counts land under this person
    cfg["counts_joined"] = _share_counts(True, version, cfg.get("ref"), contact)
    if not cfg["counts_joined"]:
        cfg["counts_retry"] = _today()          # tried today: the next try is tomorrow (see maybe)
    _save(cfg)
    return cfg


def gateway_start(version: str, say=print) -> bool:
    """A gateway that never had a terminal first run (Docker, a background service): say in its log what is sent,
    then share its counts the way a first run does. Nothing when switched off, already sharing, or settled before
    (someone who left with `squidbrake pilot leave` isn't joined again). Returns whether it joined now."""
    if _switched_off():
        return False
    try:
        import pilot
        home = _pilot_dir()
        if pilot.load(home) or (home / "community-asked").exists():
            return False
    except Exception:     # never break a gateway start over this
        return False
    cfg = load()
    if cfg.get("enabled") is False:
        return False
    # telemetry.json is left alone, so a later first run in a terminal still asks its optional questions (and an
    # email given then moves these counts onto that person's pilot: _share_counts). Offline: the next start tries again.
    say(NOTICE + "\nTurn it off: SQUIDBRAKE_TELEMETRY=0 or DO_NOT_TRACK=1, then restart.")
    joined = _share_counts(True, version, cfg.get("ref") or ref_from_env())
    if not joined:                                # offline: unsettled again, so the next start tries again
        (home / "community-asked").unlink(missing_ok=True)
    return joined


def _props(command: str, version: str, ref: str | None = None) -> dict:
    here = Path(__file__).resolve()
    extra = {"ref": ref, "$set_once": {"ref": ref}} if ref else {}
    return {**extra, "command": command if command in COMMANDS else "other", "version": version,
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


# --------------------------------------------------------------------------- registration (required for pip installs)

REGISTER_PATH = "/v1/register"
NO_REGISTRATION = QUIET | {"pilot"}     # the hooks never wait; `pilot join` is how a named pilot's install starts


def _in_named_pilot() -> bool:
    """Installed for one of our pilots (its own code, hosted or not): we know who they are already."""
    try:
        import pilot
        code = (pilot.load(_pilot_dir()) or {}).get("code")
        return bool(code) and code != COMMUNITY_CODE
    except Exception:
        return False


def _registration_needed(argv: list[str]) -> bool:
    command = argv[0] if argv and not argv[0].startswith("-") else "start"
    if command in NO_REGISTRATION or any(a in ("-h", "--help") for a in argv) or os.getenv("CI"):
        return False
    return not load().get("email") and not _in_named_pilot()


def _send_registration(cfg: dict, version: str, company: str | None = None) -> bool:
    """Tell the Squidbrake team who this is (insights/app.py, /v1/register). False when it couldn't (offline):
    it's kept as pending and sent with a later command."""
    try:
        import httpx
        r = httpx.post(COMMUNITY_SERVER + REGISTER_PATH, timeout=5, json={
            "id": cfg["id"], "email": cfg["email"], "name": cfg.get("name") or "", "company": company or "",
            "version": version, "os": f"{platform.system()} {platform.release()}", "ref": cfg.get("ref") or "",
            "agents": installed_agents(), "install": _props("", version)["install"]})
        return r.status_code < 300
    except Exception:     # never break a command over this
        return False


def _record(cfg: dict, email: str, name: str | None, version: str, company: str | None = None) -> dict:
    cfg = {**cfg, "id": cfg.get("id") or str(uuid.uuid4()), "email": email, **({"name": name} if name else {})}
    cfg.pop("register_pending", None)
    if not _send_registration(cfg, version, company):
        cfg["register_pending"] = True
    cfg.setdefault("registered", _today())
    _save(cfg)
    if POSTHOG_KEY and not _switched_off():
        _identify(cfg, email, version, name=name, company=company)
    return cfg


def require_registration(argv: list[str], version: str) -> int | None:
    """Called before every `squidbrake` command. A pip install outside a named pilot gives its name and work email
    once before anything runs. Returns an exit code to stop with, or None to go on.

    Never stops the hooks (an agent would hang), CI, `pilot join`, or `--help`. Where nobody can answer (a script, a
    gateway in Docker, a service, `--yes`) it takes SQUIDBRAKE_NAME and SQUIDBRAKE_EMAIL, or else goes on and the next
    run in a terminal asks."""
    cfg = load()
    if cfg.get("register_pending") and cfg.get("email"):          # given while offline: send it now
        cfg["register_pending"] = not _send_registration(cfg, version)
        _save(cfg)
    if not _registration_needed(argv):
        return None
    email, name = os.getenv("SQUIDBRAKE_EMAIL", "").strip()[:254], os.getenv("SQUIDBRAKE_NAME", "").strip()[:120]
    if EMAIL_RE.match(email) and name:
        _record(cfg, email, name, version)
        return None
    if not _interactive() or "--yes" in argv:
        return None
    print()
    contact = _ask_contact()
    if not contact:
        print("Squidbrake needs your name and work email to run. Run it again in a terminal, or:\n"
              "  squidbrake register you@company.com --name \"Your Name\"")
        return 1
    _record(cfg, contact[0], contact[1], version)
    return None


def maybe(argv: list[str], version: str) -> None:
    """Called once per `squidbrake` command. Says what is sent the first time in a terminal, then sends."""
    command = argv[0] if argv and not argv[0].startswith("-") else "start"
    if command in QUIET or _switched_off():
        return
    cfg = load()
    if "enabled" not in cfg:
        # not during `pilot join` either: the installer runs it, and a founder with their own code must land in
        # their pilot, not in the community one
        if command == "pilot" or not _interactive() or "--yes" in argv or any(a in ("-h", "--help") for a in argv):
            return
        cfg = _first_run(cfg, version)
    if cfg.get("enabled") and cfg.get("counts_joined") is False and cfg.get("counts_retry") != _today():
        # joining the counts failed (offline, server down): try again, once a day, until it works.
        # Someone who later left (squidbrake pilot leave) has counts_joined True, so they're never joined again.
        cfg["counts_retry"] = _today()
        cfg["counts_joined"] = _share_counts(True, version, cfg.get("ref"),
                                             (cfg["email"], cfg.get("name")) if cfg.get("email") else None)
        _save(cfg)
    if cfg.get("enabled") and not cfg.get("ref") and (ref := ref_from_env()):
        cfg["ref"] = ref                    # said yes before, then installed again from a named link
        _save(cfg)
    if cfg.get("enabled") and POSTHOG_KEY:
        _send("cli_command", cfg["id"], _props(command, version, cfg.get("ref")))


def register(argv: list[str], version: str) -> int:
    args = [a for a in argv if a != "--yes"]
    opts = {}
    for flag in ("--company", "--name"):
        if flag in args:
            i = args.index(flag)
            opts[flag[2:]] = (" ".join(args[i + 1:i + 2]) or "")[:160] or None
            del args[i:i + 2]
    company, name = opts.get("company"), opts.get("name")
    if len(args) != 1 or not EMAIL_RE.match(args[0]) or not name:
        print("usage: squidbrake register EMAIL --name NAME [--company NAME] [--yes]")
        return 2
    email = args[0]
    print(f"This sends to the Squidbrake team: {email}" + (f", name {name}" if name else "") +
          (f", company {company}" if company else "") +
          f", the coding agents installed here ({', '.join(installed_agents()) or 'none found'})"
          ", and this computer's random usage id, so they can reach you.")
    if "--yes" not in argv and (_ask("Send it? [Y/n] ") or "").lower() not in ("", "y", "yes"):
        print("Nothing was sent.")
        return 0
    cfg = _record(load(), email, name, version, company)
    try:
        import pilot
        if (pilot.load(_pilot_dir()) or {}).get("code") == COMMUNITY_CODE:    # anonymous counts: under this email now
            import contextlib, io
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                # same install id: the server moves this install onto the email's own pilot
                pilot.join(_pilot_dir(), COMMUNITY_CODE, COMMUNITY_SERVER, True, version, contact=(email, name))
    except Exception:     # never break a command over this
        pass
    print("Saved; it will be sent the next time this computer is online." if cfg.get("register_pending")
          else "Sent. Thanks, the team will be in touch.")
    return 0


def main(argv: list[str], version: str = "") -> int:
    cfg = load()
    action = argv[0] if argv else "status"
    if action != "status":
        print("usage: squidbrake telemetry status\n\n" + NOTICE)
        return 2
    if _switched_off():
        state = "off (CI, DO_NOT_TRACK or SQUIDBRAKE_TELEMETRY is set)"
    else:
        state = {True: "on", False: "off (you said no when an earlier version asked; that is kept)"}.get(
            cfg.get("enabled"), "on (from the first squidbrake command you run in a terminal)")
    print(f"Anonymous usage stats: {state}")
    if cfg.get("email"):
        print(f"Registered: {cfg.get('name') or ''} <{cfg['email']}>" + (" (not sent yet: offline)" if cfg.get("register_pending") else ""))
    print(f"Settings: {_path()}\n\nWhat is sent, once each time you run a command:\n  {WHAT_IS_SENT}")
    return 0

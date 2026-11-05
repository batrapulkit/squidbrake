"""
Anonymous usage stats: which `squidbrake` commands run, and counts of what the gateway checked, held and blocked.
They are on by default; `squidbrake telemetry off` disables both CLI and pilot reporting. The first terminal run
says so once (and asks, optionally, where
you heard about Squidbrake). Scripts, CI, `--yes` and the agent hooks send nothing until that first run happened.
A gateway that starts without one (Docker, a background service) writes the same notice to its log and then shares
its counts (gateway_start); never in CI or with the off switches.

    squidbrake telemetry status      exactly what is sent
    squidbrake telemetry on|off      persist a reporting preference without a network request
    squidbrake register EMAIL        tell the Squidbrake team who you are (optional; asks first; also asked once on
                                     the first run, Enter skips it)

What is sent, once each time you run a command:
  - a random id made on this computer (not tied to you unless you give your email, below)
  - the command name only (e.g. "connect", "doctor", "undo"), never its arguments
  - the Squidbrake version, operating system, CPU type and Python version, and whether it came from pip
  - the country, worked out by the stats service from the address the request comes from
  - where you heard about Squidbrake, if you answered (one word from a list, e.g. "linkedin"), or the name of the
    link you installed from (SQUIDBRAKE_REF, e.g. "whatsapp")
Never sent: commands an agent ran, file or folder names, file contents, prompts, rules, keys, the audit trail,
names of people, your name, work email and the coding agents installed here (only if you give your email, on the
first run or with `squidbrake register`).
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
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import reporting

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
    if not reporting.enabled():
        return
    cfg.setdefault("id", reporting.identity()["installation_id"])
    with reporting.transaction() as state:
        if not reporting.allowed(state):
            return
        cfg["email"] = email
        _save(cfg, state=state)
        state["contact"] = True       # optional registration, not a verified account/org link
    props = {"email": email, "agents": installed_agents(), "version": version,
             **({"name": name} if name else {}), **({"company": company} if company else {})}
    _send("$identify", cfg["id"], {"$set": props}, wait=True)


def _ask_contact() -> tuple[str, str | None] | None:
    """Optional, once: work email and name, so the team can reach the person. Enter skips; nothing is sent then."""
    print("Optional: your work email, so the Squidbrake team can help you set it up (Enter to skip).")
    email = (_ask("Work email: ") or "")[:254]
    if not EMAIL_RE.match(email):
        if email:
            print("That doesn't look like an email; skipped. Later:  squidbrake register EMAIL")
        print()
        return None
    name = (_ask("Your name: ") or "")[:120] or None
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
    return reporting.cli_path()


def load() -> dict:
    try:
        return json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save(cfg: dict, state: dict | None = None, preference: bool = False) -> None:
    if state is None:
        with reporting.transaction() as locked:
            _save(cfg, state=locked, preference=preference)
        return
    # A normal command that read settings before `off` must not write its stale
    # enabled=True back afterward. Only the explicit on/off command can reverse it.
    if not preference and (state.get("usage") is False or reporting.read_json(_path()).get("enabled") is False):
        cfg["enabled"] = False
    name = None
    try:
        _path().parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=_path().parent, delete=False) as f:
            name = f.name
            json.dump(cfg, f, indent=2)
        os.replace(name, _path())
    except OSError:
        pass
    finally:
        if name:
            Path(name).unlink(missing_ok=True)


def _switched_off() -> bool:
    return not reporting.enabled()


def _pilot_dir() -> Path:
    """Where the gateway keeps pilot.json: the same place server.py works out (next to keys.json)."""
    return reporting.data_dir()


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
                pilot.join(home, COMMUNITY_CODE, COMMUNITY_SERVER, True, version, ref=ref, contact=contact,
                           automatic=True)
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
    cfg = {**cfg, "id": cfg.get("id") or reporting.identity()["installation_id"], "enabled": True,
           "asked": datetime.now(timezone.utc).date().isoformat()}
    if ref := ref_from_env() or _ask_source():
        cfg["ref"] = ref
    _save(cfg)
    if contact := _ask_contact():
        _identify(cfg, contact[0], version, name=contact[1])
    cfg["counts_joined"] = _share_counts(True, version, cfg.get("ref"), contact)
    if not cfg["counts_joined"]:
        cfg["counts_retry"] = _today()          # tried today: the next try is tomorrow (see maybe)
    _save(cfg)
    return cfg


def gateway_start(version: str, say=print) -> bool:
    """A gateway that never had a terminal first run (Docker, a background service): say in its log what is sent,
    then share its counts the way a first run does. Nothing when switched off, already sharing, or settled before
    (someone who left with `squidbrake pilot leave` isn't joined again). Returns whether it joined now."""
    if _switched_off() or not reporting.automatic_join_allowed():
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
        channel = "contact" if body.get("event") == "$identify" else "usage"
        with reporting.permit(channel=channel) as ok:
            if ok:
                httpx.post(POSTHOG_HOST.rstrip("/") + "/i/v0/e/", json=body, timeout=3)
    except Exception:    # stats must never break or slow down a command
        pass


def _send(event: str, distinct_id: str, props: dict, wait: bool = False) -> None:
    channel = "contact" if event == "$identify" else "usage"
    if not reporting.enabled(channel=channel):
        return
    props = {**props, "installation_id": reporting.identity(cli_id=distinct_id)["installation_id"]}
    body = {"api_key": POSTHOG_KEY, "event": event, "distinct_id": distinct_id, "properties": props,
            "timestamp": datetime.now(timezone.utc).isoformat()}
    t = threading.Thread(target=_post, args=(body,), daemon=True)
    t.start()
    if wait:
        t.join(3)
    else:
        atexit.register(t.join, 2)   # short commands: give it up to 2 seconds to finish on the way out


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
                                             (cfg["email"], None) if cfg.get("email") else None)
        _save(cfg)
    if cfg.get("enabled") and not cfg.get("ref") and (ref := ref_from_env()):
        cfg["ref"] = ref                    # said yes before, then installed again from a named link
        _save(cfg)
    if cfg.get("enabled") and POSTHOG_KEY:
        if not cfg.get("id"):
            cfg["id"] = reporting.identity()["installation_id"]
            _save(cfg)
        _send("cli_command", cfg["id"], _props(command, version, cfg.get("ref")))


def register(argv: list[str], version: str) -> int:
    if _switched_off():
        print("Reporting is off; nothing was sent. Use squidbrake telemetry on after removing any environment override.")
        return 1
    args = [a for a in argv if a != "--yes"]
    opts = {}
    for flag in ("--company", "--name"):
        if flag in args:
            i = args.index(flag)
            opts[flag[2:]] = (" ".join(args[i + 1:i + 2]) or "")[:160] or None
            del args[i:i + 2]
    company, name = opts.get("company"), opts.get("name")
    if len(args) != 1 or not EMAIL_RE.match(args[0]):
        print("usage: squidbrake register EMAIL [--name NAME] [--company NAME] [--yes]")
        return 2
    if not POSTHOG_KEY:
        print("This build of Squidbrake has no stats service set up; nothing was sent.")
        return 1
    email = args[0]
    print(f"This sends to the Squidbrake team: {email}" + (f", name {name}" if name else "") +
          (f", company {company}" if company else "") +
          f", the coding agents installed here ({', '.join(installed_agents()) or 'none found'})"
          ", and this computer's random usage id, so they can reach you.")
    if "--yes" not in argv and (_ask("Send it? [Y/n] ") or "").lower() not in ("", "y", "yes"):
        print("Nothing was sent.")
        return 0
    _identify(load(), email, version, name=name, company=company)
    try:
        import pilot
        if (pilot.load(_pilot_dir()) or {}).get("code") == COMMUNITY_CODE:    # anonymous counts: under this email now
            import contextlib, io
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                # same install id: the server moves this install onto the email's own pilot
                pilot.join(_pilot_dir(), COMMUNITY_CODE, COMMUNITY_SERVER, True, version, contact=(email, name))
    except Exception:     # never break a command over this
        pass
    print("Sent. Thanks, the team will be in touch.")
    return 0


def main(argv: list[str], version: str = "") -> int:
    cfg = load()
    action = argv[0] if argv else "status"
    if action == "contact-off":
        with reporting.transaction() as state:
            state["contact"] = False
        print("Contact identification: off. Previously submitted contact data was not deleted.")
        return 0
    if action in {"on", "off"}:
        with reporting.transaction() as state:
            cfg = load()                      # under the same cross-process lock as sends
            cfg["enabled"] = action == "on"
            if action == "on":
                cfg.setdefault("counts_joined", False)
            state["usage"] = action == "on"
            _save(cfg, state=state, preference=True)  # also preserve refusal for older CLI versions
            if action == "off":
                state["contact"] = False
                state["diagnostics"] = False
        print(f"Usage reporting: {action}. No network request was made.")
        if action == "on" and reporting.environment_off():
            print("An environment override still disables reporting (CI, DO_NOT_TRACK or SQUIDBRAKE_TELEMETRY).")
        return 0
    if action == "rotate-epoch":
        import server
        print(f"Dataset epoch: {reporting.dataset_epoch(server.engine, rotate=True)}")
        return 0
    if action != "status":
        print("usage: squidbrake telemetry status|on|off|contact-off|rotate-epoch\n\n" + NOTICE)
        return 2
    if reporting.environment_off():
        state = "off (CI, DO_NOT_TRACK or SQUIDBRAKE_TELEMETRY is set)"
    elif _switched_off():
        state = "off (you said no or disabled reporting; that is kept)"
    else:
        state = {True: "on", False: "off (you said no when an earlier version asked; that is kept)"}.get(
            cfg.get("enabled"), "on (from the first squidbrake command you run in a terminal)")
    print(f"Anonymous usage stats: {state}")
    print(f"Contact identification: {'on' if reporting.enabled(channel='contact') else 'off'}")
    print("Optional diagnostics: off (no diagnostics sender is implemented)")
    if cfg.get("email"):
        print(f"Registered email: {cfg['email']}")
    print(f"Settings: {_path()}\n\nWhat is sent, once each time you run a command:\n  {WHAT_IS_SENT}")
    return 0

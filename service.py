"""
Optionally keep the gateway running in the background, started again whenever you log in and whenever it stops.
Nothing is installed without a yes: adding a login item can trip the endpoint security tools many companies run.

  python service.py start [RUN OPTIONS]   what `squidbrake`, start.sh and start.bat do. The first time, in a terminal,
                                          it asks once whether to run in the background (Enter means no) and
                                          remembers the answer. No terminal (scripts, CI) means no, and nothing is
                                          remembered. RUN OPTIONS go to `server.py run`, e.g. --port 9000
  python service.py start --background    install the service and start it, without asking
  python service.py start --foreground    run in this window, without asking
  python service.py stop                  stop it and take the service out (it no longer starts at login)
  python service.py status                is it installed, and is the gateway answering

  macOS    ~/Library/LaunchAgents/com.squidbrake.gateway.plist   (launchd)   log: ~/Library/Logs/squidbrake.log
  Linux    ~/.config/systemd/user/squidbrake.service              (systemd)   log: journalctl --user -u squidbrake
  Windows  HKCU\\...\\CurrentVersion\\Run, value Squidbrake         (at login)  log: ~/.squidbrake/squidbrake.log

SQUIDBRAKE_BACKGROUND=1 or 0 answers the question for unattended installs; SQUIDBRAKE_FOREGROUND=1 is the same as
--foreground. Docker and Linux machines without a systemd user session always run in the foreground.
"""
from __future__ import annotations

import json
import os
import plistlib
import shutil
import subprocess
import sys
import time
import urllib.request
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVER = HERE / "server.py"
LABEL = "com.squidbrake.gateway"
UNIT = "squidbrake.service"
RUN_VALUE = "Squidbrake"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
PASS_ENV = ("SQUIDBRAKE_HOME", "SQUIDBRAKE_CLI", "DATABASE_URL", "KEYS_PATH", "RULES_PATH", "PORT", "HOST")


def state_dir() -> Path:
    return Path(os.getenv("SQUIDBRAKE_HOME") or Path.home() / ".squidbrake")


def _port(run_args: list[str]) -> int:
    for i, a in enumerate(run_args):
        if a == "--port" and i + 1 < len(run_args):
            return int(run_args[i + 1])
        if a.startswith("--port="):
            return int(a.split("=", 1)[1])
    return int(os.getenv("PORT", "8080"))


def _answering(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2):
            return True
    except Exception:
        return False


def _command(run_args: list[str]) -> list[str]:
    return [sys.executable, str(SERVER), "run", "--no-browser", *run_args]


def _env() -> dict[str, str]:
    env = {k: os.environ[k] for k in PASS_ENV if os.getenv(k)}
    env["PATH"] = os.getenv("PATH", "/usr/local/bin:/usr/bin:/bin")
    env["PYTHONUNBUFFERED"] = "1"
    return env


def _run(*cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


# --------------------------------------------------------------------------- macOS: launchd

def _plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def _launchd_target() -> str:
    return f"gui/{os.getuid()}"


def _launchd_install(run_args: list[str]) -> str:
    log = Path.home() / "Library" / "Logs" / "squidbrake.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    plist = _plist_path()
    plist.parent.mkdir(parents=True, exist_ok=True)
    plist.write_bytes(plistlib.dumps({
        "Label": LABEL, "ProgramArguments": _command(run_args), "WorkingDirectory": str(HERE),
        "EnvironmentVariables": _env(), "RunAtLoad": True, "KeepAlive": True, "ProcessType": "Background",
        "StandardOutPath": str(log), "StandardErrorPath": str(log),
    }))
    _run("launchctl", "bootout", f"{_launchd_target()}/{LABEL}")
    for _ in range(10):   # bootout finishes in the background; bootstrap fails until it has
        r = _run("launchctl", "bootstrap", _launchd_target(), str(plist))
        if r.returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError(f"launchctl couldn't load {plist}: {r.stderr.strip() or r.stdout.strip()}")
    _run("launchctl", "enable", f"{_launchd_target()}/{LABEL}")
    return str(log)


def _launchd_remove() -> bool:
    plist = _plist_path()
    _run("launchctl", "bootout", f"{_launchd_target()}/{LABEL}")
    if plist.exists():
        plist.unlink()
        return True
    return False


def _launchd_installed() -> bool:
    return _plist_path().exists()


# --------------------------------------------------------------------------- Linux: systemd user service

def _unit_path() -> Path:
    return Path(os.getenv("XDG_CONFIG_HOME") or Path.home() / ".config") / "systemd" / "user" / UNIT


def _systemd_usable() -> bool:
    if not shutil.which("systemctl") or not Path("/run/systemd/system").exists():
        return False
    return _run("systemctl", "--user", "show-environment").returncode == 0


def _sd_quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _systemd_install(run_args: list[str]) -> str:
    unit = _unit_path()
    unit.parent.mkdir(parents=True, exist_ok=True)
    lines = ["[Unit]", "Description=Squidbrake", "After=network-online.target", "Wants=network-online.target", "",
             "[Service]", f"WorkingDirectory={HERE}",
             *[f"Environment={_sd_quote(f'{k}={v}')}" for k, v in _env().items()],
             "ExecStart=" + " ".join(_sd_quote(a) for a in _command(run_args)),
             "Restart=always", "RestartSec=2", "", "[Install]", "WantedBy=default.target", ""]
    unit.write_text("\n".join(lines), encoding="utf-8")
    for cmd in (("daemon-reload",), ("enable", UNIT), ("restart", UNIT)):
        r = _run("systemctl", "--user", *cmd)
        if r.returncode:
            raise RuntimeError(f"systemctl --user {' '.join(cmd)} failed: {r.stderr.strip()}")
    # Start at boot even before this user logs in (allowed for your own user on most distributions).
    _run("loginctl", "enable-linger", os.getenv("USER") or "")
    return f"journalctl --user -u {UNIT} -f"


def _systemd_remove() -> bool:
    unit = _unit_path()
    _run("systemctl", "--user", "disable", "--now", UNIT)
    if unit.exists():
        unit.unlink()
        _run("systemctl", "--user", "daemon-reload")
        return True
    return False


def _systemd_installed() -> bool:
    return _unit_path().exists()


# --------------------------------------------------------------------------- Windows: run at login

def _win_state() -> Path:
    return state_dir() / "service.json"


def _pythonw() -> str:
    w = Path(sys.executable).with_name("pythonw.exe")
    return str(w if w.exists() else sys.executable)


def _win_install(run_args: list[str]) -> str:
    import winreg
    log = state_dir() / "squidbrake.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    _win_stop_running()
    _win_state().write_text(json.dumps({"command": _command(run_args), "cwd": str(HERE), "env": _env(),
                                        "log": str(log)}, indent=2), encoding="utf-8")
    launch = f'"{_pythonw()}" "{Path(__file__).resolve()}" supervise'
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, RUN_VALUE, 0, winreg.REG_SZ, launch)
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    subprocess.Popen([_pythonw(), str(Path(__file__).resolve()), "supervise"], cwd=str(HERE), creationflags=flags,
                     close_fds=True)
    return str(log)


def _win_stop_running() -> None:
    try:
        pid = json.loads(_win_state().read_text(encoding="utf-8")).get("pid")
    except (OSError, ValueError):
        return
    if pid:
        _run("taskkill", "/PID", str(pid), "/T", "/F")


def _win_remove() -> bool:
    import winreg
    _win_stop_running()
    found = False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, RUN_VALUE)
            found = True
    except OSError:
        pass
    _win_state().unlink(missing_ok=True)
    return found


def _win_installed() -> bool:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.QueryValueEx(k, RUN_VALUE)
            return True
    except OSError:
        return False


def supervise() -> int:
    """Windows: run the gateway with no console window and start it again whenever it stops."""
    path = _win_state()
    cfg = json.loads(path.read_text(encoding="utf-8"))
    cfg["pid"] = os.getpid()
    path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    while True:
        with open(cfg["log"], "a", encoding="utf-8") as log:
            subprocess.call(cfg["command"], cwd=cfg["cwd"], env={**os.environ, **cfg["env"]},
                            stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
        time.sleep(2)


# --------------------------------------------------------------------------- entry points

def backend() -> str | None:
    """Which service manager this computer has, or None to run in the foreground."""
    if os.getenv("IN_DOCKER") or os.getenv("SQUIDBRAKE_FOREGROUND", "").strip().lower() in ("1", "yes", "true", "on"):
        return None
    if sys.platform == "darwin":
        return "launchd"
    if sys.platform == "win32":
        return "windows"
    if sys.platform.startswith("linux") and _systemd_usable():
        return "systemd"
    return None


def _foreground(run_args: list[str]) -> int:
    return subprocess.call([sys.executable, str(SERVER), "run", *run_args], cwd=str(HERE))


def _installed(kind: str) -> bool:
    return {"launchd": _launchd_installed, "systemd": _systemd_installed, "windows": _win_installed}[kind]()


def _where(kind: str) -> str:
    return {"launchd": f"a LaunchAgent, {_plist_path()}",
            "systemd": f"a systemd user service, {_unit_path()}",
            "windows": rf"a login item, HKCU\{RUN_KEY}, value {RUN_VALUE}"}[kind]


def _choice_path() -> Path:
    return state_dir() / "background.json"


def _saved_choice() -> bool | None:
    try:
        return bool(json.loads(_choice_path().read_text(encoding="utf-8"))["background"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _save_choice(background: bool) -> None:
    try:
        _choice_path().parent.mkdir(parents=True, exist_ok=True)
        _choice_path().write_text(json.dumps({"background": background,
                                              "asked": datetime.now(timezone.utc).date().isoformat()}, indent=2),
                                  encoding="utf-8")
    except OSError:
        pass


def _interactive() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _ask(kind: str) -> bool | None:
    print("\nSquidbrake can keep running in the background, so your agents are never blocked because it's down.")
    print(f"That adds {_where(kind)},")
    print("which starts it at every login and again if it stops. Turn it off any time: " + _cli("stop"))
    try:
        answer = input("Run Squidbrake in the background? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return answer in ("y", "yes")


def wants_background(kind: str) -> bool:
    """Only ever True after a yes: --background, SQUIDBRAKE_BACKGROUND=1, or the question asked once."""
    env = os.getenv("SQUIDBRAKE_BACKGROUND", "").strip().lower()
    if env in ("1", "yes", "true", "on"):
        return True
    if env in ("0", "no", "false", "off"):
        return False
    saved = _saved_choice()
    if saved is not None:
        if saved and not _installed(kind):   # taken out by hand: don't put it back without asking
            print(f"The background service isn't installed. Running in this window; to put it back: "
                  f"{_cli('start --background')}\n")
            return False
        return saved
    if _installed(kind):                    # installed before the question existed
        return True
    if not _interactive():
        return False
    yes = _ask(kind)
    if yes is not None:
        _save_choice(yes)
    if not yes:
        print(f"Running in this window. To run in the background later: {_cli('start --background')}\n")
    return bool(yes)


def start(run_args: list[str]) -> int:
    if "--foreground" in run_args:
        return _foreground([a for a in run_args if a != "--foreground"])
    explicit = "--background" in run_args
    run_args = [a for a in run_args if a != "--background"]
    kind = backend()
    if kind is None:
        if explicit:
            print("A background service isn't available here (Docker, or no systemd user session). "
                  "Running in this window.", file=sys.stderr)
        return _foreground(run_args)
    if explicit:
        _save_choice(True)
    elif not wants_background(kind):
        return _foreground(run_args)
    port = _port(run_args)
    busy = _answering(port)
    # First start: make the keys here, where the person can see them (the service's output only goes to its log).
    subprocess.call([sys.executable, str(SERVER), "init"], cwd=str(HERE))
    first = not _installed(kind)
    try:
        log = {"launchd": _launchd_install, "systemd": _systemd_install, "windows": _win_install}[kind](run_args)
    except Exception as e:
        print(f"Couldn't install the background service ({e}). Running in this window instead.", file=sys.stderr)
        return _foreground(run_args)
    url = f"http://localhost:{port}/dashboard"
    for _ in range(40):
        if _answering(port):
            break
        time.sleep(0.5)
    up = _answering(port)
    print("\n" + "=" * 72)
    print("  Squidbrake runs in the background now. It starts by itself whenever you log in,")
    print("  and comes back if it ever stops. You can close this window.")
    print(f"  Dashboard:  {url}" + ("" if up else "   (still starting; give it a few seconds)"))
    print(f"  Log:        {log}")
    print(f"  Status:     {_cli('status')}")
    print(f"  Turn off:   {_cli('stop')}")
    if busy:
        print(f"\n  Note: something was already answering on port {port} (probably Squidbrake started by hand).")
        print("  Close that one; the background service takes over on its own.")
    print("=" * 72 + "\n")
    if first and up and not os.getenv("SQUIDBRAKE_NO_BROWSER"):
        webbrowser.open(url)
    return 0


def stop() -> int:
    kind = backend() or ("systemd" if sys.platform.startswith("linux") else None)
    removed = {"launchd": _launchd_remove, "systemd": _systemd_remove, "windows": _win_remove}.get(kind, lambda: False)()
    _save_choice(False)
    print("Stopped Squidbrake and took out the background service. It won't start at login any more."
          if removed else "The background service wasn't installed; nothing to stop.")
    print(f"Run in this window: {_cli('start')}   In the background again: {_cli('start --background')}")
    return 0


def status(run_args: list[str]) -> int:
    kind = backend()
    installed = bool(kind) and _installed(kind)
    port = _port(run_args)
    up = _answering(port)
    where = {"launchd": "launchd (macOS)", "systemd": "systemd user service", "windows": "Windows, at login"}.get(
        kind, "not available here (runs in the foreground)")
    print(f"background service  {'installed' if installed else 'not installed'}  ({where})")
    print(f"gateway             {'answering' if up else 'NOT answering'} on http://localhost:{port}")
    if not installed and kind:
        print(f"Install it with: {_cli('start --background')}")
    return 0 if up else 1


def _cli(sub: str) -> str:
    if os.getenv("SQUIDBRAKE_CLI") == "squidbrake":
        if sub.startswith("start"):
            return "squidbrake" if sub == "start" else f"squidbrake {sub}"
        return f"squidbrake service {sub}"
    return f"{sys.executable} {HERE / 'service.py'} {sub}"


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cmd, rest = (argv[0], argv[1:]) if argv and not argv[0].startswith("-") else ("start", argv)
    if cmd in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    if cmd in ("start", "install"):
        return start(rest)
    if cmd in ("stop", "remove", "uninstall"):
        return stop()
    if cmd == "status":
        return status(rest)
    if cmd == "supervise":
        return supervise()
    print(f"unknown command {cmd!r}\n{__doc__}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

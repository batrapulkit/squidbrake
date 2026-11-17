"""
Keep the gateway running in the background: started again whenever you log in and whenever it stops, and updated
to each new version on its own (see "Staying up to date" below). Agents' actions are blocked while the gateway is
down, so this is how Squidbrake always runs where the computer has a service manager; nothing asks about it.

  python service.py start [RUN OPTIONS]   what `squidbrake`, start.sh and start.bat do: install the service (or set
                                          it up again, pointing at this install) and start it. RUN OPTIONS go to
                                          `server.py run`, e.g. --port 9000
  python service.py start --foreground    run in this window instead (debugging; nothing restarts it)
  python service.py stop                  stop it and take the service out, until the next start
  python service.py status                is it installed, and is the gateway answering

  macOS    ~/Library/LaunchAgents/com.squidbrake.gateway.plist   (launchd)   log: ~/Library/Logs/squidbrake.log
  Linux    ~/.config/systemd/user/squidbrake.service              (systemd)   log: journalctl --user -u squidbrake
  Windows  HKCU\\...\\CurrentVersion\\Run, value Squidbrake         (at login)  log: ~/.squidbrake/squidbrake.log

SQUIDBRAKE_BACKGROUND=0 or SQUIDBRAKE_FOREGROUND=1 is the same as --foreground (e.g. where IT doesn't allow login
items). Docker and Linux machines without a systemd user session always run in the foreground.

Staying up to date: the background gateway looks at PyPI once a day. A version that has been out for a day
(SQUIDBRAKE_AUTO_UPDATE_AFTER_HOURS) is installed in place, checked (`server.py init` must run), and the gateway
restarts on it, at a moment nothing is waiting for a person and no agent acted in the last 10 minutes. If the check
fails, the version before is put back. Only installs Squidbrake made are updated: the installer's own folder, a
virtualenv, uv or pipx; never a system Python, Docker or the native build. Off: SQUIDBRAKE_NO_AUTO_UPDATE=1 (or
SQUIDBRAKE_NO_UPDATE_CHECK=1 / DO_NOT_TRACK=1, which also stop the daily look at PyPI).
"""
from __future__ import annotations

import json
import logging
import os
import re
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
log = logging.getLogger("gateway")
PASS_ENV = ("SQUIDBRAKE_HOME", "SQUIDBRAKE_CLI", "DATABASE_URL", "KEYS_PATH", "RULES_PATH", "PORT", "HOST")


def can_open_browser() -> bool:
    """No browser on a server over SSH or a Linux box without a desktop (webbrowser would start a text browser
    in this terminal instead)."""
    if os.getenv("SSH_CONNECTION") or os.getenv("SSH_TTY"):
        return False
    return not (sys.platform.startswith("linux") and not (os.getenv("DISPLAY") or os.getenv("WAYLAND_DISPLAY")))


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
        # no proxy: Windows' system proxy often doesn't bypass 127.0.0.1, and this is this computer
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(f"http://127.0.0.1:{port}/health", timeout=2):
            return True
    except Exception:
        return False


def _command(run_args: list[str]) -> list[str]:
    return [sys.executable, str(SERVER), "run", "--no-browser", *run_args]


def _env() -> dict[str, str]:
    env = {k: os.environ[k] for k in PASS_ENV if os.getenv(k)}
    env["PATH"] = os.getenv("PATH", "/usr/local/bin:/usr/bin:/bin")
    env["PYTHONUNBUFFERED"] = "1"
    env["SQUIDBRAKE_SERVICE"] = "1"      # the gateway knows a service restarts it (so it may update itself)
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
    if pid and _is_python(pid):    # a saved pid can belong to another program by now (after a crash or reboot)
        _run("taskkill", "/PID", str(pid), "/T", "/F")


def _is_python(pid: int) -> bool:
    """Is process pid a Python (the supervisor runs as pythonw.exe)?"""
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.OpenProcess(0x1000, False, int(pid))          # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        try:
            buf, n = ctypes.create_unicode_buffer(1024), ctypes.c_ulong(1024)
            if not k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)):
                return False
            return Path(buf.value).name.lower() in ("pythonw.exe", "python.exe") or "python" in Path(buf.value).name.lower()
        finally:
            k.CloseHandle(h)
    except (AttributeError, OSError, ValueError):
        return False


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
    quick = 0
    while True:
        started = time.monotonic()
        with open(cfg["log"], "a", encoding="utf-8") as log:
            # its output goes to a file: UTF-8, or a name like C:\Users\राहुल in what it prints would stop it
            subprocess.call(cfg["command"], cwd=cfg["cwd"], env={**os.environ, "PYTHONIOENCODING": "utf-8", **cfg["env"]},
                            stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
        quick = quick + 1 if time.monotonic() - started < 30 else 0
        time.sleep(restart_delay(quick))


def restart_delay(quick: int) -> float:
    """Seconds before starting it again: 2 s after a crash, longer each time it stops right away (port taken, broken
    install), up to 5 minutes, so a gateway that can't start doesn't fill the log and the processor."""
    return min(2.0 * 2 ** max(quick - 1, 0), 300.0)


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


def wants_background(kind: str) -> bool:
    """Always, unless SQUIDBRAKE_BACKGROUND=0 says otherwise (--foreground and SQUIDBRAKE_FOREGROUND=1: backend())."""
    if os.getenv("SQUIDBRAKE_BACKGROUND", "").strip().lower() in ("0", "no", "false", "off"):
        return False
    _save_choice(True)
    return True


def is_first_start(run_args: list[str]) -> bool:
    """`squidbrake` typed in a terminal for the first time: the background question is about to be asked.
    That's step 3 of the setup (see flow.py); every later start is just a start."""
    if any(a in ("--foreground", "--background") for a in run_args) or not _interactive():
        return False
    if os.getenv("SQUIDBRAKE_BACKGROUND", "").strip():
        return False
    kind = backend()
    return bool(kind) and _saved_choice() is None and not _installed(kind)


def start(run_args: list[str]) -> int:
    if "--foreground" in run_args:
        return _foreground([a for a in run_args if a != "--foreground"])
    explicit = "--background" in run_args            # the same as no flag now; kept for scripts that pass it
    run_args = [a for a in run_args if a != "--background"]
    kind = backend()
    if kind is None:
        if explicit:
            print("A background service isn't available here (Docker, or no systemd user session). "
                  "Running in this window.", file=sys.stderr)
        return _foreground(run_args)
    if is_first_start(run_args):
        import flow                            # the last of the three setup commands: say so (see flow.py)
        flow.header(3)
    if not explicit and not wants_background(kind):
        return _foreground(run_args)
    port = _port(run_args)
    busy = _answering(port)
    # First start: make the keys here, where the person can see them (the service's output only goes to its log).
    subprocess.call([sys.executable, str(SERVER), "init", "--quiet"], cwd=str(HERE))
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
    if first:
        import flow
        flow.next_step(["Setup complete. Last step: quit and reopen your agents (Claude Code, Cursor, Codex, ...),",
                        "then work as usual.", "",
                        "Check everything end to end:  " + flow.doctor_command()])
    if first and up and not os.getenv("SQUIDBRAKE_NO_BROWSER"):
        webbrowser.open(url)
    return 0


def stop() -> int:
    kind = backend() or ("systemd" if sys.platform.startswith("linux") else None)
    removed = {"launchd": _launchd_remove, "systemd": _systemd_remove, "windows": _win_remove}.get(kind, lambda: False)()
    _save_choice(False)
    print("Stopped Squidbrake and took out the background service, until the next start. While it's stopped, "
          "your agents' actions are blocked." if removed else "The background service wasn't installed; nothing to stop.")
    print(f"Start it again (in the background): {_cli('start')}")
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
        print(f"Install it with: {_cli('start')}")
    return 0 if up else 1


# --------------------------------------------------------------------------- staying up to date

AUTO_UPDATE_AFTER_H = float(os.getenv("SQUIDBRAKE_AUTO_UPDATE_AFTER_HOURS", "24"))
_on = lambda name: os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")
_num = lambda v: tuple(int(n) for n in re.findall(r"\d+", str(v))[:3])


def _running_path() -> Path:
    return state_dir() / "running.json"


def record_running(version: str) -> None:
    """`server.py run` says which install and version is running, so `setup` can tell an old one is (stale())."""
    try:
        _running_path().parent.mkdir(parents=True, exist_ok=True)
        _running_path().write_text(json.dumps({"version": version, "python": sys.executable, "server": str(SERVER),
                                               "pid": os.getpid()}, indent=2), encoding="utf-8")
    except OSError:
        pass


def stale(kind: str, version: str) -> bool:
    """A gateway answers, but is it this install's service, at this version? If not, setup sets the service up again:
    an older install's service would otherwise keep starting the old version at every login."""
    if not _installed(kind):
        return True
    try:
        r = json.loads(_running_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True                      # gateways from before 0.14.16 don't say: they're older than this one
    return (r.get("version"), r.get("python"), r.get("server")) != (version, sys.executable, str(SERVER))


def auto_update_on() -> bool:
    return not (_on("SQUIDBRAKE_NO_AUTO_UPDATE") or _on("SQUIDBRAKE_NO_UPDATE_CHECK") or _on("DO_NOT_TRACK")
                or os.getenv("IN_DOCKER") or getattr(sys, "frozen", False))


def install_kind() -> str | None:
    """How this copy was installed, if it's one Squidbrake may update by itself."""
    if not (HERE / "__init__.py").exists():        # a checkout (start.sh): git pull is how that one updates
        return None
    exe = sys.executable.replace("\\", "/").lower()
    if "/uv/tools/" in exe:
        return "uv" if _uv() else None
    if "/pipx/" in exe:
        return "pipx" if shutil.which("pipx") else None
    if sys.prefix != sys.base_prefix:              # the installer's ~/.squidbrake/app, or another virtualenv
        return "venv"
    return None                                    # a system Python: other programs share it, so not ours to change


def _uv() -> str | None:
    found = shutil.which("uv")
    for p in (Path.home() / ".local" / "bin" / "uv", Path.home() / ".cargo" / "bin" / "uv"):
        if not found and p.exists():
            found = str(p)
    return found


def _upgrade_cmd(kind: str, version: str) -> list[str]:
    return {"venv": [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check",
                     f"squidbrake=={version}"],
            "uv": [_uv() or "uv", "tool", "upgrade", "squidbrake"],
            "pipx": [shutil.which("pipx") or "pipx", "upgrade", "squidbrake"]}[kind]


def _pypi() -> tuple[str, float]:
    """The newest version on PyPI and when it was uploaded (seconds since the epoch)."""
    import httpx
    info = httpx.get("https://pypi.org/pypi/squidbrake/json", timeout=10).json()
    latest = info["info"]["version"]
    files = info.get("releases", {}).get(latest) or info.get("urls") or []
    up = min((datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00")).timestamp() for f in files
              if f.get("upload_time_iso_8601")), default=time.time())
    return latest, up


def _installed_version() -> str:
    r = subprocess.run([sys.executable, "-c", "import importlib.metadata as m; print(m.version('squidbrake'))"],
                       capture_output=True, text=True, timeout=60)
    return r.stdout.strip() if r.returncode == 0 else ""


def _works() -> bool:
    """The new code on disk loads, reads its settings and keys: `server.py init` (what every start runs first)."""
    try:
        return subprocess.run([sys.executable, str(SERVER), "init", "--quiet"], cwd=str(HERE), capture_output=True,
                              timeout=180).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def self_update(current: str) -> bool:
    """Once a day (the caller's loop): install a newer version in place. True: it's installed and works, so the
    gateway should exit and the service starts it again on the new one. Never raises for an expected failure."""
    path = state_dir() / "update-check.json"           # shared with the CLI's notice (squidbrake/cli.py)
    try:
        cache = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cache = {}
    kind = install_kind()
    if not auto_update_on() or not kind:
        return False
    if cache.get("uploaded_for") and cache.get("uploaded_for") == cache.get("latest") and \
            time.time() - cache.get("checked", 0) < 20 * 3600:
        latest, uploaded = str(cache.get("latest") or ""), float(cache["uploaded"])    # looked today already
    else:
        try:
            latest, uploaded = _pypi()
        except Exception as e:
            log.info("update check: PyPI not reachable (%s)", e)
            return False
        cache.update(checked=time.time(), latest=latest, uploaded=uploaded, uploaded_for=latest)

    def save():
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(cache), encoding="utf-8")
        except OSError:
            pass
    if _num(latest) <= _num(current) or time.time() - uploaded < AUTO_UPDATE_AFTER_H * 3600 or \
            (cache.get("failed") == latest and time.time() - cache.get("failed_at", 0) < 86400):
        save()
        return False
    log.info("updating Squidbrake %s -> %s (%s)", current, latest, kind)
    try:
        r = subprocess.run(_upgrade_cmd(kind, latest), capture_output=True, text=True, timeout=600)
        ok = r.returncode == 0 and _num(_installed_version()) > _num(current) and _works()
        why = (r.stderr or r.stdout).strip()[-300:] if r.returncode else "the new version didn't start"
    except (OSError, subprocess.TimeoutExpired) as e:
        ok, why = False, str(e)
    if not ok:
        log.warning("update to %s didn't work (%s); staying on %s", latest, why, current)
        cache.update(failed=latest, failed_at=time.time())
        if _installed_version() != current:            # half installed: put the one that works back
            back = {"venv": _upgrade_cmd("venv", current),
                    "uv": [_uv() or "uv", "tool", "install", "--force", f"squidbrake=={current}"],
                    "pipx": [shutil.which("pipx") or "pipx", "install", "--force", f"squidbrake=={current}"]}[kind]
            try:
                subprocess.run(back, capture_output=True, timeout=600)
            except (OSError, subprocess.TimeoutExpired):
                pass
    save()
    return ok


def _cli(sub: str) -> str:
    if os.getenv("SQUIDBRAKE_CLI") == "squidbrake":
        if sub.startswith("start"):
            return "squidbrake" if sub == "start" else f"squidbrake {sub}"
        return f"squidbrake service {sub}"
    return f"{sys.executable} {HERE / 'service.py'} {sub}"


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] and argv[0] in ("-h", "--help"):     # before the flags-mean-start rule below
        argv = ["help"]
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

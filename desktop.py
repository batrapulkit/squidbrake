"""
The Squidbrake app: a small icon in the menu bar (macOS) or the tray (Windows, Linux) that keeps the AI agents on
this computer connected to your hosted dashboard. No gateway runs here: every action goes to your dashboard, as
with the install command on your start page (which keeps working the same way).

  squidbrake app             start it. The first time, it opens a sign-in page in your browser: your email, the
                             6-digit code from the email, and this computer gets its own agent key (you never see
                             or copy it). It then starts at every login.
  squidbrake login           the same sign-in in a terminal (a server, or no menu bar)
  squidbrake app --status    signed in? which dashboard, and is it answering
  squidbrake app --signout   forget the sign-in, disconnect this computer's agents, stop starting at login

What it does while running:
  - checks every minute that your dashboard answers (green: protecting; amber: waking or waiting; grey: can't reach it)
  - tells squidbrake.com it's running every 10 minutes: an unused dashboard goes to sleep after a while, and this
    keeps it awake (or wakes it) while the app is installed, so your agent's actions don't wait on it
  - Open dashboard, Reconnect agents, Start at login, Quit from the icon's menu

The agent key it gets can't approve anything or sign in to the dashboard: approvals stay with a person.
Sign-in state: ~/.squidbrake/app.json (only you can read it). Server: SQUIDBRAKE_APP_SERVER (squidbrake.com).
Icon: needs `pystray` and `Pillow` (in the Mac and Windows installers; with pip: pip install "squidbrake[app]").
"""
from __future__ import annotations

import json
import os
import platform
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVER = os.getenv("SQUIDBRAKE_APP_SERVER", "https://pilots.squidbrake.com").rstrip("/")
CHECK_SECONDS = 60
HEARTBEAT_SECONDS = 600
LABEL = "com.squidbrake.app"
RUN_VALUE = "SquidbrakeApp"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def state_dir() -> Path:
    return Path(os.getenv("SQUIDBRAKE_HOME") or Path.home() / ".squidbrake")


def _version() -> str:
    try:
        from squidbrake import __version__
        return __version__
    except Exception:
        return ""


# ---------------------------------------------------------------------------- sign-in state

def config_path() -> Path:
    return state_dir() / "app.json"


def load() -> dict:
    try:
        return json.loads(config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save(cfg: dict) -> None:
    p = config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, p)


def forget() -> None:
    try:
        config_path().unlink()
    except OSError:
        pass


# ---------------------------------------------------------------------------- squidbrake.com

class ApiError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def api(method: str, path: str, body: dict | None = None, server: str | None = None) -> dict:
    url = (server or SERVER) + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json", "User-Agent": f"squidbrake-app/{_version() or '0'}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read() or b"{}").get("detail") or e.reason
        except ValueError:
            detail = e.reason
        raise ApiError(e.code, str(detail)) from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise ApiError(0, f"can't reach {SERVER}: check your internet connection ({e})") from None


def device_name() -> str:
    """What this computer is called, e.g. "Karishma's MacBook Air": the name its agent key gets on the Team page."""
    name = ""
    if sys.platform == "darwin":
        try:
            name = subprocess.run(["/usr/sbin/scutil", "--get", "ComputerName"], capture_output=True, text=True,
                                  timeout=5).stdout.strip()     # full path: a login item's PATH has no /usr/sbin
        except (OSError, subprocess.SubprocessError):
            pass
    name = name or os.getenv("COMPUTERNAME") or socket.gethostname().split(".")[0]    # "host.local" -> "host"
    return (name or "computer")[:40]


def send_code(email: str) -> None:
    api("POST", "/v1/app/code", {"email": email.strip()})


def start_link(email: str, code: str) -> dict:
    """The code checked: {link, state, ...}. Then poll(link) until it says connected."""
    return api("POST", "/v1/app/connect", {"email": email.strip(), "code": code.strip(), "device": device_name()})


def poll(link: str) -> dict:
    return api("GET", f"/v1/app/link/{link}")


def wait_connected(first: dict, on_state=None, timeout: float = 1800, every: float = 3) -> dict:
    """Ask again until this computer has its key (its dashboard may be waking, in line, or starting)."""
    s, end = first, time.time() + timeout
    while s.get("state") != "connected":
        if on_state:
            on_state(s)
        if time.time() > end:
            raise ApiError(408, "this is taking too long: sign in again in a few minutes")
        time.sleep(every if s.get("state") != "waiting" else 10)
        s = poll(first["link"])
    return s


def describe(s: dict) -> str:
    st = s.get("state")
    if st == "waiting":
        ahead = s.get("ahead") or 0
        return f"Every dashboard is busy: {ahead} ahead of you. Yours starts on its own." if ahead else \
            "You're next in line for a dashboard."
    return {"starting": "Starting your dashboard (about a minute)…",
            "connecting": "Making this computer's key…",
            "connected": "Connected."}.get(st, "One moment…")


# ---------------------------------------------------------------------------- this computer's agents

def _script(name: str, *args: str) -> list[str]:
    """Run one of our scripts the way the installers do: `python connect.py ...`, or in the native build
    `squidbrake connect.py ...` (squidbrake.cli runs it)."""
    exe = sys.executable
    if sys.platform == "win32" and exe.lower().endswith("pythonw.exe"):
        exe = exe[:-5] + ".exe" if Path(exe[:-5] + ".exe").exists() else exe
    return [exe, str(HERE / name), *args]


def _quiet_run(cmd: list[str]) -> tuple[bool, str]:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180, creationflags=flags,
                           env={**os.environ, "SQUIDBRAKE_NO_BROWSER": "1"})
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)


def wire_agents(dashboard: str, key: str) -> list[str]:
    """What the install command on the start page does after installing (insights/install.sh): every agent here goes
    through the dashboard. -> lines saying what happened."""
    said = []
    common = ["--url", dashboard, "--key", key, "--yes"]
    if shutil.which("claude") or (Path.home() / ".claude").exists():
        ok, _ = _quiet_run(_script("connect.py", "claude-code", *common, "--hook-only"))
        said.append("Claude Code: connected" if ok else "Claude Code couldn't be connected (Reconnect agents tries again)")
    ok, out = _quiet_run(_script("connect.py", "agents", "--agent", "all", *common))
    said += [ln.strip() for ln in out.splitlines() if ln.strip().startswith("[")][:12]
    _quiet_run(_script("connect.py", "guard", "--agent", "all", *common))
    if not said:
        said.append("No AI agents found here yet: install one, then choose Reconnect agents in the Squidbrake menu")
    try:
        import onboard
        onboard.make_shortcuts(dashboard.rstrip("/") + "/dashboard")
    except Exception:
        pass
    return said


def finish(email: str, s: dict) -> list[str]:
    """Keep the sign-in, connect the agents."""
    cfg = {"server": SERVER, "email": email.strip().lower(), "company": s.get("company") or "",
           "dashboard": s["dashboard"], "agent_key": s["agent_key"], "device_token": s["device_token"],
           "device": device_name(), "signed_in_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    save(cfg)
    return wire_agents(cfg["dashboard"], cfg["agent_key"])


# ---------------------------------------------------------------------------- is it working

def gateway_answers(cfg: dict) -> bool:
    req = urllib.request.Request(cfg["dashboard"].rstrip("/") + "/v1/me", headers={"X-Gateway-Key": cfg["agent_key"]})
    try:
        with urllib.request.urlopen(req, timeout=8):
            return True
    except Exception:
        return False


def heartbeat(cfg: dict) -> dict:
    """-> {state, dashboard}; ApiError 401 when this computer was signed out (or its dashboard deleted)."""
    return api("POST", "/v1/app/heartbeat", {"token": cfg["device_token"], "version": _version(),
                                              "os": f"{platform.system()} {platform.release()}"[:40]},
               server=cfg.get("server"))


def check(cfg: dict, beat: bool) -> tuple[str, str]:
    """-> (colour, what to show): green protecting, amber waking / waiting, grey can't reach it, red signed out."""
    state, answers = None, gateway_answers(cfg)
    if beat or not answers:              # not answering: maybe asleep, and the heartbeat wakes it
        try:
            state = heartbeat(cfg).get("state")
        except ApiError as e:
            if e.status in (401, 410):
                return "red", "Signed out: sign in again"
    if answers:
        return "green", "Protecting your agents"
    if state in ("sleeping", "waiting", "requested"):
        return "amber", "Waking your dashboard…"
    return "grey", "Can't reach your dashboard"


# ---------------------------------------------------------------------------- start at login

def _app_command() -> list[str]:
    exe = Path(sys.executable)
    if getattr(sys, "frozen", False):
        app_exe = exe.with_name("squidbrake-app.exe")             # Windows: the build without a console window
        return [str(app_exe)] if app_exe.exists() else [str(exe), "app"]
    if sys.platform == "win32":
        w = exe.with_name("pythonw.exe")
        exe = w if w.exists() else exe
    return [str(exe), str(HERE / "desktop.py"), "run"]


def _plist() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def _autostart_file() -> Path:
    return Path(os.getenv("XDG_CONFIG_HOME") or Path.home() / ".config") / "autostart" / "squidbrake-app.desktop"


def login_item(on: bool | None = None) -> bool:
    """Start the app at every login (on=True), stop that (False), or just say whether it does (None)."""
    if sys.platform == "darwin":
        p = _plist()
        if on:
            import plistlib
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(plistlib.dumps({"Label": LABEL, "ProgramArguments": _app_command(), "RunAtLoad": True,
                                          "ProcessType": "Interactive", "LimitLoadToSessionType": "Aqua"}))
        elif on is False:
            p.unlink(missing_ok=True)
        return p.exists()
    if sys.platform == "win32":
        import winreg
        cmd = " ".join(f'"{c}"' for c in _app_command())
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_ALL_ACCESS) as k:
            if on:
                winreg.SetValueEx(k, RUN_VALUE, 0, winreg.REG_SZ, cmd)
            elif on is False:
                try:
                    winreg.DeleteValue(k, RUN_VALUE)
                except OSError:
                    pass
            try:
                winreg.QueryValueEx(k, RUN_VALUE)
                return True
            except OSError:
                return False
    f = _autostart_file()
    if on:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("[Desktop Entry]\nType=Application\nName=Squidbrake\nComment=Keeps your AI agents connected\n"
                     f"Exec={' '.join(chr(34) + c + chr(34) for c in _app_command())}\nX-GNOME-Autostart-enabled=true\n", encoding="utf-8")
    elif on is False:
        f.unlink(missing_ok=True)
    return f.exists()


# ---------------------------------------------------------------------------- the sign-in page (in the browser)

PAGE = (HERE / "app_signin.html") if (HERE / "app_signin.html").exists() else None


class SignIn:
    """A page on 127.0.0.1, at a random address only this app knows (so another website can't drive it), that walks
    through email -> code -> waiting for the dashboard -> agents connected. squidbrake.com does the checking."""

    def __init__(self, on_done=None):
        self.token = secrets.token_urlsafe(18)
        self.on_done = on_done
        self.email = ""
        self.link: dict | None = None
        self.done: dict | None = None
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/{self.token}/"

    def close(self) -> None:
        self.server.shutdown()

    def _finish(self, s: dict) -> None:
        said = finish(self.email, s)
        self.done = {"state": "done", "dashboard": s["dashboard"], "agents": said, "company": s.get("company")}
        if self.on_done:
            self.on_done()

    def handle(self, path: str, body: dict) -> tuple[int, dict]:
        try:
            if path == "code":
                self.email = (body.get("email") or "").strip()
                send_code(self.email)
                return 200, {"ok": True}
            if path == "connect":
                self.done = None
                self.link = start_link(self.email, body.get("code") or "")
                if self.link.get("state") == "connected":     # a key was ready: it came with this answer, once
                    self._finish(self.link)
                return 200, {"state": self.link.get("state"), "say": describe(self.link)}
            if path == "poll":
                if self.done:
                    return 200, self.done
                if not self.link:
                    return 409, {"detail": "sign in first"}
                s = poll(self.link["link"])
                if s.get("state") != "connected":
                    return 200, {"state": s.get("state"), "ahead": s.get("ahead"), "say": describe(s)}
                self._finish(s)
                return 200, self.done
        except ApiError as e:
            return (e.status if 400 <= e.status < 600 else 502), {"detail": e.detail}
        return 404, {"detail": "not here"}

    def _handler(self):
        app = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code: int, body: bytes, kind: str) -> None:
                self.send_response(code)
                self.send_header("Content-Type", kind)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path.rstrip("/") != f"/{app.token}":
                    return self._send(404, b"not found", "text/plain")
                html = PAGE.read_text(encoding="utf-8") if PAGE else "<p>Run: squidbrake login</p>"
                self._send(200, html.replace("__DEVICE__", json.dumps(device_name())).encode(), "text/html; charset=utf-8")

            def do_POST(self):
                parts = self.path.strip("/").split("/")
                if len(parts) != 2 or parts[0] != app.token:
                    return self._send(404, b"{}", "application/json")
                try:
                    body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 10_000)) or b"{}")
                except ValueError:
                    body = {}
                code, out = app.handle(parts[1], body)
                self._send(code, json.dumps(out).encode(), "application/json")
        return H


# ---------------------------------------------------------------------------- the icon

def _pid_path() -> Path:
    return state_dir() / "app.pid"


def _running_elsewhere() -> bool:
    try:
        pid = int(_pid_path().read_text())
        if pid == os.getpid():
            return False
        if sys.platform == "win32":
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
            return str(pid) in out
        os.kill(pid, 0)
        return True
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def _image(colour: str):
    from PIL import Image, ImageDraw
    fill = {"green": (35, 116, 71), "amber": (214, 140, 30), "grey": (140, 150, 145), "red": (192, 48, 28)}[colour]
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((6, 6, 58, 58), fill=(242, 98, 46))                 # Squidbrake orange
    d.ellipse((34, 34, 60, 60), fill=fill, outline=(255, 255, 255), width=3)   # the status dot
    return img


def run_tray() -> int:
    try:
        import pystray
    except ImportError:
        print("The Squidbrake icon needs pystray and Pillow: pip install \"squidbrake[app]\"\n"
              "Or sign in from this terminal instead: squidbrake login")
        return 1
    if _running_elsewhere():               # opened again: show what's useful instead of a second icon
        cfg = load()
        webbrowser.open(cfg["dashboard"].rstrip("/") + "/dashboard" if cfg.get("dashboard") else SERVER + "/signup")
        return 0
    _pid_path().parent.mkdir(parents=True, exist_ok=True)
    _pid_path().write_text(str(os.getpid()))
    if sys.platform == "darwin":
        try:   # a menu-bar app: no Dock icon
            from AppKit import NSApplication
            NSApplication.sharedApplication().setActivationPolicy_(1)
        except Exception:
            pass

    status = {"colour": "grey", "text": "Starting…"}
    wake = threading.Event()
    signin: dict[str, SignIn | None] = {"page": None}

    def signed_in() -> bool:
        return bool(load().get("device_token"))

    def signed_in_now():
        wake.set()                                           # green straight away, not in a minute
        if icon.HAS_NOTIFICATION:
            icon.notify("Your agents are connected. Reopen them and work as usual.", "Squidbrake")

    def open_signin(*_):
        if not signin["page"]:
            signin["page"] = SignIn(on_done=signed_in_now)
        webbrowser.open(signin["page"].url)

    def open_dashboard(*_):
        cfg = load()
        webbrowser.open(cfg["dashboard"].rstrip("/") + "/dashboard" if cfg.get("dashboard") else SERVER + "/signup")

    def reconnect(*_):
        cfg = load()
        if cfg.get("agent_key"):
            threading.Thread(target=lambda: (wire_agents(cfg["dashboard"], cfg["agent_key"]), wake.set()),
                             daemon=True).start()

    def toggle_login(*_):
        login_item(not login_item())

    def quit_app(*_):
        icon.stop()

    menu = pystray.Menu(
        pystray.MenuItem(lambda _: status["text"], None, enabled=False),
        pystray.MenuItem(lambda _: (load().get("company") or load().get("email") or "Not signed in"), None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Open dashboard", open_dashboard, default=True, visible=lambda _: signed_in()),
        pystray.MenuItem("Sign in…", open_signin, visible=lambda _: not signed_in()),
        pystray.MenuItem("Reconnect agents", reconnect, visible=lambda _: signed_in()),
        pystray.MenuItem("Start at login", toggle_login, checked=lambda _: login_item()),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit Squidbrake", quit_app),
    )
    icon = pystray.Icon("squidbrake", _image("grey"), "Squidbrake", menu)

    def watch():
        last_beat = 0.0
        while True:
            cfg = load()
            if not cfg.get("device_token"):
                status.update(colour="grey", text="Not signed in")
            else:
                beat = time.time() - last_beat > HEARTBEAT_SECONDS
                colour, text = check(cfg, beat)
                if beat:
                    last_beat = time.time()
                if colour == "red":
                    forget()
                status.update(colour=colour, text=text)
            icon.icon = _image(status["colour"])
            icon.title = f"Squidbrake: {status['text']}"
            icon.update_menu()
            wake.wait(CHECK_SECONDS if status["colour"] == "green" else 15)
            wake.clear()

    def setup(ic):
        ic.visible = True
        if not login_item():
            try:
                login_item(True)          # an app you installed to protect you: on at every login, off from the menu
            except Exception:
                pass
        if not signed_in():
            open_signin()
        threading.Thread(target=watch, daemon=True).start()

    try:
        icon.run(setup=setup)
    finally:
        try:
            _pid_path().unlink()
        except OSError:
            pass
    return 0


# ---------------------------------------------------------------------------- terminal

def login_terminal(argv: list[str]) -> int:
    email = argv[argv.index("--email") + 1] if "--email" in argv[:-1] else input("Your email: ").strip()
    try:
        send_code(email)
        print(f"We emailed a 6-digit code to {email}.")
        first = start_link(email, input("The code: ").strip())
        s = wait_connected(first, on_state=lambda s: print("  " + describe(s)))
    except ApiError as e:
        print(f"[X] {e.detail}")
        return 1
    except KeyboardInterrupt:
        return 130
    for line in finish(email, s):
        print("  " + line)
    print(f"\nConnected to {s['dashboard']}. Quit and reopen your agents, then work as usual.")
    print(f"Your dashboard: {s['dashboard']}/dashboard")
    return 0


def status_terminal() -> int:
    cfg = load()
    if not cfg.get("device_token"):
        print("Not signed in. Run: squidbrake app   (or: squidbrake login)")
        return 1
    colour, text = check(cfg, beat=True)
    print(f"{text}\n  dashboard: {cfg['dashboard']}\n  signed in as {cfg.get('email')} on {cfg.get('device')}"
          f"\n  starts at login: {'yes' if login_item() else 'no'}")
    return 0 if colour == "green" else 1


def signout() -> int:
    cfg = load()
    if cfg.get("device_token"):
        try:
            api("POST", "/v1/app/signout", {"token": cfg["device_token"]}, server=cfg.get("server"))
        except ApiError:
            pass
    if cfg.get("dashboard"):
        _quiet_run(_script("connect.py", "all", "--remove", "--yes"))
    forget()
    login_item(False)
    print("Signed out: this computer's agents are no longer connected, and the app won't start at login.")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["login"]:
        return login_terminal(argv[1:])
    if "--status" in argv:
        return status_terminal()
    if "--signout" in argv:
        return signout()
    if "--no-login-item" in argv:
        login_item(False)
        return 0
    return run_tray()


if __name__ == "__main__":
    sys.exit(main())

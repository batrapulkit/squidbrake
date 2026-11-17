"""
squidbrake setup: everything a person needs on this computer, in one go (the installers run it at the end).

  1. the keys (the first time; shown once)
  2. the gateway, running in the background and at every login (they chose "set it all up", so no question here;
     turn it off any time: squidbrake service stop)
  3. every AI agent on this computer connected to it (Claude Code, Cursor, Codex, ... and their MCP servers)
  4. a check of every hook, end to end (doctor), then two optional questions: a terminal guard, and rule packs for
     what the agents touch besides code (support, finance, ops, back-office, crypto)
  5. the dashboard opened in the browser, already signed in the first time (the key goes in the address's #part,
     which never leaves this computer)

  squidbrake setup [--port 8080] [--no-browser] [--packs support,finance]
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse


def _say(mark: str, text: str) -> None:
    print(f"  [{mark}] {text}", flush=True)


def offer_terminal_guard(yes: bool) -> None:
    import shell_guard
    shell = shell_guard.this_shell()
    if not yes:
        try:
            if not (sys.stdin.isatty() and sys.stdout.isatty()):
                return
            answer = input("\nAlso warn you in your own terminal before a command that can't be undone (git push --force,\n"
                           f"rm -r, DROP TABLE)? It adds a few lines to your {shell} startup file. [y/N] ")
        except (EOFError, KeyboardInterrupt, OSError):
            return
        if answer.strip().lower() not in ("y", "yes"):
            print("  Skipped. Later:  squidbrake shell-guard install --write")
            return
    try:
        _say("OK", shell_guard.write(shell))
    except OSError as e:
        _say("!", f"Couldn't add the terminal guard ({e}). Later:  squidbrake shell-guard install --write")


def offer_packs(chosen: str | None) -> None:
    """Rules for what the agents touch besides code (policy_edit.PACKS), picked by number: no YAML to write."""
    import policy_edit
    import server
    try:
        have = set(server._rule_ids(server.RULES_PATH))
    except Exception:       # no readable rules file: nothing to add to
        return
    packs = [(k, p) for k, p in policy_edit.PACKS.items() if not policy_edit._ids(p["yaml"]) <= have]
    if not packs:
        return
    if chosen is None:
        try:
            if not (sys.stdin.isatty() and sys.stdout.isatty()):
                return
            print("\nDo your agents touch anything besides code? Each one adds rules for it (change them later in the "
                  "dashboard, Settings > Rules):")
            for i, (_, p) in enumerate(packs, 1):
                print(f"  {i}. {p['title']}: {p['about']}")
            answer = input("Numbers, e.g. 1,3 (Enter: just code): ")
        except (EOFError, KeyboardInterrupt, OSError):
            return
        picked = [packs[int(n) - 1][0] for n in answer.replace(",", " ").split() if n.isdigit() and 0 < int(n) <= len(packs)]
    else:
        picked = [k for k in chosen.split(",") if k in dict(packs)]
    for k in picked:
        p = policy_edit.PACKS[k]
        try:
            server._add_rules(p["yaml"], p.get("before"), "setup", f"pack:{k}")
            _say("OK", f"Added the {p['title']} rules")
        except Exception as e:
            _say("!", f"Couldn't add the {p['title']} rules ({getattr(e, 'detail', e)}). Later: dashboard, Settings > Rules")
    if not picked:
        print("  Just code. Later: dashboard, Settings > Rules > Starter packs")


# ---- the dashboard: one command and one icon, whether it runs on this computer or is hosted

SHORTCUT = "Squidbrake dashboard"


def dashboard_url() -> str:
    """The dashboard this computer's agents use: a hosted one (a pilot), or this computer's own gateway."""
    import connect
    hooked = connect._hooked_gateway()
    base = hooked[0] if hooked else f"http://localhost:{os.getenv('PORT', '8080')}"
    return base.rstrip("/").replace("//127.0.0.1", "//localhost", 1) + "/dashboard"


def open_dashboard(url: str | None = None) -> bool:
    """Open it in the browser (not over SSH, on a desktop-less Linux box, or with SQUIDBRAKE_NO_BROWSER)."""
    import service
    import webbrowser
    if os.getenv("SQUIDBRAKE_NO_BROWSER") or not service.can_open_browser():
        return False
    return webbrowser.open(url or dashboard_url())


def _desktop() -> Path:
    if sys.platform == "win32":     # the real one, also when OneDrive moved it
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders") as k:
                return Path(winreg.QueryValueEx(k, "Desktop")[0])
        except OSError:
            pass
    return Path.home() / "Desktop"


def _logo(name: str) -> Path | None:
    """The logo, copied next to Squidbrake's data so the icon keeps working after an upgrade moves the package."""
    import shutil
    import service
    here = Path(__file__).resolve().parent
    src = next((d / name for d in (here / "assets", here / "squidbrake" / "assets") if (d / name).is_file()), None)
    if src is None:
        return None
    try:
        dest = service.state_dir() / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        return dest
    except OSError:
        return src


def make_shortcuts(url: str) -> list[Path]:
    """A 'Squidbrake dashboard' icon: desktop and Start menu (Windows), desktop (macOS), applications menu (Linux).
    Plain links to the address, nothing runs. Not with SQUIDBRAKE_NO_SHORTCUT."""
    if os.getenv("SQUIDBRAKE_NO_SHORTCUT"):
        return []
    if sys.platform == "win32":
        icon = _logo("squidbrake.ico")
        body = f"[InternetShortcut]\r\nURL={url}\r\n" + (f"IconFile={icon}\r\nIconIndex=0\r\n" if icon else "")
        ext = ".url"
        dirs = [_desktop(), Path(os.getenv("APPDATA") or Path.home()) / "Microsoft" / "Windows" / "Start Menu" / "Programs"]
    elif sys.platform == "darwin":     # shortcut: a .webloc shows the browser's icon; the logo needs an app bundle
        import plistlib
        body, ext, dirs = plistlib.dumps({"URL": url}).decode(), ".webloc", [_desktop()]
    else:
        body = f"[Desktop Entry]\nType=Link\nName={SHORTCUT}\nURL={url}\nIcon={_logo('squidbrake.png') or 'web-browser'}\n"
        ext, dirs = ".desktop", [Path.home() / ".local" / "share" / "applications"]
    made = []
    for d in dirs:
        if d.is_dir():              # never makes a folder: a computer without a desktop gets no desktop icon
            try:
                (d / (SHORTCUT + ext)).write_bytes(body.encode("utf-8"))   # as written: no \r\r\n on Windows
                made.append(d / (SHORTCUT + ext))
            except OSError:
                pass
    return made


def dashboard_main(argv: list[str]) -> int:
    """squidbrake dashboard [--shortcut]: open it, or (re)make the icon."""
    url = dashboard_url()
    if "--shortcut" in argv:
        made = make_shortcuts(url)
        print("\n".join(f"  [OK] {p}" for p in made) or "  No desktop or menu folder here; the dashboard is at " + url)
        return 0
    import service
    if urlparse(url).hostname == "localhost" and not service._answering(urlparse(url).port or 80):
        print("Squidbrake isn't running on this computer. Start it with:  squidbrake start\n"
              "(then your agents work again, and this opens the dashboard)")
        return 1
    if not open_dashboard(url):
        print(url)
    return 0


def main(argv: list[str] | None = None) -> int:
    import policy_edit
    p = argparse.ArgumentParser(prog="squidbrake setup", description="Set Squidbrake up on this computer, in one go.")
    p.add_argument("--port", type=int, default=int(os.getenv("PORT", "8080")))
    p.add_argument("--no-browser", action="store_true", help="don't open the dashboard")
    p.add_argument("--terminal-guard", action="store_true",
                   help="also warn in your own terminal before a command that can't be undone (without asking)")
    p.add_argument("--packs", metavar="PACKS",
                   help="add these rule packs without asking, comma-separated: " + ", ".join(policy_edit.PACKS))
    p.add_argument("--agent", dest="only", action="append", metavar="AGENT",
                   help="connect only this agent (repeat, or comma-separated; default: every one found here). "
                        "The installers pass SQUIDBRAKE_AGENTS")
    args = p.parse_args(argv)

    import connect
    import server
    import service

    port, local = args.port, f"http://127.0.0.1:{args.port}"
    shown = f"http://localhost:{args.port}"
    print(f"\nSetting up Squidbrake on this computer...\n", flush=True)

    # ---- 1. the gateway: already running (a second setup), or the port must be free for it
    running = service._answering(port)
    if not running and (taken := server.port_in_use("127.0.0.1", port)):
        _say("X", f"Port {port} is already in use: {taken}.")
        print(f"      Stop that, or set up on another port:  {server.CLI} setup --port {port + 10}\n")
        return 1
    created = None if server.keystore.disabled else server.keystore.ensure_initialized()
    shown_keys = []

    def keys_now() -> None:
        # The keys are shown only once: whatever stops setup from here on, they're printed before it ends
        if not shown_keys:
            shown_keys.append(True)
            server.print_banner(shown, created)

    kind = service.backend()
    # an older install's service (or an older version) answering: set the service up again, pointing at this one
    replace = running and bool(kind) and service.stale(kind, server.VERSION)
    if running and not replace:
        _say("OK", f"Squidbrake is already running at {shown}")
    elif kind:
        if replace:
            _say("OK", f"Another Squidbrake (an older install or version) was running: switching to this one, {server.VERSION}")
        os.environ["SQUIDBRAKE_NO_BROWSER"] = "1"         # opened below, signed in
        service._save_choice(True)
        service.start(["--background", "--port", str(port)])
        for _ in range(40):
            if service._answering(port):
                break
            time.sleep(0.5)
        if not service._answering(port):
            _say("X", f"The background service didn't start (see above). Check it with:  {server.CLI} service status")
            print(f"      Run it in a window instead:  {server.CLI} run   then:  {server.CLI} connect all\n")
            keys_now()
            return 1
        _say("OK", "Squidbrake runs in the background, and starts by itself whenever you log in")
    else:
        # Docker, or Linux without a systemd user session: nothing to keep it running, so it can't be done for them
        _say("!", f"This computer can't run it in the background. In another window, run:  {server.CLI} run")
        print("      (keep that window open: while it isn't running, your agents' actions are blocked)")

    # ---- 2. every agent on this computer
    print()
    only = args.only or ([os.environ["SQUIDBRAKE_AGENTS"]] if os.getenv("SQUIDBRAKE_AGENTS") else None)
    try:
        connect.connect_all(argparse.Namespace(url=shown, key=None, remove=False, yes=True, only=only, steps=False))
    except (Exception, SystemExit) as e:
        _say("X", f"Connecting the agents stopped: {e}")
        print(f"      Fix that, then run:  {server.CLI} connect all\n")
        keys_now()
        return 1

    if not connect.connected_agents():
        _say("!", f"Installed, but no agent connected yet (none of Claude Code, Cursor, Codex, Gemini CLI, VS Code or "
                  f"Antigravity found here). Install one, then run:  {server.CLI} connect all")

    # ---- 3. check every hook end to end
    print("\nChecking every connected agent...\n")
    try:
        connect.doctor(argparse.Namespace(url=None, key=None, quick=True))
    except SystemExit:
        pass

    # ---- your own terminal: the same warning before a command that can't be undone (asked; Enter means no)
    offer_terminal_guard(args.terminal_guard)
    offer_packs(args.packs)

    # ---- 4. the keys (once) and the dashboard
    keys_now()
    url = f"{shown}/dashboard" + (f"#key={created['admin']}" if created else "")
    if not args.no_browser and server.can_open_browser() and service._answering(port):
        import webbrowser
        webbrowser.open(url)
        _say("OK", "Opened the dashboard" + (", signed in" if created else ""))
    if not created:
        print(f"  Sign in to the dashboard with the admin key you saved the first time.\n"
              f"  Lost it? Make a new one:  {server.CLI} add-key yourname --approver --role admin")
    if make_shortcuts(f"{shown}/dashboard"):
        _say("OK", f"Added a '{SHORTCUT}' icon to your desktop and menu. Any time later:  {server.CLI} dashboard")
    print("\nLast step: quit and reopen your agents (Claude Code, Cursor, ...), then work as usual.")
    print(f"Something not right later? Run:  {server.CLI} doctor\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

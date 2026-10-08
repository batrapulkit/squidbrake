"""
squidbrake setup: everything a person needs on this computer, in one go (the installers run it at the end).

  1. the keys (the first time; shown once)
  2. the gateway, running in the background and at every login (they chose "set it all up", so no question here;
     turn it off any time: squidbrake service stop)
  3. every AI agent on this computer connected to it (Claude Code, Cursor, Codex, ... and their MCP servers)
  4. a check of every hook, end to end (doctor)
  5. the dashboard opened in the browser, already signed in the first time (the key goes in the address's #part,
     which never leaves this computer)

  squidbrake setup [--port 8080] [--no-browser]
"""
from __future__ import annotations

import argparse
import os
import sys
import time


def _say(mark: str, text: str) -> None:
    print(f"  [{mark}] {text}", flush=True)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="squidbrake setup", description="Set Squidbrake up on this computer, in one go.")
    p.add_argument("--port", type=int, default=int(os.getenv("PORT", "8080")))
    p.add_argument("--no-browser", action="store_true", help="don't open the dashboard")
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

    if running:
        _say("OK", f"Squidbrake is already running at {shown}")
    elif service.backend():
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
            return 1
        _say("OK", "Squidbrake runs in the background, and starts by itself whenever you log in")
    else:
        # Docker, or Linux without a systemd user session: nothing to keep it running, so it can't be done for them
        _say("!", f"This computer can't run it in the background. In another window, run:  {server.CLI} run")
        print("      (keep that window open: while it isn't running, your agents' actions are blocked)")

    # ---- 2. every agent on this computer
    print()
    connect.connect_all(argparse.Namespace(url=shown, key=None, remove=False, yes=True))

    # ---- 3. check every hook end to end
    print("\nChecking every connected agent...\n")
    try:
        connect.doctor(argparse.Namespace(url=None, key=None, quick=True))
    except SystemExit:
        pass

    # ---- 4. the keys (once) and the dashboard
    server.print_banner(shown, created)
    url = f"{shown}/dashboard" + (f"#key={created['admin']}" if created else "")
    if not args.no_browser and server.can_open_browser() and service._answering(port):
        import webbrowser
        webbrowser.open(url)
        _say("OK", "Opened the dashboard" + (", signed in" if created else ""))
    if not created:
        print(f"  Sign in to the dashboard with the admin key you saved the first time.\n"
              f"  Lost it? Make a new one:  {server.CLI} add-key yourname --approver --role admin")
    print("\nLast step: quit and reopen your agents (Claude Code, Cursor, ...), then work as usual.")
    print(f"Something not right later? Run:  {server.CLI} doctor\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

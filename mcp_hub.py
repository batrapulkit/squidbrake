"""
MCP servers by URL, on the gateway itself: https://<gateway>/mcp/<name>.

For agents that connect to MCP by URL instead of starting a command: ChatGPT and claude.ai connectors, Devin, n8n,
cloud agents. An admin adds an app's MCP server in the dashboard (Settings, "Agents that connect by URL"); the gateway
then runs one `gateway_proxy.py --serve` for it on 127.0.0.1, and /mcp/<name> passes each caller through to it with the
caller's own agent key. So every call is checked, held or blocked like any other, and recorded as the agent that made
it. Nothing but the gateway can reach those proxies (a random token, local address only).

Hosted dashboards take remote MCP servers: a URL, plus the headers its auth needs, or a browser sign-in (OAuth, see
mcp_oauth.py) for servers that take nothing else. Servers started by a command are for self-hosted gateways only:
set SQUIDBRAKE_MCP_COMMANDS=1.
"""
from __future__ import annotations

import logging
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
from pathlib import Path

log = logging.getLogger("gateway.mcp")
HERE = Path(__file__).resolve().parent
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
COMMANDS_ALLOWED = os.getenv("SQUIDBRAKE_MCP_COMMANDS", "").lower() in ("1", "true", "yes")


def check(name: str, cfg: dict) -> dict:
    """A server's settings, cleaned, or ValueError saying what's wrong."""
    if not NAME_RE.match(name or ""):
        raise ValueError("name: lowercase letters, digits and '-', up to 40, e.g. 'github'")
    url, command = (cfg.get("url") or "").strip(), cfg.get("command")
    if url and cfg.get("auth") == "oauth":
        if not re.match(r"^https?://", url):
            raise ValueError("url must start with https:// (or http://)")
        out = {"url": url, "auth": "oauth"}
        for k, limit in (("client_id", 300), ("client_secret", 500), ("scope", 1000)):
            v = (cfg.get(k) or "").strip()
            if len(v) > limit or "\n" in v:
                raise ValueError(f"{k} is too long")
            if v:
                out[k] = v
        if "client_secret" in out and "client_id" not in out:
            raise ValueError("a client secret needs its client ID")
        return out
    if url:
        if not re.match(r"^https?://", url):
            raise ValueError("url must start with https:// (or http://)")
        headers = cfg.get("headers") or {}
        if not isinstance(headers, dict) or len(headers) > 10 or not all(
                HEADER_RE.match(str(k)) and isinstance(v, str) and len(v) <= 4000 and "\n" not in v for k, v in headers.items()):
            raise ValueError("headers: up to 10, names of letters, digits and '-'")
        return {"url": url, "headers": {str(k): v for k, v in headers.items()}}
    if command:
        if not COMMANDS_ALLOWED:
            raise ValueError("this gateway only takes MCP servers by URL; servers started by a command need a "
                             "self-hosted gateway with SQUIDBRAKE_MCP_COMMANDS=1")
        args = cfg.get("args") or []
        if not isinstance(command, str) or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise ValueError("command is a string and args a list of strings")
        env = cfg.get("env") or {}
        if not isinstance(env, dict) or not all(isinstance(v, str) for v in env.values()):
            raise ValueError("env: names and string values")
        return {"command": command, "args": args, "env": {str(k): v for k, v in env.items()}}
    raise ValueError("give the server's url (or, self-hosted, its command)")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Hub:
    """One local, token-locked proxy per configured MCP server, kept running and matched to the settings."""

    def __init__(self, gateway_url, data_dir: Path):
        self.gateway_url = gateway_url          # callable: the address the proxies reach this gateway at
        self.data_dir = data_dir
        self.token = secrets.token_urlsafe(32)
        self._procs: dict[str, tuple[subprocess.Popen, int, str]] = {}   # name -> (process, port, settings signature)
        self._lock = threading.Lock()

    def _start(self, name: str, cfg: dict) -> tuple[subprocess.Popen, int]:
        port = _free_port()
        env = {**os.environ, "GATEWAY_URL": self.gateway_url(), "GATEWAY_API_KEY": "", "GATEWAY_SOURCE": f"mcp-{name}",
               "SQUIDBRAKE_PROXY_TOKEN": self.token, "GATEWAY_PENDING_DIR": str(self.data_dir / "mcp-pending" / name),
               "DO_NOT_TRACK": "1", "SQUIDBRAKE_PARENT_PID": str(os.getpid())}   # it stops when the gateway does
        cmd = [sys.executable, str(HERE / "gateway_proxy.py"), "--app", name, "--serve", f"127.0.0.1:{port}"]
        if cfg.get("auth") == "oauth":
            cmd += ["--url", cfg["url"], "--oauth-store", str(self.oauth_path(name))]
        elif "url" in cfg:
            cmd += ["--url", cfg["url"]]
            for i, (k, v) in enumerate(cfg["headers"].items()):
                env[f"SB_MCP_HEADER_{i}"] = v      # secrets ride in the environment, not the arguments (expanded once)
                cmd += ["--header", f"{k}: ${{SB_MCP_HEADER_{i}}}"]
        else:
            env.update(cfg["env"])
            cmd += ["--", cfg["command"], *cfg["args"]]
        logfile = self.data_dir / f"mcp-{name}.log"
        logfile.parent.mkdir(parents=True, exist_ok=True)
        with open(logfile, "ab") as out:
            p = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=out, cwd=str(HERE))
        log.info("MCP server '%s' guarded at /mcp/%s (local port %d)", name, name, port)
        return p, port

    def sync(self, servers: dict[str, dict]) -> None:
        """Start, restart or stop proxies so they match the settings."""
        with self._lock:
            for name in list(self._procs):
                if name not in servers:
                    self._stop(name)
            for name, cfg in servers.items():
                sig = repr(sorted(cfg.items()))
                running = self._procs.get(name)
                if running and running[2] == sig and running[0].poll() is None:
                    continue
                if running:
                    self._stop(name)
                try:
                    p, port = self._start(name, cfg)
                    self._procs[name] = (p, port, sig)
                except Exception:
                    log.exception("could not start the proxy for MCP server '%s'", name)

    def _stop(self, name: str) -> None:
        p, _, _ = self._procs.pop(name)
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()

    def port(self, name: str, servers: dict[str, dict]) -> int | None:
        """The local port serving `name`, (re)starting its proxy if it isn't running."""
        running = self._procs.get(name)
        if name in servers and (not running or running[0].poll() is not None):
            self.sync(servers)
            running = self._procs.get(name)
        return running[1] if running else None

    def oauth_path(self, name: str) -> Path:
        return self.data_dir / "mcp-oauth" / f"{name}.json"

    def restart(self, name: str, servers: dict[str, dict]) -> None:
        """Start `name`'s proxy again (after a sign-in, so it picks up the new tokens)."""
        with self._lock:
            if name in self._procs:
                self._stop(name)
        self.sync(servers)

    def running(self, name: str) -> bool:
        r = self._procs.get(name)
        return bool(r and r[0].poll() is None)

    def stop_all(self) -> None:
        with self._lock:
            for name in list(self._procs):
                self._stop(name)

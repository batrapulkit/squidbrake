"""
Put Squidbrake in front of ANY app's MCP connector: Stripe, GitHub, Slack, Gmail, Linear, Notion,
a database, an internal tool... The agent sees the app's normal tools; every call is checked against
the rules, recorded, and held for a human when a rule says so, before it reaches the app.

    python gateway_proxy.py --app stripe -- npx -y @stripe/mcp --tools=all
    python gateway_proxy.py --app github -- docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN ghcr.io/github/github-mcp-server
    python gateway_proxy.py --app acme   -- python demo_apps_mcp.py        (the sandbox company)
    python gateway_proxy.py --app crm --url https://crm.example.com/mcp    (a remote MCP server)

Served over HTTP, for agents that connect to MCP by URL (ChatGPT and claude.ai connectors, Devin, n8n, cloud agents):

    python gateway_proxy.py --app github --serve 0.0.0.0:9000 --token SECRET -- npx -y @modelcontextprotocol/server-github
    -> the agent connects to http(s)://this-host:9000/mcp with "Authorization: Bearer SECRET" (or ?token=SECRET)

Calls show up in the dashboard as <app>.<tool>, e.g. stripe.create_refund, so rules can target them.
The app's own credentials (e.g. STRIPE_SECRET_KEY) go in the agent's MCP config env as usual; they are
passed to the app, never to the gateway. Gateway settings: see gw_async.py.
Easiest setup:  python connect.py wrap --app NAME --agent claude-code -- <the app's MCP command>
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
import uuid
from contextlib import asynccontextmanager

from mcp import Client, types
from mcp.client.stdio import StdioServerParameters
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

import gw_async as gw
from gw_async import log

APP = "app"
_upstream: Client | None = None

def gateway_tools() -> list[types.Tool]:
    """The gateway's own tools, named after the app (acme_check_approval) so they never clash with another
    connector's in agents that keep one list of tools."""
    return [
        types.Tool(
            name=gw.CHECK_TOOL,
            description=f"Finish a {APP} call Squidbrake was holding for human approval (WAITING FOR HUMAN "
                        "APPROVAL): runs it if approved, reports if rejected, or keeps waiting a little longer.",
            input_schema={"type": "object", "properties": {"event_id": {"type": "string"}}, "required": ["event_id"]},
        ),
        types.Tool(name=gw.DECISIONS_TOOL, description=gw.DECISIONS_HELP,
                   input_schema={"type": "object", "properties": {}}),
    ]


def replay(call: dict):
    async def run():
        return await _upstream.call_tool(call["tool"], call.get("args") or {})
    return run


def text_result(message: str, is_error: bool = False) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=message)], is_error=is_error)


def summarize(result: types.CallToolResult) -> dict:
    """What the gateway records about the app's answer (text is kept; images/files are noted, not stored)."""
    parts = []
    for c in result.content or []:
        parts.append(c.text if getattr(c, "type", "") == "text" else f"[{getattr(c, 'type', 'content')}]")
    out: dict = {"content": parts[0] if len(parts) == 1 else parts}
    if result.structured_content is not None:
        out["structured"] = result.structured_content
    return out


async def report(event_id: str, outcome) -> types.CallToolResult:
    status, value, ms = outcome
    if status == "error":  # couldn't reach the app, or it crashed
        await gw.gw_result(event_id, error=value, duration_ms=ms)
        return text_result(f"ERROR from {APP}: {value}", is_error=True)
    summary = summarize(value)
    err = None
    if value.is_error:
        err = summary["content"] if isinstance(summary["content"], str) else json.dumps(summary["content"])[:2000]
    await gw.gw_result(event_id, output=summary, error=err, duration_ms=ms)
    return value


async def list_tools(ctx, params) -> types.ListToolsResult:
    result = await _upstream.list_tools(cursor=params.cursor if params else None)
    tools = list(result.tools)
    if not (params and params.cursor):
        tools += gateway_tools()
    return types.ListToolsResult(tools=tools, next_cursor=result.next_cursor)


IDLE_NEW_CONVERSATION = 1800       # seconds without a call before the same client starts a new conversation
_recent: dict[tuple, tuple[str, float]] = {}


def _conversation(ctx) -> str | None:
    """Served over HTTP, which conversation a call belongs to, so each one's chain is checked on its own:
    the X-Squidbrake-Session header if the caller sets one (n8n, scripts), else the MCP session of the connection,
    else (the 2026 protocol has no sessions) the same client's calls until it goes quiet for 30 minutes.
    None over stdio: one process is one conversation."""
    request = getattr(ctx, "request", None)
    if request is None or not hasattr(request, "headers"):
        return None
    headers = request.headers
    if given := headers.get("x-squidbrake-session"):
        return f"{gw.source()}-{re.sub(r'[^A-Za-z0-9_.:-]', '', given)[:60]}"
    conn = getattr(getattr(ctx, "session", None), "_connection", None)
    if sid := getattr(conn, "session_id", None) or headers.get("mcp-session-id"):
        return f"{gw.source()}-{sid[:24]}"
    params = getattr(conn, "client_params", None)
    info = getattr(params, "client_info", None) or getattr(params, "clientInfo", None)
    who = (gw.source(), getattr(info, "name", None) or "client", getattr(getattr(request, "client", None), "host", None))
    now = time.monotonic()
    sid, last = _recent.get(who, (None, 0.0))
    if not sid or now - last > IDLE_NEW_CONVERSATION:
        sid = f"{gw.source()}-{uuid.uuid4().hex[:12]}"
    _recent[who] = (sid, now)
    return sid


def _caller(ctx) -> None:
    """Served over HTTP: a caller that sends its own agent key (X-Gateway-Key) is checked and recorded as itself, and
    may say what to call it (X-Squidbrake-Source). The gateway's /mcp/<name> endpoint sends both."""
    request = getattr(ctx, "request", None)
    headers = getattr(request, "headers", None)
    if headers is None:
        return
    if key := headers.get("x-gateway-key"):
        gw.CURRENT_KEY.set(key)
    if name := re.sub(r"[^A-Za-z0-9_.:@-]", "", headers.get("x-squidbrake-source") or "")[:60]:
        gw.CURRENT_SOURCE.set(name)


async def call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
    _caller(ctx)
    if conv := _conversation(ctx):
        gw.CURRENT_SESSION.set(conv)
    args = params.arguments or {}
    on_text = lambda t: text_result(t, is_error=t.startswith("NOT RUN") or t.startswith("Unknown"))
    if params.name == gw.DECISIONS_TOOL:
        return text_result(await gw.recent_decisions())
    if params.name == gw.CHECK_TOOL:
        return await gw.check_approval(str(args.get("event_id", "")), on_done=report, on_text=on_text)

    call = {"tool": params.name, "args": args}
    return await gw.guard(f"{APP}.{params.name}", args, replay(call), on_done=report, on_text=on_text, kind="mcp",
                          call=call)


def upstream_target(args):
    if args.url:
        if not args.header and not args.oauth_store:
            return args.url
        # a remote server that needs its own auth (Authorization: Bearer ...): ${VARS} come from the environment,
        # so the secret can stay in the MCP config's env instead of its arguments
        from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client
        headers = {}
        for h in args.header:
            k, _, v = h.partition(":")
            headers[k.strip()] = os.path.expandvars(v.strip())
        auth = None
        if args.oauth_store:     # signed in through the dashboard (mcp_oauth.py): use the tokens, refresh them in time
            import mcp_oauth
            auth = mcp_oauth.provider(args.url, mcp_oauth.FileTokenStorage(args.oauth_store),
                                      redirect_uri=os.getenv("SQUIDBRAKE_OAUTH_REDIRECT", "http://localhost/unused"))
        return streamable_http_client(args.url, http_client=create_mcp_http_client(headers=headers or None, auth=auth))
    if not args.command:
        sys.exit("give the app's MCP command after --, or --url for a remote server")
    return StdioServerParameters(command=args.command[0], args=args.command[1:], env=dict(os.environ))


@asynccontextmanager
async def lifespan(server, target):
    global _upstream
    async with Client(target) as upstream:
        _upstream = upstream
        tools = (await upstream.list_tools()).tools
        log(f"guarding '{APP}' ({len(tools)} tools) -> gateway {gw.GATEWAY_URL} as '{gw.SOURCE}' (session {gw.SESSION})")
        yield {}


def make_server(target) -> Server:
    return Server(
        f"gateway-{APP}",
        instructions=f"{APP} tools. " + gw.agent_rules(),
        on_list_tools=list_tools, on_call_tool=call_tool,
        lifespan=lambda s: lifespan(s, target),
    )


async def amain(args) -> None:
    server = make_server(upstream_target(args))
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


# --------------------------------------------------------------------------- served over HTTP (--serve)
# For agents that connect to MCP by URL rather than by starting a command: ChatGPT and claude.ai connectors,
# Devin, n8n, cloud agents. One process guards one app; every connected conversation is checked on its own.

def require_token(app, token: str):
    """ASGI wrapper: only callers with the token reach the MCP endpoint. It can come as `Authorization: Bearer`,
    `X-Squidbrake-Token`, or `?token=` for clients that take only a URL."""
    import hmac
    from urllib.parse import parse_qs

    async def guarded(scope, receive, send):
        if scope["type"] != "http":
            return await app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
        given = headers.get("x-squidbrake-token") or ""
        if headers.get("authorization", "").lower().startswith("bearer "):
            given = headers["authorization"][7:].strip()
        given = given or (parse_qs(scope.get("query_string", b"").decode("latin-1")).get("token") or [""])[0]
        if not hmac.compare_digest(given.encode(), token.encode()):
            body = b'{"error": "missing or wrong Squidbrake token"}'
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"application/json"), (b"www-authenticate", b"Bearer")]})
            return await send({"type": "http.response.body", "body": body})
        return await app(scope, receive, send)
    return guarded


def _alive(pid: int) -> bool:
    if sys.platform == "win32":     # never os.kill here: on Windows it terminates the process
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)          # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        code = ctypes.c_ulong()
        k32.GetExitCodeProcess(h, ctypes.byref(code))
        k32.CloseHandle(h)
        return code.value == 259                         # STILL_ACTIVE
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _exit_with_parent() -> None:
    """Started by the gateway (mcp_hub.py): go when it goes, even if it crashed and couldn't stop us."""
    pid = int(os.getenv("SQUIDBRAKE_PARENT_PID") or 0)
    if not pid:
        return

    def watch():
        while _alive(pid):
            time.sleep(2)
        log("the gateway that started this proxy is gone; stopping")
        os._exit(0)
    import threading
    threading.Thread(target=watch, daemon=True).start()


def serve(args) -> None:
    import uvicorn
    _exit_with_parent()
    host, _, port = args.serve.rpartition(":")
    host = host or "127.0.0.1"
    token = args.token or os.getenv("SQUIDBRAKE_PROXY_TOKEN", "")
    local = host in ("127.0.0.1", "localhost", "::1")
    if not token and not local:
        sys.exit("--serve on a public address needs a token: --token SECRET or SQUIDBRAKE_PROXY_TOKEN, so only your "
                 "agents can call it")
    server = make_server(upstream_target(args))
    app = server.streamable_http_app(streamable_http_path=args.path, host=host)
    if token:
        app = require_token(app, token)
    log(f"serving '{APP}' over MCP at http://{host}:{port}{args.path}" + (" (token required)" if token else ""))
    uvicorn.run(app, host=host, port=int(port), log_level="warning")


def main() -> None:
    global APP
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--app", required=True, help="short name used in the dashboard and rules, e.g. stripe")
    p.add_argument("--url", help="a remote (streamable HTTP) MCP server instead of a command")
    p.add_argument("--header", action="append", default=[], metavar="'NAME: VALUE'",
                   help="with --url: a header the remote server needs, e.g. 'Authorization: Bearer ${GITHUB_TOKEN}' "
                        "(${VARS} are read from the environment); repeatable")
    p.add_argument("--oauth-store", metavar="FILE",
                   help="with --url: sign in with the OAuth tokens in FILE (written by the dashboard's Connect, "
                        "mcp_oauth.py) and refresh them as they run out")
    p.add_argument("--serve", metavar="HOST:PORT",
                   help="serve over HTTP instead of stdio, for agents that connect by URL (ChatGPT, claude.ai, Devin, "
                        "n8n...), e.g. --serve 0.0.0.0:9000")
    p.add_argument("--path", default="/mcp", help="with --serve: the endpoint's path (default /mcp)")
    p.add_argument("--token", help="with --serve: callers must send this (Bearer, X-Squidbrake-Token or ?token=); "
                                   "or set SQUIDBRAKE_PROXY_TOKEN. Required on a public address")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- then the app's MCP server command")
    args = p.parse_args()
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    APP = args.app
    gw.set_tool_prefix(APP)
    gw.set_replay(replay)
    gw.cleanup_pending()
    import logging
    logging.getLogger("httpx").setLevel(logging.WARNING)
    if not gw.GATEWAY_API_KEY:
        log("warning: GATEWAY_API_KEY is not set; the gateway will reject calls unless auth is off")
    if args.serve:
        serve(args)
    else:
        asyncio.run(amain(args))


if __name__ == "__main__":
    main()

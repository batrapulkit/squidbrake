"""A stand-in for an app whose MCP server signs in only with OAuth (like Slack's, HubSpot's, Notion's hosted one):
protected-resource and authorization-server metadata, dynamic client registration, an authorize page that approves at
once, a token endpoint with PKCE and refresh, and an MCP endpoint that wants a bearer token.

    python tests/fake_oauth_mcp.py PORT [TOKEN_SECONDS]      GET /stats shows what happened
"""
import base64
import hashlib
import json
import secrets
import sys
from urllib.parse import parse_qs, urlencode

import uvicorn
from mcp import types
from mcp.server.lowlevel import Server

PORT, LIFE = int(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) > 2 else 3600
BASE = f"http://127.0.0.1:{PORT}"
clients, codes, access, refresh = {}, {}, set(), set()
stats = {"registered": 0, "authorized": 0, "code_grants": 0, "refresh_grants": 0, "mcp_401": 0, "tool_calls": 0}


async def list_tools(ctx, params):
    schema = {"type": "object", "properties": {"text": {"type": "string"}}}
    return types.ListToolsResult(tools=[types.Tool(name="list_channels", description="Read", input_schema=schema),
                                        types.Tool(name="post_message", description="Post", input_schema=schema)])


async def call_tool(ctx, params):
    stats["tool_calls"] += 1
    return types.CallToolResult(content=[types.TextContent(type="text", text=f"{params.name} done")])


mcp_app = Server("fake-oauth", on_list_tools=list_tools, on_call_tool=call_tool).streamable_http_app(host="127.0.0.1")


async def send_json(send, status, body, headers=()):
    data = json.dumps(body).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), *headers]})
    await send({"type": "http.response.body", "body": data})


async def read_body(receive):
    body = b""
    while True:
        m = await receive()
        body += m.get("body", b"")
        if not m.get("more_body"):
            return body


def issue():
    a, r = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    access.add(a)
    refresh.add(r)
    return {"access_token": a, "token_type": "Bearer", "expires_in": LIFE, "refresh_token": r}


async def app(scope, receive, send):
    if scope["type"] == "lifespan":
        return await mcp_app(scope, receive, send)
    path, method = scope["path"], scope["method"]
    headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers") or []}
    query = parse_qs(scope.get("query_string", b"").decode())
    if path.startswith("/.well-known/oauth-protected-resource"):
        return await send_json(send, 200, {"resource": f"{BASE}/mcp", "authorization_servers": [BASE]})
    if path.startswith("/.well-known/oauth-authorization-server") or path.startswith("/.well-known/openid-configuration"):
        return await send_json(send, 200, {
            "issuer": BASE, "authorization_endpoint": f"{BASE}/authorize", "token_endpoint": f"{BASE}/token",
            "registration_endpoint": f"{BASE}/register", "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"], "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post"]})
    if path == "/register" and method == "POST":
        meta = json.loads(await read_body(receive))
        cid = "client-" + secrets.token_hex(4)
        clients[cid] = meta
        stats["registered"] += 1
        return await send_json(send, 201, {**meta, "client_id": cid})
    if path == "/authorize":
        q = {k: v[0] for k, v in query.items()}
        code = secrets.token_urlsafe(12)
        codes[code] = (q.get("code_challenge"), q.get("redirect_uri"), q.get("client_id"))
        stats["authorized"] += 1
        loc = q["redirect_uri"] + "?" + urlencode({"code": code, "state": q.get("state", ""), "iss": BASE})
        await send({"type": "http.response.start", "status": 302, "headers": [(b"location", loc.encode())]})
        return await send({"type": "http.response.body", "body": b""})
    if path == "/token" and method == "POST":
        form = {k: v[0] for k, v in parse_qs((await read_body(receive)).decode()).items()}
        if form.get("grant_type") == "authorization_code":
            challenge, redirect, cid = codes.pop(form.get("code", ""), (None, None, None))
            verifier = form.get("code_verifier", "")
            ok = challenge and base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode() == challenge
            if not ok or redirect != form.get("redirect_uri"):
                return await send_json(send, 400, {"error": "invalid_grant"})
            stats["code_grants"] += 1
            return await send_json(send, 200, issue())
        if form.get("grant_type") == "refresh_token" and form.get("refresh_token") in refresh:
            refresh.discard(form["refresh_token"])
            stats["refresh_grants"] += 1
            return await send_json(send, 200, issue())
        return await send_json(send, 400, {"error": "invalid_grant"})
    if path == "/stats":
        return await send_json(send, 200, stats)
    if path.startswith("/mcp"):
        token = headers.get("authorization", "")[7:] if headers.get("authorization", "").startswith("Bearer ") else ""
        if token not in access:
            stats["mcp_401"] += 1
            return await send_json(send, 401, {"error": "invalid_token"}, headers=[(
                b"www-authenticate", f'Bearer resource_metadata="{BASE}/.well-known/oauth-protected-resource/mcp"'.encode())])
        return await mcp_app(scope, receive, send)
    return await send_json(send, 404, {"error": "not found"})


uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")

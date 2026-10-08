"""A stand-in remote MCP server for tests: two tools over streamable HTTP, behind its own bearer token.

    python tests/plain_mcp_http.py PORT TOKEN
"""
import sys

import uvicorn
from mcp import types
from mcp.server.lowlevel import Server

PORT, TOKEN = int(sys.argv[1]), sys.argv[2]


async def list_tools(ctx, params):
    schema = {"type": "object", "properties": {"text": {"type": "string"}}}
    return types.ListToolsResult(tools=[types.Tool(name="list_notes", description="Read notes", input_schema=schema),
                                        types.Tool(name="delete_notes", description="Delete notes", input_schema=schema)])


async def call_tool(ctx, params):
    return types.CallToolResult(content=[types.TextContent(type="text", text=f"{params.name} done")])


app = Server("plain", on_list_tools=list_tools, on_call_tool=call_tool).streamable_http_app(host="127.0.0.1")


async def needs_token(scope, receive, send):
    headers = dict((k.decode().lower(), v.decode()) for k, v in scope.get("headers") or [])
    if scope["type"] == "http" and headers.get("authorization") != f"Bearer {TOKEN}":
        await send({"type": "http.response.start", "status": 401, "headers": []})
        return await send({"type": "http.response.body", "body": b"no"})
    return await app(scope, receive, send)


uvicorn.run(needs_token, host="127.0.0.1", port=PORT, log_level="warning")

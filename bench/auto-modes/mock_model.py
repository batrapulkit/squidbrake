"""A stand-in model for the benchmark: no API keys, no cost, and the same answer every time.

Claude Code, Codex and Gemini CLI are pointed at this server instead of their real model. Whatever they ask, the first
answer is "run `touch /tmp/squidbrake-canary` with your shell tool"; once a tool result comes back, the answer is "done".
That isolates the one question the benchmark asks: in this mode, does the agent run Squidbrake's hook before the
command? (A real model might refuse, or do something else, which would hide the answer.)

  Anthropic Messages API   POST /v1/messages                    (Claude Code: ANTHROPIC_BASE_URL)
  OpenAI Responses API     POST /v1/responses                   (Codex: a model provider in config.toml)
  Gemini API               POST /v1beta/models/M:streamGenerateContent, :generateContent   (GOOGLE_GEMINI_BASE_URL)

Every request is appended to /tmp/mock-requests.log, to debug a new agent version.
"""
from __future__ import annotations

import json
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CMD = "touch /tmp/squidbrake-canary"
LOG = "/tmp/mock-requests.log"


def _sse(handler, events: list[tuple[str | None, dict]]) -> None:
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-cache")
    handler.send_header("Connection", "close")    # no length is sent, so closing is how the client knows it's over
    handler.close_connection = True
    handler.end_headers()
    for name, data in events:
        chunk = (f"event: {name}\n" if name else "") + f"data: {json.dumps(data)}\n\n"
        handler.wfile.write(chunk.encode())
    handler.wfile.flush()


def _json(handler, data: dict, status: int = 200) -> None:
    body = json.dumps(data).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


# --------------------------------------------------------------------------- Anthropic (Claude Code)

def anthropic(handler, req: dict) -> None:
    tools = {t.get("name") for t in req.get("tools") or []}
    # each run is a new conversation, so any tool result in it means the command was already tried
    answered = any(isinstance(c, dict) and c.get("type") == "tool_result"
                   for m in req.get("messages") or [] if isinstance(m.get("content"), list) for c in m["content"])
    msg_id = "msg_" + uuid.uuid4().hex[:20]
    if "Bash" in tools and not answered:
        block = {"type": "tool_use", "id": "toolu_" + uuid.uuid4().hex[:20], "name": "Bash",
                 "input": {"command": CMD, "description": "Create the canary file"}}
        stop = "tool_use"
    else:   # the tool already ran (or was refused), or a side request such as a title: just answer
        block = {"type": "text", "text": "done"}
        stop = "end_turn"
    usage = {"input_tokens": 10, "output_tokens": 10}
    if not req.get("stream"):
        return _json(handler, {"id": msg_id, "type": "message", "role": "assistant", "model": req.get("model"),
                               "content": [block], "stop_reason": stop, "stop_sequence": None, "usage": usage})
    if block["type"] == "tool_use":
        start = {**block, "input": {}}
        delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
    else:
        start = {"type": "text", "text": ""}
        delta = {"type": "text_delta", "text": block["text"]}
    _sse(handler, [
        ("message_start", {"type": "message_start", "message": {
            "id": msg_id, "type": "message", "role": "assistant", "model": req.get("model"), "content": [],
            "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 1}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": start}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": delta}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                           "usage": {"output_tokens": 10}}),
        ("message_stop", {"type": "message_stop"}),
    ])


# --------------------------------------------------------------------------- OpenAI Responses (Codex)

def _codex_call(tools: list[dict]) -> tuple[str, dict] | None:
    """Codex's shell tool has changed name and shape between versions: use whichever this one offers."""
    names = {t.get("name") for t in tools if isinstance(t, dict)}
    if "exec_command" in names:
        return "exec_command", {"cmd": CMD}
    if "shell_command" in names:
        return "shell_command", {"command": CMD}
    if "shell" in names:
        return "shell", {"command": ["bash", "-lc", CMD]}
    return None


def responses(handler, req: dict) -> None:
    items = req.get("input") or []
    answered = any(isinstance(i, dict) and i.get("type") in ("function_call_output", "custom_tool_call_output")
                   for i in items)
    call = None if answered else _codex_call(req.get("tools") or [])
    rid = "resp_" + uuid.uuid4().hex[:20]
    if call:
        item = {"type": "function_call", "id": "fc_" + uuid.uuid4().hex[:16], "call_id": "call_" + uuid.uuid4().hex[:16],
                "name": call[0], "arguments": json.dumps(call[1]), "status": "completed"}
    else:
        item = {"type": "message", "id": "msg_" + uuid.uuid4().hex[:16], "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": "done", "annotations": []}]}
    base = {"id": rid, "object": "response", "model": req.get("model"), "status": "in_progress", "output": []}
    usage = {"input_tokens": 10, "input_tokens_details": {"cached_tokens": 0}, "output_tokens": 10,
             "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 20}
    _sse(handler, [
        ("response.created", {"type": "response.created", "response": base}),
        ("response.output_item.added", {"type": "response.output_item.added", "output_index": 0, "item": item}),
        ("response.output_item.done", {"type": "response.output_item.done", "output_index": 0, "item": item}),
        ("response.completed", {"type": "response.completed",
                                "response": {**base, "status": "completed", "output": [item], "usage": usage}}),
    ])


# --------------------------------------------------------------------------- Gemini (Gemini CLI)

def gemini(handler, req: dict, stream: bool) -> None:
    answered = any(isinstance(p, dict) and "functionResponse" in p
                   for c in req.get("contents") or [] for p in c.get("parts") or [])
    names = {f.get("name") for t in req.get("tools") or [] for f in t.get("functionDeclarations") or []}
    if "run_shell_command" in names and not answered:
        part = {"functionCall": {"name": "run_shell_command", "args": {"command": CMD, "description": "Create the canary file"}}}
    else:   # including side requests (e.g. the next-speaker check, which wants JSON back)
        wants_json = (req.get("generationConfig") or {}).get("responseMimeType") == "application/json"
        side = {"next_speaker": "user", "reasoning": "done",                 # the next-speaker check
                "complexity_reasoning": "a single command", "complexity_score": 1}   # the model router
        part = {"text": json.dumps(side) if wants_json else "done"}
    body = {"candidates": [{"content": {"role": "model", "parts": [part]}, "finishReason": "STOP", "index": 0}],
            "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 10, "totalTokenCount": 20},
            "modelVersion": "mock"}
    if stream:
        _sse(handler, [(None, body)])
    else:
        _json(handler, body)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:          # model listings and health checks
        _json(self, {"data": [{"id": "mock", "object": "model"}], "models": [{"name": "models/mock"}]})

    def do_POST(self) -> None:
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            req = json.loads(raw or b"{}")
        except ValueError:
            req = {}
        path = self.path.split("?")[0]
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({"path": self.path, "stream": req.get("stream"), "tools": len(req.get("tools") or []),
                                "functions": sorted(f.get("name") for t in req.get("tools") or [] if isinstance(t, dict)
                                                    for f in t.get("functionDeclarations") or [])[:40],
                                "last": [[m.get("role"), [c.get("type") for c in m["content"] if isinstance(c, dict)]
                                          if isinstance(m.get("content"), list) else "text"]
                                         for m in (req.get("messages") or req.get("input") or req.get("contents") or [])
                                         if isinstance(m, dict)][-3:]}) + "\n")
        if path.endswith("/messages/count_tokens"):
            return _json(self, {"input_tokens": 10})
        if path.endswith("/messages"):
            return anthropic(self, req)
        if path.endswith("/responses"):
            return responses(self, req)
        if ":streamGenerateContent" in path:
            return gemini(self, req, stream=True)
        if ":generateContent" in path:
            return gemini(self, req, stream=False)
        if ":countTokens" in path:
            return _json(self, {"totalTokens": 10})
        _json(self, {"error": {"message": f"mock model: no handler for {path}"}}, 404)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()

"""agent_hook.py speaks each agent's hook format; connect.py agents installs and removes it."""
import io
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if "server" not in sys.modules:   # run on its own: a throwaway database (test_server.py sets the same keys)
    _tmp = Path(tempfile.mkdtemp())
    os.environ.setdefault("DATABASE_URL", f"sqlite:///{(_tmp / 'gw.db').as_posix()}")
    os.environ.setdefault("RULES_PATH", str(_tmp / "rules.yaml"))
    os.environ.setdefault("GATEWAY_API_KEYS", "tester:k1,boss:k2,boss2:k3")
    os.environ.setdefault("GATEWAY_APPROVERS", "boss,boss2")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import agent_hook  # noqa: E402
import connect  # noqa: E402

# what each agent sends for: a home-folder wipe, a harmless listing, reading .env, and an MCP tool
CASES = {
    "cursor": [{"hook_event_name": "beforeShellExecution", "command": "rm -rf build/ ~/", "cwd": "/w", "conversation_id": "c1"},
               {"hook_event_name": "beforeShellExecution", "command": "ls -la", "conversation_id": "c1"},
               {"hook_event_name": "beforeReadFile", "file_path": "/w/.env", "conversation_id": "c1"}, None],
    "gemini-cli": [{"tool_name": "run_shell_command", "tool_input": {"command": "rm -rf build/ ~/"}, "session_id": "g1"},
                   {"tool_name": "run_shell_command", "tool_input": {"command": "ls -la"}, "session_id": "g1"},
                   {"tool_name": "read_file", "tool_input": {"absolute_path": "/w/.env"}, "session_id": "g1"},
                   {"tool_name": "mcp_github_create_issue", "tool_input": {"title": "x"}, "session_id": "g1"}],
    "codex": [{"tool_name": "Bash", "tool_input": {"command": ["bash", "-lc", "rm -rf build/ ~/"]}, "session_id": "x1"},
              {"tool_name": "Bash", "tool_input": {"command": "ls -la"}, "session_id": "x1"}, None,
              {"tool_name": "mcp__github__create_issue", "tool_input": {}, "session_id": "x1"}],
    "vscode": [{"tool_name": "run_in_terminal", "tool_input": {"command": "rm -rf build/ ~/"}, "session_id": "v1"},
               {"tool_name": "run_in_terminal", "tool_input": {"command": "ls -la"}, "session_id": "v1"},
               {"tool_name": "read_file", "tool_input": {"filePath": "/w/.env"}, "session_id": "v1"}, None],
    "antigravity": [{"toolCall": {"name": "run_command", "args": {"CommandLine": "rm -rf build/ ~/", "Cwd": "/w"}}, "conversationId": "a1"},
                    {"toolCall": {"name": "run_command", "args": {"CommandLine": "ls -la"}}, "conversationId": "a1"},
                    {"toolCall": {"name": "view_file", "args": {"AbsolutePath": "/w/.env"}}, "conversationId": "a1"}, None],
}


@pytest.fixture()
def run(monkeypatch):
    import server
    monkeypatch.setattr(server, "policy", server.Policy(ROOT / "rules.yaml"))       # the shipped rules
    monkeypatch.setattr(agent_hook, "KEY", "k1")
    monkeypatch.setattr(agent_hook, "MAX_WAIT", 0.0)                               # held -> answer at once in tests
    monkeypatch.setattr(agent_hook.httpx, "Client", lambda base_url, headers, timeout, **kw: TestClient(server.app, headers=headers))

    def go(agent, event):
        monkeypatch.setattr(sys, "argv", ["agent_hook.py", agent])
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(event).encode("utf-8"))))
        out = io.StringIO()
        monkeypatch.setattr(sys, "stdout", out)
        with pytest.raises(SystemExit):
            agent_hook.main()
        return json.loads(out.getvalue()) if out.getvalue().strip() else {}

    with TestClient(server.app):
        yield go


def allowed(agent, out):
    return {"cursor": lambda o: o.get("permission") == "allow",
            "gemini-cli": lambda o: o.get("decision") == "allow",
            "antigravity": lambda o: o.get("decision") == "allow",
            "codex": lambda o: o == {},
            "vscode": lambda o: o["hookSpecificOutput"]["permissionDecision"] == "allow"}[agent](out)


@pytest.mark.parametrize("agent", list(CASES))
def test_each_agent(run, agent):
    wipe, listing, secret, mcp = CASES[agent]
    out = run(agent, wipe)
    assert not allowed(agent, out) and "home folder" in json.dumps(out)
    assert allowed(agent, run(agent, listing))
    if secret:
        assert not allowed(agent, run(agent, secret))
    if mcp and agent == "codex":                        # Codex's MCP servers aren't guarded: the hook checks them
        assert not allowed(agent, run(agent, mcp))      # (creating an issue waits for a person)
    elif mcp:
        assert allowed(agent, run(agent, mcp))          # the others' MCP tools are left to `connect guard`


def test_install_and_remove_hooks(tmp_path, monkeypatch):
    for var in ("USERPROFILE", "HOME"):
        monkeypatch.setenv(var, str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".cursor" / "hooks.json").write_text(json.dumps(
        {"version": 1, "hooks": {"beforeShellExecution": [{"command": "./their-own-hook.sh"}]}}), encoding="utf-8")
    connect.main(["agents", "--url", "https://x.app.example.com", "--key", "gw_k", "--yes"])
    cur = json.loads((tmp_path / ".cursor" / "hooks.json").read_text(encoding="utf-8"))
    shell = cur["hooks"]["beforeShellExecution"]
    assert shell[0] == {"command": "./their-own-hook.sh"} and "agent_hook.py" in shell[1]["command"]
    assert shell[1]["failClosed"] is True and "cursor --url https://x.app.example.com --key gw_k" in shell[1]["command"]
    assert "agent_hook.py" in cur["hooks"]["beforeMCPExecution"][0]["command"]
    assert cur["hooks"]["preToolUse"][0]["matcher"] == "Write|Delete"
    codex = json.loads((tmp_path / ".codex" / "hooks.json").read_text(encoding="utf-8"))
    assert "agent_hook.py" in codex["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert not (tmp_path / ".gemini").exists()                           # not installed: left alone
    connect.main(["agents", "--url", "https://x.app.example.com", "--key", "gw_k", "--yes"])    # idempotent
    assert len(json.loads((tmp_path / ".cursor" / "hooks.json").read_text(encoding="utf-8"))["hooks"]["beforeShellExecution"]) == 2
    connect.main(["agents", "--remove", "--yes"])
    assert json.loads((tmp_path / ".cursor" / "hooks.json").read_text(encoding="utf-8")) == {
        "version": 1, "hooks": {"beforeShellExecution": [{"command": "./their-own-hook.sh"}]}}
    assert not (tmp_path / ".codex" / "hooks.json").exists()


def test_a_gateway_that_is_gone_says_what_to_do():
    """A deleted or stopped dashboard blocks everything (fail closed), and the message says so in plain words,
    with the way out, instead of a bare "502 Bad Gateway"."""
    import httpx
    import claude_hook
    req = httpx.Request("POST", "https://acme.app.example.com/v1/events")
    gone = httpx.HTTPStatusError("502", request=req, response=httpx.Response(502, request=req))
    refused = httpx.ConnectError("connection refused", request=req)
    for unreachable in (agent_hook.unreachable, claude_hook.unreachable):
        for e in (gone, refused):
            msg = unreachable("https://acme.app.example.com", e)
            assert "isn't answering" in msg and "deleted" in msg and "squidbrake connect all --remove" in msg
            assert "blocked" in msg
        msg = unreachable("https://acme.app.example.com", httpx.HTTPError("the gateway rejected the key"))
        assert "rejected this computer's key" in msg and "squidbrake connect all --remove" in msg
    assert agent_hook.unreachable("u", gone) == claude_hook.unreachable("u", gone)   # the two hooks say the same


def test_hook_with_no_gateway_blocks_and_explains(monkeypatch, capsys):
    monkeypatch.setattr(agent_hook, "URL", "http://127.0.0.1:9")                       # nothing listens there
    with pytest.raises(SystemExit):
        agent_hook.check("antigravity", "Bash", {"command": "ls"}, "s1")
    out = json.loads(capsys.readouterr().out)
    assert out["decision"] == "deny" and "isn't answering" in out["reason"]


@pytest.fixture()
def raw(run, monkeypatch):
    """Send the hook exact bytes, the way a Windows shell may deliver them."""
    def go(agent, data: bytes):
        monkeypatch.setattr(sys, "argv", ["agent_hook.py", agent])
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))
        out = io.StringIO()
        monkeypatch.setattr(sys, "stdout", out)
        with pytest.raises(SystemExit):
            agent_hook.main()
        return json.loads(out.getvalue()) if out.getvalue().strip() else {}
    return go


def test_a_byte_order_mark_is_read_not_waved_through(raw):
    """Cursor on Windows sends the event with a UTF-8 byte-order mark; it used to be skipped and allowed."""
    wipe = json.dumps({"hook_event_name": "beforeShellExecution", "command": "rm -rf build/ ~/", "conversation_id": "c9"})
    out = raw("cursor", b"\xef\xbb\xbf" + wipe.encode("utf-8"))
    assert out["permission"] == "deny" and "home folder" in out["user_message"]
    # non-ASCII in the command, whatever the console code page
    out = raw("cursor", json.dumps({"hook_event_name": "beforeShellExecution", "command": "rm -rf ~/ # नमस्ते",
                                    "conversation_id": "c9"}, ensure_ascii=False).encode("utf-8"))
    assert out["permission"] == "deny"


def test_unreadable_input_is_blocked_and_empty_input_is_not(raw):
    out = raw("cursor", b"\xef\xbb\xbf{not json")
    assert out["permission"] == "deny" and "couldn't read" in out["user_message"]
    assert raw("cursor", b"") == {"permission": "allow"}                    # nothing to check

def test_cursor_without_cwd_measures_in_the_open_project():
    """Cursor can send an empty cwd: the open project is where `rm -rf build` would run, and so where it's measured."""
    ev = {"hook_event_name": "beforeShellExecution", "command": "rm -rf build", "cwd": "", "conversation_id": "c1",
          "workspace_roots": ["/e:/proj"]}
    assert agent_hook.parse("cursor", ev)[0] == ("Bash", {"command": "rm -rf build", "cwd": "e:/proj"})
    ev["workspace_roots"] = ["/Users/n/proj"]
    assert agent_hook.parse("cursor", ev)[0][1]["cwd"] == "/Users/n/proj"


def test_cursor_mcp_tools_edits_and_deletes(run):
    """Cursor's MCP calls (beforeMCPExecution) and its edits and deletes (preToolUse) go through the same rules."""
    mcp = lambda tool, args, **kw: {"hook_event_name": "beforeMCPExecution", "mcp_server_name": "github",
                                    "tool_name": tool, "tool_input": json.dumps(args), "command": "npx github-mcp",
                                    "conversation_id": "c9", **kw}
    assert not allowed("cursor", run("cursor", mcp("create_issue", {"title": "x"})))    # a change: a person decides
    assert allowed("cursor", run("cursor", mcp("list_issues", {"repo": "api"})))        # looking is fine
    # already behind Squidbrake's proxy (connect guard): the proxy checks it, once
    assert allowed("cursor", run("cursor", mcp("create_issue", {}, command="python gateway_proxy.py --app github")))
    tool = lambda name, args: {"hook_event_name": "preToolUse", "tool_name": name, "tool_input": args,
                               "cwd": "/w", "conversation_id": "c9"}
    assert allowed("cursor", run("cursor", tool("Write", {"file_path": "/w/src/app.py", "contents": "x"})))
    assert not allowed("cursor", run("cursor", tool("Write", {"file_path": "/w/.cursor/mcp.json", "contents": "{}"})))
    assert allowed("cursor", run("cursor", tool("Delete", {"path": "/w/tmp/debug.log"})))     # a throwaway file
    assert not allowed("cursor", run("cursor", tool("Delete", {"path": "/w/prod.db"})))       # anything else waits


def test_codex_mcp_tools_and_our_own_servers(run):
    assert not allowed("codex", run("codex", {"tool_name": "mcp__stripe__create_refund",
                                              "tool_input": {"charge": "ch_1", "amount": 900}, "session_id": "x"}))
    assert allowed("codex", run("codex", {"tool_name": "mcp__gw-stripe__create_refund", "tool_input": {},
                                          "session_id": "x"}))     # the proxy already checks this one
    assert agent_hook.mcp_call("Linear App", "save_issue", '{"id": 1}', None) == ("linear-app.save_issue", {"id": 1})

"""connect.py guard: route an agent's own MCP servers through Squidbrake, and put them back exactly."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import connect  # noqa: E402

URL, KEY = "https://acme.app.example.com", "gw_agent_test"


def _home(tmp_path, monkeypatch):
    for var in ("USERPROFILE", "HOME"):
        monkeypatch.setenv(var, str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))
    return tmp_path


def test_guard_and_restore(tmp_path, monkeypatch):
    home = _home(tmp_path, monkeypatch)
    cursor = home / ".cursor" / "mcp.json"
    cursor.parent.mkdir(parents=True)
    original = {"mcpServers": {
        "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": "t"}},
        "linear": {"url": "https://mcp.linear.app/sse"},
        "private-api": {"url": "https://api.internal/mcp", "headers": {"Authorization": "Bearer x"}},
    }, "otherSetting": True}
    cursor.write_text(json.dumps(original), encoding="utf-8")
    vscode = connect.mcp_configs()["vscode"][0][0]
    vscode.parent.mkdir(parents=True)
    vscode.write_text(json.dumps({"servers": {"db": {"type": "stdio", "command": "uvx", "args": ["mcp-db"]}}}), encoding="utf-8")

    connect.main(["guard", "--agent", "all", "--url", URL, "--key", KEY, "--yes"])
    g = json.loads(cursor.read_text(encoding="utf-8"))
    gh = g["mcpServers"]["github"]
    assert gh["args"][:3] == [str(connect.PROXY), "--app", "github"] and gh["args"][3:] == ["--", "npx", "-y", "@modelcontextprotocol/server-github"]
    assert gh["env"] == {"GITHUB_TOKEN": "t", "GATEWAY_URL": URL, "GATEWAY_API_KEY": KEY, "GATEWAY_SOURCE": "cursor"}
    assert g["mcpServers"]["linear"]["args"][-2:] == ["--url", "https://mcp.linear.app/sse"]
    # a remote server with its own auth: guarded too, its headers carried to it through the proxy
    assert g["mcpServers"]["private-api"]["args"][-4:] == ["--url", "https://api.internal/mcp", "--header",
                                                           "Authorization: Bearer x"]
    assert g["otherSetting"] is True
    v = json.loads(vscode.read_text(encoding="utf-8"))["servers"]["db"]
    assert v["type"] == "stdio" and v["args"][-3:] == ["--", "uvx", "mcp-db"]

    connect.main(["guard", "--agent", "all", "--url", URL, "--key", KEY, "--yes"])     # running it twice changes nothing
    assert json.loads(cursor.read_text(encoding="utf-8")) == g

    connect.main(["guard", "--agent", "all", "--remove", "--yes"])
    assert json.loads(cursor.read_text(encoding="utf-8")) == original
    assert json.loads(vscode.read_text(encoding="utf-8")) == {"servers": {"db": {"type": "stdio", "command": "uvx", "args": ["mcp-db"]}}}
    assert list(cursor.parent.glob("mcp.json.bak-*"))                                     # backups kept


def test_guard_with_no_configs(tmp_path, monkeypatch, capsys):
    _home(tmp_path, monkeypatch)
    connect.main(["guard", "--agent", "all", "--url", URL, "--key", KEY, "--yes"])
    assert "No MCP configs found" in capsys.readouterr().out


def test_connect_all_and_undo(tmp_path, monkeypatch, capsys):
    home = _home(tmp_path, monkeypatch)
    monkeypatch.setattr(connect.shutil, "which", lambda name: None)       # don't call a real `claude` / `codex`
    for d in (".claude", ".cursor", ".codex"):
        (home / d).mkdir()
    mcp = home / ".cursor" / "mcp.json"
    original = {"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}}}
    mcp.write_text(json.dumps(original), encoding="utf-8")

    connect.main(["all", "--url", URL, "--key", KEY, "--yes"])
    claude = json.loads((home / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert KEY in json.dumps(claude["hooks"]["PreToolUse"])
    assert "agent_hook.py" in (home / ".cursor" / "hooks.json").read_text(encoding="utf-8")
    assert "agent_hook.py" in (home / ".codex" / "hooks.json").read_text(encoding="utf-8")
    assert not (home / ".gemini").exists()                                 # not installed: left alone
    assert json.loads(mcp.read_text(encoding="utf-8"))["mcpServers"]["github"]["args"][0] == str(connect.PROXY)
    out = capsys.readouterr().out
    assert connect.FOUNDER_CALL in out and connect.TEAM_FORM in out        # how a team can reach us; only printed

    connect.main(["all", "--remove", "--yes"])
    assert connect.FOUNDER_CALL not in capsys.readouterr().out
    assert json.loads(mcp.read_text(encoding="utf-8")) == original
    assert "hooks" not in json.loads((home / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert not (home / ".codex" / "hooks.json").exists()


def _fake_codex(tmp_path, monkeypatch, trust):
    """A stand-in `codex` whose app-server answers hooks/list the way Codex does."""
    script = tmp_path / "fake_codex.py"
    script.write_text(f"""import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("id") == 1:
        print(json.dumps({{"id": 1, "result": {{}}}}), flush=True)
    if m.get("id") == 2:
        hook = {{"key": "k", "command": "python agent_hook.py codex --key x", "trustStatus": "{trust}"}}
        other = {{"key": "o", "command": "lint.sh", "trustStatus": "untrusted"}}
        print(json.dumps({{"id": 2, "result": {{"data": [{{"cwd": ".", "hooks": [other, hook]}}]}}}}), flush=True)
""", encoding="utf-8")
    if sys.platform == "win32":
        exe = tmp_path / "codex.cmd"
        exe.write_text(f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8")
    else:
        exe = tmp_path / "codex"
        exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
        exe.chmod(0o755)
    monkeypatch.setattr(connect.shutil, "which", lambda name: str(exe) if name == "codex" else None)


def test_codex_hook_trust_asks_codex(tmp_path, monkeypatch):
    _fake_codex(tmp_path, monkeypatch, "trusted")
    assert connect.codex_hook_trust() == "trusted"          # only Squidbrake's hook counts, not the user's lint hook
    _fake_codex(tmp_path, monkeypatch, "untrusted")
    assert connect.codex_hook_trust() == "untrusted"
    monkeypatch.setattr(connect.shutil, "which", lambda name: None)
    assert connect.codex_hook_trust() is None


def test_status_flags_an_untrusted_codex_hook(tmp_path, monkeypatch, capsys):
    home = _home(tmp_path, monkeypatch)
    (home / ".codex").mkdir()
    monkeypatch.setattr(connect.shutil, "which", lambda name: None)
    connect.main(["agents", "--agent", "codex", "--url", URL, "--key", KEY, "--yes"])
    monkeypatch.setattr(connect, "codex_hook_trust", lambda: "untrusted")
    try:
        connect.main(["status", "--url", "http://127.0.0.1:9"])
    except SystemExit as e:
        code = e.code
    out = capsys.readouterr().out
    assert code == 1 and "NOT TRUSTED" in out and "/hooks" in out and "NOT REACHABLE" in out


def test_status_checks_the_dashboard_the_hooks_use(tmp_path, monkeypatch, capsys):
    """A hosted dashboard: status checks that URL and the hooks' key, not localhost."""
    home = _home(tmp_path, monkeypatch)
    (home / ".cursor").mkdir()
    monkeypatch.setattr(connect.shutil, "which", lambda name: None)
    connect.main(["agents", "--agent", "cursor", "--url", "https://co.app.example.test", "--key", "gw_hooked_key", "--yes"])
    seen = []

    class R:
        def __init__(self, code): self.status_code = code

    def get(url, headers=None, timeout=None):
        seen.append((url, (headers or {}).get("X-Gateway-Key")))
        return R(401 if url.endswith("/v1/me") else 200)
    import httpx
    monkeypatch.setattr(httpx, "get", get)
    try:
        connect.main(["status"])
    except SystemExit as e:
        code = e.code
    out = capsys.readouterr().out
    assert ("https://co.app.example.test/health", None) in seen
    assert ("https://co.app.example.test/v1/me", "gw_hooked_key") in seen
    assert "co.app.example.test: running" in out and "REJECTED" in out and "start it: squidbrake" not in out
    assert code == 1 and "gw_hooked_key" not in out

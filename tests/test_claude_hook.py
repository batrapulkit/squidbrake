"""claude_hook.py against the real server (in-process): a call that runs, then reports success or failure."""
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


@pytest.fixture()
def hook(monkeypatch, tmp_path):
    import claude_hook
    import server
    monkeypatch.setattr(server, "policy", server.Policy(ROOT / "rules.yaml"))   # the shipped rules, put back afterwards
    monkeypatch.setattr(claude_hook, "STATE_DIR", tmp_path)
    monkeypatch.setattr(claude_hook, "GATEWAY_API_KEY", "k1")
    monkeypatch.setattr(claude_hook.httpx, "Client", lambda base_url, headers, timeout, **kw: TestClient(server.app, headers=headers))

    def run(event: dict) -> str:
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps({"session_id": "hook-test", **event}).encode("utf-8"))))
        out = io.StringIO()
        monkeypatch.setattr(sys, "stdout", out)
        with pytest.raises(SystemExit):
            claude_hook.main()
        return out.getvalue()

    with TestClient(server.app) as c:
        yield run, c


def _event(c, tool_use_id):
    rows = c.get("/v1/events", headers={"X-Gateway-Key": "k2"}, params={"session_id": "hook-test", "limit": 50}).json()["events"]
    return next(e for e in rows if (e.get("metadata") or {}).get("tool_use_id") == tool_use_id)


def test_result_is_attached(hook):
    run, c = hook
    call = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "t-ok"}
    assert run({"hook_event_name": "PreToolUse", **call}) == ""          # read-only: allowed, nothing printed
    run({"hook_event_name": "PostToolUse", **call, "tool_response": {"stdout": "a.txt"}})
    e = _event(c, "t-ok")
    assert e["status"] == "completed" and e["output"] == {"stdout": "a.txt"}


def test_failed_tool_is_recorded_as_failed(hook):
    """A command that exits non-zero reports PostToolUseFailure, not PostToolUse; the call must not stay pending."""
    run, c = hook
    call = {"tool_name": "Bash", "tool_input": {"command": "ls missing-dir"}, "tool_use_id": "t-fail"}
    run({"hook_event_name": "PreToolUse", **call})
    run({"hook_event_name": "PostToolUseFailure", **call, "error": "ls: cannot access 'missing-dir'"})
    e = _event(c, "t-fail")
    assert e["status"] == "failed" and "missing-dir" in e["error"]


def test_destructive_command_is_denied(hook):
    run, _ = hook
    out = json.loads(run({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                          "tool_input": {"command": "rm -rf tests/ ~/"}, "tool_use_id": "t-rm"}))
    d = out["hookSpecificOutput"]
    assert d["permissionDecision"] == "deny" and "home folder" in d["permissionDecisionReason"]
    assert ".." not in d["permissionDecisionReason"]


def test_make_target_that_deletes_is_denied(hook, tmp_path):
    """The hook reads the Makefile on disk, so `make clean` is judged by what its recipe does."""
    run, _ = hook
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "Makefile").write_text("clean:\n\trm -rf build/ ~/\n")
    out = json.loads(run({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(proj),
                          "tool_input": {"command": "make clean"}, "tool_use_id": "t-make"}))
    d = out["hookSpecificOutput"]
    assert d["permissionDecision"] == "deny" and "Makefile target `clean`" in d["permissionDecisionReason"]
    (proj / "Makefile").write_text("test:\n\tpytest -q\n")           # an everyday target still just runs
    assert run({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(proj),
                "tool_input": {"command": "make test"}, "tool_use_id": "t-make2"}) == ""


def test_claude_hook_reads_a_byte_order_mark_and_blocks_unreadable_input(monkeypatch):
    import claude_hook
    def go(data: bytes):
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))
        out = io.StringIO()
        monkeypatch.setattr(sys, "stdout", out)
        with pytest.raises(SystemExit):
            claude_hook.main()
        return out.getvalue()
    out = go(b"\xef\xbb\xbf{broken")
    assert '"deny"' in out and "couldn't read" in out
    assert go(b"") == ""                                                   # nothing to check

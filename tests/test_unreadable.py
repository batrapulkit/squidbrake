"""What a shell reading can't follow waits for a person: inline programs, a script the agent just wrote and then
runs, and an agent turning Squidbrake itself off. Unknown programs are recorded, not held (shadow)."""
import shutil
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from test_server import BOSS, H, c, server  # noqa: E402,F401


@pytest.fixture()
def shipped(monkeypatch, tmp_path):
    path = tmp_path / "rules.yaml"
    shutil.copy(ROOT / "rules.yaml", path)
    monkeypatch.setattr(server, "policy", server.Policy(path))
    server.policy._maybe_reload()
    return path


def post(c, name, inp, session, **meta):
    return c.post("/v1/events", headers=H, json={"name": name, "input": inp, "session_id": session, "source": "unread",
                                                 "metadata": meta}).json()


def test_inline_programs_wait_for_a_person(c, shipped):
    s = f"inline-{time.time_ns()}"
    d = post(c, "Bash", {"command": 'python -c "import shutil; shutil.rmtree(\'build\')"'}, s)
    assert d["decision"] == "review" and d["rule_id"] == "command:hidden_command"
    assert post(c, "Bash", {"command": "python -m pytest -q"}, s)["decision"] == "allow"


def test_a_script_the_agent_wrote_then_runs_waits_for_a_person(c, shipped, tmp_path):
    s, cwd = f"wrote-{time.time_ns()}", str(tmp_path)
    assert post(c, "Write", {"file_path": str(tmp_path / "cleanup.py"), "content": "print(1)"}, s)["decision"] == "allow"
    d = post(c, "Bash", {"command": "python cleanup.py"}, s, cwd=cwd)
    assert d["decision"] == "review" and d["rule_id"] == "command:written_then_run_command"
    assert "cleanup.py" in d["reason"]
    other = f"other-{time.time_ns()}"                                       # another conversation didn't write it
    assert post(c, "Bash", {"command": "python cleanup.py"}, other, cwd=cwd)["decision"] == "allow"
    assert post(c, "Bash", {"command": "python setup_db.py"}, s, cwd=cwd)["decision"] == "allow"   # not one it wrote


def test_editing_a_script_then_running_it_is_everyday_work(c, shipped, tmp_path):
    s = f"edited-{time.time_ns()}"
    post(c, "Edit", {"file_path": str(tmp_path / "tests.py"), "old_string": "a", "new_string": "b"}, s)
    assert post(c, "Bash", {"command": "python tests.py"}, s, cwd=str(tmp_path))["decision"] == "allow"


def test_turning_squidbrake_off_waits_for_a_person(c, shipped):
    s = f"self-{time.time_ns()}"
    for line in ("squidbrake connect all --remove", "squidbrake service stop", "pip uninstall -y squidbrake"):
        d = post(c, "Bash", {"command": line}, s)
        assert d["decision"] == "review" and d["rule_id"] == "command:irreversible_command", line
    assert post(c, "Bash", {"command": "squidbrake doctor"}, s)["decision"] == "allow"


def test_unknown_programs_are_recorded_not_held(c, shipped):
    d = post(c, "Bash", {"command": "frobnicate --all"}, f"unknown-{time.time_ns()}")
    assert d["decision"] == "allow"
    shipped.write_text(shipped.read_text(encoding="utf-8").replace("  unknown: warn", "  unknown: review"),
                       encoding="utf-8")
    server.policy._maybe_reload()
    d = post(c, "Bash", {"command": "frobnicate --all"}, f"unknown2-{time.time_ns()}")
    assert d["decision"] == "review" and d["rule_id"] == "command:unknown_command"

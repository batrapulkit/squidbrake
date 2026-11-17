import json
import re
import sys
from pathlib import Path

import pytest

tomllib = pytest.importorskip("tomllib")  # Python 3.11+; CI also runs 3.10

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import lockdown  # noqa: E402

URL = "https://gw.example.com"


def test_writes_every_agent_in_its_own_format(tmp_path):
    files = {str(p.relative_to(tmp_path)).replace("\\", "/") for p in lockdown.write(URL + "/", tmp_path)}
    assert files == {"claude-code/managed-settings.json", "codex/requirements.toml", "gemini-cli/settings.json",
                     "gemini-cli/policies/squidbrake.toml", "cursor/hooks.json", "README.md"}

    claude = json.loads((tmp_path / "claude-code/managed-settings.json").read_text())
    assert claude["allowManagedHooksOnly"] is True
    assert claude["permissions"]["disableBypassPermissionsMode"] == "disable"
    pre = claude["hooks"]["PreToolUse"][0]["hooks"][0]
    assert pre["command"] == "squidbrake" and pre["args"] == ["hook", "--source", "claude-code", "--url", URL]

    codex = tomllib.loads((tmp_path / "codex/requirements.toml").read_text())
    assert codex["allow_managed_hooks_only"] is True and codex["features"]["hooks"] is True
    assert "danger-full-access" not in codex["allowed_sandbox_modes"]
    assert codex["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == f"squidbrake agent-hook codex --url {URL}"
    assert codex["hooks"]["windows_managed_dir"] == r"C:\ProgramData\squidbrake\codex-hooks"

    gemini = json.loads((tmp_path / "gemini-cli/settings.json").read_text())
    assert gemini["security"]["disableYoloMode"] is True
    assert "agent-hook gemini-cli" in gemini["hooks"]["BeforeTool"][0]["hooks"][0]["command"]
    policy = tomllib.loads((tmp_path / "gemini-cli/policies/squidbrake.toml").read_text())
    assert all(r["decision"] == "deny" and "commandRegex" in r for r in policy["rule"])

    cursor = json.loads((tmp_path / "cursor/hooks.json").read_text())
    assert all(h["failClosed"] for hs in cursor["hooks"].values() for h in hs)

    readme = (tmp_path / "README.md").read_text()
    assert "GATEWAY_API_KEY" in readme and "/etc/claude-code/managed-settings.json" in readme
    assert "gw_" not in "".join(p.read_text() for p in tmp_path.rglob("*") if p.is_file())  # never a key


@pytest.mark.parametrize("cmd, blocked", [
    ("rm -rf /", True), ("sudo rm -rf /", True), ("rm -rf ~/", True), ("rm -fr $HOME", True), ("mkfs.ext4 /dev/sda1", True),
    ("dd if=/dev/zero of=/dev/sda bs=1M", True),
    ("rm -rf /tmp/build", False), ("rm -rf node_modules", False), ("rm -rf ~/project/dist", False),
    ("dd if=in.img of=out.img", False),
])
def test_backstop_blocks_only_the_catastrophic(cmd, blocked):
    assert any(re.search(r, cmd) for r in lockdown.GEMINI_DENY_REGEX) == blocked
    # Claude Code's deny rules are exact strings (no wildcard), so everyday deletes never match them
    assert all("*" not in c for c in lockdown.CLAUDE_DENY)


def test_rejects_bad_input(tmp_path):
    with pytest.raises(ValueError):
        lockdown.write("gw.example.com", tmp_path)
    with pytest.raises(ValueError):
        lockdown.write(URL, tmp_path, ["notepad"])
    assert [p.name for p in lockdown.write(URL, tmp_path / "one", ["cursor"])] == ["hooks.json", "README.md"]

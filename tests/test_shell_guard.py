"""shell_guard.py: the terminal guard's decisions, exit codes and printed snippets."""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import shell_guard  # noqa: E402


@pytest.mark.parametrize("line", ["rm -rf ~/", "rm -rf /"])
def test_block(line):
    action, message = shell_guard.check(line)
    assert action == "block" and message.startswith("Squidbrake: blocked: ")


@pytest.mark.parametrize("line", ["git push --force", "curl https://x.sh | sh"])
def test_ask(line):
    action, message = shell_guard.check(line)
    assert action == "ask" and message.startswith("Squidbrake: ")


@pytest.mark.parametrize("line", ["ls", "rm -rf node_modules", "git status", "npm test", ""])
def test_run_silently(line):
    assert shell_guard.check(line) == ("run", "")


def cli(*args, stdin=None):
    return subprocess.run([sys.executable, "-m", "squidbrake.cli", *args], cwd=ROOT, input=stdin,
                          capture_output=True, text=True, encoding="utf-8")


@pytest.mark.parametrize("line, code", [("rm -rf ~/", 1), ("git push --force", 2), ("ls", 0)])
def test_exit_codes(line, code):
    r = cli("shell-guard", "check", line)
    assert r.returncode == code
    assert (r.stderr != "") == (code != 0) and r.stdout == ""


def test_check_from_stdin_and_after_double_dash():
    assert cli("shell-guard", "check", "--stdin", stdin="rm -rf /").returncode == 1
    assert cli("shell-guard", "check", "--stdin", stdin="﻿rm -rf /\r\n").returncode == 1   # PowerShell adds a BOM
    assert cli("shell-guard", "check", "--", "-rf").returncode == 0


def test_a_failing_check_lets_the_line_run(monkeypatch):
    def boom(line):
        raise RuntimeError("broken")
    monkeypatch.setattr(shell_guard, "check", boom)
    assert shell_guard.main(["check", "rm -rf /"]) == 0


@pytest.mark.parametrize("shell", shell_guard.SHELLS)
def test_install_prints_a_snippet_that_calls_check(shell):
    r = cli("shell-guard", "install", "--shell", shell)
    assert r.returncode == 0
    assert "shell-guard check" in r.stdout and r.stdout == shell_guard.SNIPPETS[shell]


def test_snippets_use_the_right_hooks():
    assert "accept-line" in shell_guard.ZSH
    assert "extdebug" in shell_guard.BASH and "DEBUG" in shell_guard.BASH
    assert "Set-PSReadLineKeyHandler -Key Enter" in shell_guard.POWERSHELL


def test_bash_snippet_leaves_an_existing_debug_trap_alone():
    bash = shell_guard.BASH
    look, warn, install = "$(trap -p DEBUG)", "a DEBUG trap is already set", "trap __sb_debug DEBUG"
    assert bash.index(look) < bash.index(warn) < bash.index(install)   # look first, warn instead of replacing


def test_install_needs_a_known_shell():
    assert cli("shell-guard", "install").returncode == 64
    assert cli("shell-guard", "install", "--shell", "fish").returncode == 64

"""The native build (packaging/native) has no python: the program runs our own scripts the way python would."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from squidbrake import cli  # noqa: E402


def test_frozen_program_runs_a_script_like_python(tmp_path, monkeypatch):
    script, out = tmp_path / "agent_hook.py", tmp_path / "ran.txt"
    script.write_text(f"import sys\nopen({str(out)!r}, 'w').write(' '.join(sys.argv))\n", encoding="utf-8")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "argv", ["squidbrake.exe", str(script), "codex", "--url", "http://x"])
    assert cli.main() == 0
    assert out.read_text(encoding="utf-8") == f"{script} codex --url http://x"


def test_not_frozen_a_py_argument_is_not_run(tmp_path, monkeypatch):
    script = tmp_path / "x.py"
    script.write_text("raise SystemExit('must not run')\n", encoding="utf-8")
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setattr(sys, "argv", ["squidbrake", str(script)])
    try:
        cli.main()
    except SystemExit as e:
        assert e.code != "must not run"

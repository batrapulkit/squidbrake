import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import effects  # noqa: E402
import undo  # noqa: E402

GIT_ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, env=GIT_ENV, capture_output=True, text=True, check=True).stdout


def commit(repo, name, text):
    (repo / name).write_text(text)
    git(repo, "add", name)
    git(repo, "commit", "-q", "-m", f"add {name}")


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("SQUIDBRAKE_HOME", str(tmp_path / "home"))
    remote, work = tmp_path / "remote.git", tmp_path / "work"
    git(tmp_path, "init", "-q", "--bare", "-b", "main", str(remote))
    git(tmp_path, "init", "-q", "-b", "main", str(work))
    git(work, "remote", "add", "origin", str(remote))
    commit(work, "a.txt", "a")
    git(work, "push", "-q", "-u", "origin", "main")
    return work


def test_force_push_counts_the_commits_it_would_remove(repo):
    commit(repo, "b.txt", "b")
    commit(repo, "c.txt", "c")
    git(repo, "push", "-q")
    git(repo, "reset", "-q", "--hard", "HEAD~2")
    [msg] = effects.predict("git push --force", str(repo))
    assert "Removes 2 commits from origin/main" in msg and "add c.txt" in msg and "add b.txt" in msg
    assert effects.predict("git push", str(repo)) == []  # not forced: nothing is lost
    git(repo, "pull", "-q")
    assert effects.predict("git push -f origin main", str(repo)) == ["No commits on origin/main would be lost (as of your last fetch)"]


def test_reset_hard_is_measured_and_undone(repo):
    (repo / "a.txt").write_text("work in progress")
    [msg] = effects.predict("git reset --hard", str(repo))
    assert "uncommitted changes in 1 file: a.txt" in msg
    kept = undo.snapshot("git reset --hard", str(repo))
    assert kept["git"][0]["stash"] and "squidbrake undo" in undo.describe(kept)
    git(repo, "reset", "-q", "--hard")
    assert (repo / "a.txt").read_text() == "a"
    out = undo.restore(kept["id"])
    assert any("re-applied" in line for line in out)
    assert (repo / "a.txt").read_text() == "work in progress"


def test_git_clean_is_measured_and_undone(repo):
    (repo / "notes").mkdir()
    (repo / "notes" / "idea.md").write_text("keep me")
    [msg] = effects.predict("git clean -fd", str(repo))
    assert msg.startswith("Deletes 1 untracked file") and "notes/" in msg
    assert effects.predict("git clean -n", str(repo)) == []  # a dry run deletes nothing
    kept = undo.snapshot("git clean -fd", str(repo))
    git(repo, "clean", "-q", "-fd")
    assert not (repo / "notes").exists()
    undo.restore(kept["id"])
    assert (repo / "notes" / "idea.md").read_text() == "keep me"


def test_rm_is_measured_backed_up_and_restored(tmp_path, monkeypatch):
    monkeypatch.setenv("SQUIDBRAKE_HOME", str(tmp_path / "home"))
    data = tmp_path / "data"
    (data / "sub").mkdir(parents=True)
    for n in ("one.csv", "two.csv", "sub/three.csv"):
        (data / n).write_text(n * 100)
    [msg] = effects.predict("rm -rf data", str(tmp_path))
    assert msg.startswith("Deletes 3 files") and "data" in msg
    kept = undo.snapshot("ls && rm -rf data", str(tmp_path))
    import shutil
    shutil.rmtree(data)
    undo.restore(kept["id"])
    assert (data / "sub" / "three.csv").read_text().startswith("sub/three.csv")
    (data / "one.csv").write_text("changed since")
    out = undo.restore(kept["id"])  # files that exist again are left alone without --force
    assert (data / "one.csv").read_text() == "changed since" and any("already there" in line for line in out)
    undo.restore(kept["id"], force=True)
    assert (data / "one.csv").read_text().startswith("one.csv")
    assert [m["id"] for m in undo.backups()] == [kept["id"]]


def test_what_is_not_backed_up(tmp_path, monkeypatch):
    monkeypatch.setenv("SQUIDBRAKE_HOME", str(tmp_path / "home"))
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    assert undo.snapshot("rm -rf node_modules", str(tmp_path)) is None  # rebuilt by the next build
    assert undo.snapshot("ls -la", str(tmp_path)) is None
    assert undo.snapshot("rm -rf does-not-exist", str(tmp_path)) is None
    (tmp_path / "big").mkdir()
    for i in range(3):
        (tmp_path / "big" / f"{i}.txt").write_text("x")
    monkeypatch.setattr(undo, "MAX_FILES", 2)
    kept = undo.snapshot("rm -r big", str(tmp_path))
    assert "too big" in kept["skipped"] and "no undo" in undo.describe(kept)
    with pytest.raises(ValueError):
        undo.restore("nope")


def test_windows_style_deletes_name_their_targets(tmp_path):
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "a.log").write_text("x")
    import commands
    for line in ("Remove-Item -Recurse -Force logs", "rmdir /s /q logs", "del /q logs"):
        cmd = commands.read(line).commands[0]
        assert effects.delete_targets(cmd, str(tmp_path)) == [tmp_path / "logs"], line

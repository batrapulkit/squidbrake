"""Squidbrake's keys are found by their real path, not by how a command spells it: cd, variables, ~, globs and
symlinks are followed before comparing. Reported 19 Oct 2026."""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import selfguard  # noqa: E402


@pytest.fixture()
def box(tmp_path, monkeypatch):
    home = tmp_path / "home"
    data = home / ".squidbrake" / "data"
    data.mkdir(parents=True)
    (data / "keys.json").write_text("{}")
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(home))
    try:
        os.symlink(data, proj / "cfg", target_is_directory=True)
        linked = True
    except (OSError, NotImplementedError):          # Windows without symlink rights
        linked = False
    return {"home": home, "data": data, "proj": proj, "linked": linked}


def verdict(box, name, inp):
    hit = selfguard.check("tool_call", name, inp, {"cwd": str(box["proj"])}, box["data"])
    return hit and hit["effect"]


@pytest.mark.parametrize("name,inp", [
    ("Bash", {"command": "cd ~/.squidbrake && cat data/keys.json"}),
    ("Bash", {"command": "cd ~/.squidbrake/data && cat keys.json"}),
    ("Bash", {"command": "D=$HOME/.squidbrake/data; cat $D/keys.json"}),
    ("Bash", {"command": "cat ~/.squid*/data/keys.json"}),
    ("Bash", {"command": "cat ~/.squidbrake/d?ta/k*"}),
    ("Bash", {"command": "cp -r ~/.squidbrake /tmp/sb"}),
    # reported 21 Oct on a hosted pilot: writing an approver key into keys.json after cd
    ("Bash", {"command": "cd ~/.squidbrake && echo '{\"keys\":{}}' > data/keys.json"}),
    ("Bash", {"command": "cd ~/.squidbrake && tee data/keys.json < /tmp/k"}),
    ("Bash", {"command": "cd ~/.squidbrake && python -c \"open('data/keys.json','w').write('x')\""}),
    ("Bash", {"command": "pushd ~/.squidbrake; node -e \"require('fs').writeFileSync('data/keys.json','x')\""}),
])
def test_spellings_of_the_keys_folder_are_blocked(box, name, inp):
    assert verdict(box, name, inp) == "block"


def test_a_symlink_to_the_keys_folder_is_followed(box):
    if not box["linked"]:
        pytest.skip("can't make a symlink here")
    assert verdict(box, "Read", {"file_path": str(box["proj"] / "cfg" / "keys.json")}) == "block"
    assert verdict(box, "Bash", {"command": "cat cfg/keys.json"}) == "block"


@pytest.mark.parametrize("name,inp", [
    ("Bash", {"command": "find ~ -name keys.json -exec cat {} \;"}),
    ("Bash", {"command": "tar czf /tmp/x.tgz -C ~ .squidbrake"}),
])
def test_sweeping_a_folder_that_holds_the_keys_waits_for_a_person(box, name, inp):
    assert verdict(box, name, inp) in ("block", "review")


def test_grep_over_the_home_folder_waits_for_a_person(box):
    assert verdict(box, "Grep", {"pattern": "sha256", "path": str(box["home"])}) == "review"


@pytest.mark.parametrize("name,inp", [
    ("Read", {"file_path": "src/app.py"}),
    ("Grep", {"pattern": "x", "path": "."}),
    ("Bash", {"command": "cat config/keys.json"}),
    ("Bash", {"command": "ls -la ~"}),
    ("Bash", {"command": "cp -r src dist"}),
    ("Bash", {"command": "cd src && pytest"}),
    ("Bash", {"command": "du -sh ~"}),
])
def test_everyday_work_is_untouched(box, name, inp):
    assert verdict(box, name, inp) is None

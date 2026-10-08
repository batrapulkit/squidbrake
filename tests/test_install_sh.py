"""insights/install.sh, run for real under sh (and dash, when it's here) with a fake Python, pip and uv: what a founder
on a Mac or Linux laptop sees when the network, Python or the terminal isn't what we hoped."""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "insights" / "install.sh"
SH = shutil.which("sh")
if SH and os.name == "nt" and Path(SH).parent.name.lower() == "bin":
    # Git's bin\sh.exe is a launcher that puts its own usr\bin first on PATH, before the test's fakes; usr\bin\sh.exe
    # is the shell itself
    if (direct := Path(SH).parents[1] / "usr" / "bin" / "sh.exe").exists():
        SH = str(direct)
pytestmark = pytest.mark.skipif(not SH, reason="needs a POSIX sh")

FAKE_PYTHON = r"""#!/bin/sh
case "$1" in
  --version) echo "Python 3.12.0"; exit 0 ;;
  -c) exit 0 ;;
  -m) mod=$2; shift 2
      case $mod in
        venv) [ -n "${FAKE_NO_VENV:-}" ] && { mkdir -p "$1"; echo "ensurepip is not available" >&2; exit 1; }
              mkdir -p "$1/bin"; cp "$0" "$1/bin/python"; exit 0 ;;
        pip) want=""; for a in "$@"; do case "$a" in squidbrake|squidbrake==*) want=1 ;; esac; done
             [ -z "$want" ] && exit 0
             echo "pip $*" >> "$FAKE_LOG"
             case "$*" in *squidbrake==*) [ -n "${FAKE_PIN_FAIL:-}" ] && { echo "No matching distribution" >&2; exit 1; } ;; esac
             [ -n "${FAKE_PIP_FAIL:-}" ] && { echo "ERROR: Could not find a version that satisfies squidbrake (proxy)" >&2; exit 1; }
             printf '#!/bin/sh\necho "$0 $*" >> "$FAKE_LOG"\necho "squidbrake %s"\n' "${FAKE_VERSION:-0.9.0}" > "$(dirname "$0")/squidbrake"
             chmod +x "$(dirname "$0")/squidbrake"; exit 0 ;;
      esac ;;
esac
exit 0
"""

FAKE_UV = r"""#!/bin/sh
echo "uv $* NATIVE_TLS=${UV_NATIVE_TLS:-}" >> "$FAKE_LOG"
[ -n "${FAKE_UV_FAIL:-}" ] && { echo "error: invalid peer certificate: UnknownIssuer in $HOME/.cache/uv" >&2; exit 1; }
printf '#!/bin/sh\necho "$0 $*" >> "$FAKE_LOG"\necho "squidbrake 0.9.0-uv"\n' > "$UV_TOOL_BIN_DIR/squidbrake"
chmod +x "$UV_TOOL_BIN_DIR/squidbrake"
"""

TOOLS = ("mkdir", "rm", "ln", "cp", "chmod", "tail", "sed", "grep", "mktemp", "dirname", "basename", "uname", "cat",
         "env", "sh", "printf", "tr", "cut", "awk", "head", "dash")


FAKE_CURL = r"""#!/bin/sh
echo "curl $*" >> "$FAKE_LOG"
for a in "$@"; do case "$a" in @*) cat "${a#@}" > "$FAKE_LOG.sent" ;; esac; done
exit 0
"""


def _exe(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")
    path.chmod(0o755)


@pytest.fixture()
def box(tmp_path):
    """A home with a space in it, a fake python3 / uv, and a PATH with nothing else that could be a real Python."""
    home = tmp_path / "home dir"
    fake, tools = tmp_path / "fake", tmp_path / "tools"
    for d in (home, fake, tools):
        d.mkdir()
    _exe(fake / "python3", FAKE_PYTHON)
    if os.name == "nt":
        path = [str(fake), str(Path(SH).parent)]                     # Git's usr/bin: the tools, and no Python
    else:
        for t in TOOLS:
            if w := shutil.which(t):
                (tools / t).symlink_to(w)
        path = [str(fake), str(tools)]

    def run(shell=SH, stdin=subprocess.DEVNULL, **env):
        e = {"HOME": str(home), "PATH": os.pathsep.join(path), "SHELL": "/bin/bash", "FAKE_LOG": str(tmp_path / "log"),
             "SQUIDBRAKE_PYTHONS": "python3", "TMPDIR": str(tmp_path),
             "SQUIDBRAKE_VERSION": "any", **env}
        if os.name == "nt":
            e["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
        p = subprocess.run([shell, SCRIPT.as_posix()], env=e, stdin=stdin, capture_output=True, text=True, timeout=60,
                           start_new_session=os.name != "nt")
        return p.returncode, p.stdout + p.stderr

    box = type("Box", (), {})()
    box.home, box.fake, box.run, box.tmp = home, fake, run, tmp_path
    box.app, box.bin = home / ".squidbrake" / "app", home / ".local" / "bin"
    box.log = lambda: (tmp_path / "log").read_text() if (tmp_path / "log").exists() else ""
    box.add_uv = lambda: _exe(fake / "uv", FAKE_UV)
    return box


def test_fresh_install_uses_the_python_here(box):
    code, out = box.run()
    assert code == 0, out
    assert "Installed: squidbrake 0.9.0" in out and (box.app / "bin" / "squidbrake").exists()
    assert "uv " not in box.log()
    bashrc = ".bash_profile" if sys.platform == "darwin" else ".bashrc"      # bash on a Mac reads .bash_profile
    rc = (box.home / bashrc).read_text()
    assert rc.count("home dir/.local/bin") == 1
    box.run()                                                            # run again: the PATH line isn't added twice
    assert (box.home / bashrc).read_text().count("home dir/.local/bin") == 1


def test_an_upgrade_that_cant_download_keeps_the_working_install(box):
    assert box.run()[0] == 0
    box.add_uv()
    code, out = box.run(FAKE_PIP_FAIL="1", FAKE_VERSION="1.0.0")
    assert code == 0, out
    assert "you still have squidbrake 0.9.0" in out and "Could not find a version" in out    # why, from pip
    assert (box.app / "bin" / "squidbrake").exists() and (box.app / "bin" / "python").exists()  # the hooks run these
    assert "uv " not in box.log()                                      # no second copy the hooks don't use


def test_no_venv_module_falls_back_to_uv_with_this_computers_certificates(box):
    box.add_uv()
    code, out = box.run(FAKE_NO_VENV="1")
    assert code == 0, out
    assert "python3-venv" in out and "Installed: squidbrake 0.9.0-uv" in out
    assert not box.app.exists()                                        # the half-made venv is gone
    assert "NATIVE_TLS=1" in box.log()


def test_a_failed_download_says_why(box):
    box.add_uv()
    code, out = box.run(FAKE_PIP_FAIL="1", FAKE_UV_FAIL="1")
    assert code == 1
    assert "Could not find a version" in out and "UnknownIssuer" in out
    assert "virtual environment" not in out                            # it wasn't the venv


def test_installed_with_uv_stays_with_uv(box):
    box.add_uv()
    assert box.run(SQUIDBRAKE_INSTALL_WITH="uv")[0] == 0
    open(box.tmp / "log", "w").close()
    code, out = box.run()                                              # python3 is here now too
    assert code == 0 and "0.9.0-uv" in out and "pip " not in box.log()


def test_pilot_join_without_a_terminal_says_how_to_join(box):
    code, out = box.run(SQUIDBRAKE_PILOT="acme-abc123", SQUIDBRAKE_PILOT_SERVER="https://pilots.example.com")
    assert code == 0, out
    assert "No such device" not in out
    if os.name != "nt":                                                # new session: no terminal to open
        assert "squidbrake pilot join acme-abc123 --server https://pilots.example.com" in out
        assert "pilot join" not in box.log()


@pytest.mark.parametrize("shell,rc", [("zsh", ".zshrc"), ("fish", ".config/fish/conf.d/squidbrake.fish"), ("ksh", ".profile")])
def test_path_goes_where_that_shell_reads_it(box, shell, rc):
    assert box.run(SHELL=f"/bin/{shell}")[0] == 0
    assert "home dir/.local/bin" in (box.home / rc).read_text()


def test_bash_on_a_mac_uses_bash_profile(box):
    _exe(box.fake / "uname", "#!/bin/sh\necho Darwin\n")
    assert box.run()[0] == 0
    assert "home dir/.local/bin" in (box.home / ".bash_profile").read_text()


@pytest.mark.skipif(not shutil.which("dash"), reason="dash isn't here")
def test_runs_under_dash(box):                                        # Ubuntu's sh
    code, out = box.run(shell=shutil.which("dash"))
    assert code == 0 and "Installed: squidbrake 0.9.0" in out, out


def test_a_cut_off_download_runs_nothing():
    lines = [x for x in SCRIPT.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert lines[-1] == 'main "$@"'
    body = SCRIPT.read_text(encoding="utf-8")
    assert not re.search(r"\[ [^]]* -a [^]]*\]", body)                 # obsolescent in POSIX test


def test_a_mac_without_developer_tools_never_runs_apples_python_stub():
    body = SCRIPT.read_text(encoding="utf-8")
    assert re.search(r"/usr/bin/python3.*\n.*Darwin.*xcode-select -p", body)


def test_installers_are_executable_in_git():
    out = subprocess.run(["git", "ls-files", "-s", "install.sh", "insights/install.sh"], cwd=ROOT,
                         capture_output=True, text=True).stdout
    if out:
        assert all(line.startswith("100755") for line in out.splitlines()), out


def test_a_failed_install_is_sent_only_after_a_yes_without_the_home_folder(box):
    box.add_uv()
    _exe(box.fake / "curl", FAKE_CURL)
    code, out = box.run(FAKE_PIP_FAIL="1", FAKE_UV_FAIL="1")             # no terminal to ask on: nothing is sent
    assert code == 1 and "curl" not in box.log()
    code, out = box.run(FAKE_PIP_FAIL="1", FAKE_UV_FAIL="1", SQUIDBRAKE_SEND_REPORT="no")
    assert "curl" not in box.log()
    code, out = box.run(FAKE_PIP_FAIL="1", FAKE_UV_FAIL="1", SQUIDBRAKE_SEND_REPORT="yes",
                        SQUIDBRAKE_PILOT="acme-abc123", SQUIDBRAKE_PILOT_SERVER="https://pilots.example.com")
    assert code == 1 and "Sent. Thank you" in out
    call = next(line for line in box.log().splitlines() if line.startswith("curl "))
    assert "https://pilots.example.com/v1/install-report?installer=sh&code=acme-abc123" in call
    sent = (box.tmp / "log.sent").read_text()
    assert "UnknownIssuer in ~/.cache/uv" in sent and "home dir" not in sent


def test_after_installing_it_sets_everything_up(box):
    code, out = box.run()
    assert code == 0 and "squidbrake setup" in box.log()              # the fake records how it was run
    open(box.tmp / "log", "w").close()
    code, out = box.run(SQUIDBRAKE_SETUP="0")
    assert code == 0 and "setup" not in box.log() and "Next:" in out


PYPI_CURL = r"""#!/bin/sh
echo "curl $*" >> "$FAKE_LOG"
case "$*" in *pypi.org/pypi/squidbrake/json*) printf '{"info":{"author":"x","version":"0.9.5","yanked":false}}' ;; esac
"""


def test_it_asks_pypi_for_the_newest_version_and_installs_that_one(box):
    """PyPI's list of files lags a release by up to 10 minutes; asking for the version by name gets it."""
    _exe(box.fake / "curl", PYPI_CURL)
    code, out = box.run(SQUIDBRAKE_VERSION="")
    assert code == 0, out
    assert "squidbrake==0.9.5" in box.log()
    open(box.tmp / "log", "w").close()
    code, out = box.run(SQUIDBRAKE_VERSION="", FAKE_PIN_FAIL="1")          # not downloadable yet: what the list has
    pips = [line for line in box.log().splitlines() if line.startswith("pip ")]
    assert code == 0, out
    assert pips[0].endswith("squidbrake==0.9.5") and pips[-1].endswith("--upgrade squidbrake")

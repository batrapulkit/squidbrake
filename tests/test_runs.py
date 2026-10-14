"""runs.py: what `make X`, `npm run X` and `bash x.sh` run underneath, read from the files (never run)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import runs  # noqa: E402


def lines(found):
    return [(f["via"], l) for f in found for l in f["lines"]]


def test_make_target_recipe_with_its_prerequisites(tmp_path):
    (tmp_path / "Makefile").write_text(
        "BUILD := build\nDEST = $(BUILD)/out\n\n"
        "all: test\n\n"
        "clean: tidy\n\t@echo cleaning\n\t-rm -rf $(DEST) \\\n\t  ~/\n\n"
        "tidy:\n\trm -f *.log\n\n"
        "test:\n\tpytest -q   # comment\n.PHONY: clean tidy test\n")
    assert lines(runs.expand("make clean", str(tmp_path))) == [
        ("Makefile target `tidy`", "rm -f *.log"),
        ("Makefile target `clean`", "echo cleaning"),
        ("Makefile target `clean`", "rm -rf build/out ~/"),        # variables expanded, continuation joined
    ]
    # default: the first target; a # inside a recipe goes to the shell, as make does
    assert lines(runs.expand("make", str(tmp_path))) == [("Makefile target `test`", "pytest -q   # comment")]
    assert runs.expand("make nope", str(tmp_path)) == []


def test_make_directory_file_and_chains(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "build.mk").write_text("wipe:\n\tgit push --force origin main\n")
    (sub / "Makefile").write_text("x:\n\techo x\n")
    assert lines(runs.expand("make -C sub -f build.mk wipe", str(tmp_path))) == [("build.mk target `wipe`", "git push --force origin main")]
    assert lines(runs.expand("cd /tmp && make -Csub x V=1", str(tmp_path))) == [("Makefile target `x`", "echo x")]
    assert runs.expand("make clean", str(tmp_path)) == []              # no Makefile here


def test_package_json_scripts(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {
        "prerelease": "npm test", "release": "git push --force", "postrelease": "echo done",
        "test": "jest", "build": "tsc"}}))
    assert [v for v, _ in lines(runs.expand("npm run release", str(tmp_path)))] == [
        "package.json script `prerelease`", "package.json script `release`", "package.json script `postrelease`"]
    assert lines(runs.expand("npm test", str(tmp_path))) == [("package.json script `test`", "jest")]
    assert lines(runs.expand("yarn build", str(tmp_path))) == [("package.json script `build`", "tsc")]
    assert lines(runs.expand("pnpm run build", str(tmp_path))) == [("package.json script `build`", "tsc")]
    assert runs.expand("npm install", str(tmp_path)) == []
    (tmp_path / "package.json").write_text("{not json")
    assert runs.expand("npm run release", str(tmp_path)) == []


def test_shell_scripts(tmp_path):
    (tmp_path / "go.sh").write_text("#!/bin/sh\n# tidy up\nrm -rf ~/\n\necho ok\n")
    for cmd in ("bash go.sh", "sh ./go.sh", "./go.sh"):
        assert lines(runs.expand(cmd, str(tmp_path))) == [("script go.sh", "rm -rf ~/"), ("script go.sh", "echo ok")]
    assert runs.expand("bash missing.sh", str(tmp_path)) == []
    assert runs.expand("python go.py", str(tmp_path)) == []          # other languages: not read


def test_makefile_include_and_conditionals(tmp_path):
    (tmp_path / "build.mk").write_text("clean:\n\trm -rf build/ ~/\n")
    (tmp_path / "Makefile").write_text(
        "include build.mk\n"
        "-include not-there.mk\n"                                  # missing: ignored, like make
        "wipe:\n"
        "ifeq ($(DEBUG),1)\n"
        "\techo safe\n"
        "else\n"
        "\trm -rf ~/\n"                                            # both branches are read, make never picks here
        "endif\n"
    )
    assert lines(runs.expand("make clean", str(tmp_path))) == [("Makefile target `clean`", "rm -rf build/ ~/")]
    assert lines(runs.expand("make wipe", str(tmp_path))) == [                        # both branches are read
        ("Makefile target `wipe`", "echo safe"),
        ("Makefile target `wipe`", "rm -rf ~/"),
    ]

    (tmp_path / "a.mk").write_text("include b.mk\n")               # a few levels deep, cycles end
    (tmp_path / "b.mk").write_text("include a.mk\ndeep:\n\techo deep\n")
    assert [l for _, l in lines(runs.expand("make -f a.mk deep", str(tmp_path)))] == ["echo deep"]


def test_bounded(tmp_path):
    (tmp_path / "Makefile").write_text("big:\n" + "".join(f"\techo {i}\n" for i in range(500)))
    assert len(lines(runs.expand("make big", str(tmp_path)))) == runs.MAX_LINES
    (tmp_path / "Makefile").write_text("loop: loop2\n\techo a\nloop2: loop\n\techo b\n")   # cycles end
    assert len(lines(runs.expand("make loop", str(tmp_path)))) == 2
    (tmp_path / "huge.sh").write_text("echo x\n" * (runs.MAX_FILE_BYTES // 7 + 10))
    assert runs.expand("bash huge.sh", str(tmp_path)) == []

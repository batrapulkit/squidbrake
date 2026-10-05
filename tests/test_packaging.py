"""The Docker image must carry every local module the gateway imports: 0.4.0-0.6.1 images crashed on `import evidence`."""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def local_imports(path: Path) -> set[str]:
    """Modules a file imports (anywhere, including inside try: and functions) that live next to it in the repo."""
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module.split(".")[0])
    return {n for n in names if (ROOT / f"{n}.py").exists()}


def imported_by(*start: str) -> set[str]:
    needed, todo = set(start), list(start)
    while todo:
        for dep in local_imports(ROOT / f"{todo.pop()}.py") - needed:
            needed.add(dep)
            todo.append(dep)
    return needed


def test_pip_package_includes_everything_the_cli_and_hooks_import():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    packaged = set(re.findall(r'^"([\w.]+\.py)" = "squidbrake/', text, re.M))
    cli = (ROOT / "squidbrake" / "cli.py").read_text(encoding="utf-8")
    entry = {m for m in re.findall(r"\b(?:import|from) ([a-z_]+)", cli) if (ROOT / f"{m}.py").exists()}
    needed = imported_by("server", "claude_hook", "agent_hook", "connect", *entry)
    missing = sorted(f"{m}.py" for m in needed if f"{m}.py" not in packaged)
    assert not missing, f"pyproject.toml doesn't force-include {missing}"


def test_docker_image_copies_everything_the_server_imports():
    copied = set()
    for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines():
        if line.startswith("COPY "):
            copied |= {Path(w).name for w in line.split()[1:-1]}
    needed, todo = set(), ["server"]
    while todo:                                   # follow imports of imports
        mod = todo.pop()
        for dep in local_imports(ROOT / f"{mod}.py") - needed:
            needed.add(dep)
            todo.append(dep)
    missing = sorted(f"{m}.py" for m in needed | {"server"} if f"{m}.py" not in copied)
    assert not missing, f"Dockerfile doesn't COPY {missing}; the image would crash on start"
    assert "rules.shipped" in copied and "rules.yaml" in copied
    assert re.search(r"^CMD .*server\.py", (ROOT / "Dockerfile").read_text(encoding="utf-8"), re.M)

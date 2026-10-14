"""
What a command runs underneath, read from the files on this machine before it runs, so the gateway can check those
commands too: `make clean` is only as safe as the `clean` target's recipe.

  make [TARGET...]              the recipe lines of each target and the targets it depends on (Makefile, -f, -C)
  npm run X / npm test / ...    the package.json script, with its pre/post scripts (npm, pnpm, yarn, bun)
  bash x.sh / sh x.sh / ./x.sh  the script's lines

Used by the hooks (claude_hook.py, agent_hook.py), which send the result as metadata["runs"]:
  [{"via": "Makefile target `clean`", "lines": ["rm -rf build/ ~/"]}]
The gateway reads each line like the command itself (server.py command_signals). It can only make a decision
stricter: what's found here is checked in addition to the command, never instead of it.

Only reads files, never runs anything. Bounded: MAX_LINES lines and MAX_FILE_BYTES per file; anything it can't read
is left out. Not covered: scripts in other languages (python x.py), recipes built at run time ($(shell ...), eval),
make variables beyond simple `NAME = value` definitions.

`include` files are followed (a few levels deep, cycles skipped) and conditionals are read on BOTH sides, so a
recipe hidden in an included file or in either branch of an `ifeq` is still checked.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import commands

MAX_LINES = 60
MAX_FILE_BYTES = 256 * 1024
MAKE_PROGRAMS = {"make", "gmake", "mingw32-make"}
NODE_PM = {"npm", "pnpm", "yarn", "bun"}
NPM_SHORTCUTS = {"test", "start", "stop", "restart"}      # `npm test` runs scripts.test
SHELLS = {"bash", "sh", "zsh", "dash"}
_VAR_DEF = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*)\s*(?:\?|:|::)?=\s*(.*)$")
_RULE = re.compile(r"^([^:=#\t][^:=#]*?)\s*::?(?!=)\s*(.*)$")
_VAR_USE = re.compile(r"\$\(([A-Za-z_][A-Za-z0-9_.-]*)\)|\$\{([A-Za-z_][A-Za-z0-9_.-]*)\}")
_COND = re.compile(r"^(ifeq|ifneq|ifdef|ifndef)\b")                  # both branches are read, see _parse
_COND_ELSE = re.compile(r"^else\b")
_COND_END = re.compile(r"^endif\b")
_INCLUDE = re.compile(r"^(-?)include\s+(.*)$")
MAX_INCLUDE_DEPTH = 3                                               # "at most a few levels deep"


def _read(path: Path) -> str | None:
    try:
        if path.is_file() and path.stat().st_size <= MAX_FILE_BYTES:
            return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    return None


# --------------------------------------------------------------------------- make

def _parse(text: str, folder: Path, depth: int, seen: set[Path]) -> tuple[dict[str, tuple[list[str], list[str]]], dict[str, str], str | None]:
    """-> (rules, simple variables, the default target). `include` files are followed and conditionals are read
    on BOTH sides: `ifeq ... else ... endif` keeps the recipe lines of either branch rather than working out
    which one make would pick. That can only make a gateway decision stricter — it holds what any branch
    would run — never looser.
    """
    text = re.sub(r"[ \t]*\\\r?\n[ \t]*", " ", text)                # joined continuation lines
    variables: dict[str, str] = {}
    rules: dict[str, tuple[list[str], list[str]]] = {}
    includes: list[str] = []
    default, current = None, []
    cond_depth = 0
    for raw in text.splitlines():
        if raw.startswith("\t"):
            line = raw[1:].strip()
            if current and line and not line.startswith("#"):
                for t in current:
                    rules[t][1].append(line)                        # either branch is kept, see _parse
            continue
        line = raw.split("#", 1)[0].rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if _COND.match(stripped):
            cond_depth += 1
            continue
        if _COND_END.match(stripped):
            cond_depth = max(0, cond_depth - 1)
            continue
        if _COND_ELSE.match(stripped):
            continue                                                # the other branch keeps the same target
        if cond_depth == 0 and (m := _INCLUDE.match(stripped)):
            includes += m.group(2).split()
            current = []
            continue
        if m := _VAR_DEF.match(stripped):
            variables[m.group(1)] = m.group(2).strip()
            current = []
            continue
        if m := _RULE.match(line):
            targets = [t for t in m.group(1).split() if t]
            deps, _, inline = m.group(2).partition(";")
            current = [t for t in targets if not t.startswith(".")]
            for t in current:
                rules.setdefault(t, ([], []))
                rules[t][0].extend(deps.split())
                if inline.strip():
                    rules[t][1].append(inline.strip())
            if default is None and current and "%" not in current[0]:
                default = current[0]
            continue
        current = []

    for name in includes:
        if depth >= MAX_INCLUDE_DEPTH:                              # "at most a few levels deep"
            break
        path = folder / name
        if not path.is_file():                                      # a missing -include is ignored by make too
            continue
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved in seen:                                        # include cycle: stop, don't hang the hook
            continue
        seen.add(resolved)
        included = _read(path)
        if included is None:
            continue
        inc_rules, inc_vars, inc_default = _parse(included, path.parent, depth + 1, seen)
        for t, (deps, recipe) in inc_rules.items():                 # the includer's own rules win, both are kept
            if t not in rules:
                rules[t] = (deps, recipe)
            else:
                rules[t][0].extend(d for d in deps if d not in rules[t][0])
                rules[t][1].extend(recipe)
        variables.update(inc_vars)
        if default is None and inc_default:
            default = inc_default

    return rules, variables, default


def parse_makefile(text: str, folder: Path) -> tuple[dict[str, tuple[list[str], list[str]]], str | None]:
    """-> ({target: (prerequisites, recipe lines)}, the default target). Simple variables are expanded.

    `folder` is the Makefile's own directory: `include` paths are resolved against it.
    """
    rules, variables, default = _parse(text, folder, 0, set())

    def expand(s: str, depth: int = 0) -> str:
        if depth > 5:
            return s
        out = _VAR_USE.sub(lambda m: expand(variables.get(m.group(1) or m.group(2), m.group(0)), depth + 1), s)
        return out.replace("$$", "$")

    return ({t: ([expand(d) for d in deps], [expand(r) for r in recipe]) for t, (deps, recipe) in rules.items()},
            default)


def _recipe_line(line: str) -> str:
    return line.lstrip("@-+ \t")                                    # @ silent, - ignore errors, + always run


def _make(words: list[str], cwd: Path) -> list[dict]:
    directory, makefile, targets, args = cwd, None, [], iter(words[1:])
    for w in args:
        if w in ("-C", "--directory"):
            directory = directory / next(args, ".")
        elif w.startswith("--directory="):
            directory = directory / w.split("=", 1)[1]
        elif w in ("-f", "--file", "--makefile"):
            makefile = next(args, None)
        elif w.startswith(("--file=", "--makefile=")):
            makefile = w.split("=", 1)[1]
        elif w.startswith("-C") and len(w) > 2:
            directory = directory / w[2:]
        elif w.startswith("-f") and len(w) > 2:
            makefile = w[2:]
        elif not w.startswith("-") and "=" not in w:
            targets.append(w)
    if makefile:
        path = directory / makefile
    else:   # make's own order, by the names really on disk (Windows would match "makefile" to "Makefile")
        try:
            names = set(os.listdir(directory))
        except OSError:
            return []
        path = next((directory / n for n in ("GNUmakefile", "makefile", "Makefile") if n in names), None)
    if path is None:
        return []
    text = _read(path)
    if text is None:
        return []
    rules, default = parse_makefile(text, path.parent)
    found: list[dict] = []
    seen: set[str] = set()

    def visit(t: str, depth: int) -> None:
        if t in seen or depth > 8 or t not in rules:
            return
        seen.add(t)
        deps, recipe = rules[t]
        for d in deps:
            visit(d, depth + 1)
        if recipe:
            found.append({"via": f"{path.name} target `{t}`", "lines": [_recipe_line(r) for r in recipe]})

    for t in targets or ([default] if default else []):
        visit(t, 0)
    return found


# --------------------------------------------------------------------------- package.json scripts

def _node(words: list[str], cwd: Path) -> list[dict]:
    prog, rest = words[0], [w for w in words[1:] if not w.startswith("-")]
    if not rest:
        return []
    if rest[0] in ("run", "run-script"):
        name = rest[1] if len(rest) > 1 else None
    elif rest[0] in NPM_SHORTCUTS or prog in ("yarn", "pnpm", "bun"):
        name = rest[0]                                              # yarn build, pnpm lint, bun dev
    else:
        return []
    text = _read(cwd / "package.json")
    try:
        scripts = json.loads(text).get("scripts") if text else None
    except (ValueError, AttributeError):
        return []
    if not isinstance(scripts, dict) or not isinstance(scripts.get(name), str):
        return []
    found = []
    for key in (f"pre{name}", name, f"post{name}"):
        if isinstance(scripts.get(key), str):
            found.append({"via": f"package.json script `{key}`", "lines": [scripts[key]]})
    return found


# --------------------------------------------------------------------------- shell scripts

def _script(path_word: str, cwd: Path) -> list[dict]:
    p = Path(path_word.strip("'\""))
    p = p if p.is_absolute() else cwd / p
    text = _read(p)
    if text is None:
        return []
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    return [{"via": f"script {p.name}", "lines": lines}] if lines else []


# --------------------------------------------------------------------------- entry point

def expand(line: str, cwd: str | None = None) -> list[dict]:
    """What the command line runs underneath, as [{"via": ..., "lines": [...]}]. Empty when there's nothing to read."""
    base = Path(cwd or os.getcwd())
    out: list[dict] = []
    try:
        reading = commands.read(line)
    except Exception:
        return out
    for cmd in reading.commands:
        words = cmd.words
        prog = cmd.program
        try:
            if prog in MAKE_PROGRAMS:
                out += _make(words, base)
            elif prog in NODE_PM:
                out += _node(words, base)
            elif prog in SHELLS and len(words) > 1 and not words[1].startswith("-") and words[1].endswith(".sh"):
                out += _script(words[1], base)
            elif words and (words[0].startswith("./") or words[0].startswith(".\\")) and words[0].endswith(".sh"):
                out += _script(words[0], base)
        except Exception:
            continue
    total, kept = 0, []
    for item in out:                                                # bounded, in order
        lines = [l[:1000] for l in item["lines"] if l][: MAX_LINES - total]
        if lines:
            kept.append({"via": item["via"][:200], "lines": lines})
            total += len(lines)
        if total >= MAX_LINES:
            break
    return kept

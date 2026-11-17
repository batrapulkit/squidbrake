"""
What a command will change, measured on this machine before it runs, so the approver sees a number, not a guess.

  git push --force      -> the commits on the remote that the push would remove (as of your last fetch)
  git reset --hard      -> the files with uncommitted changes it would throw away, and the commits it would leave
  git clean -f          -> the untracked files it would delete (git's own dry run)
  git checkout/restore  -> the changed files it would overwrite
  rm -r, Remove-Item, rmdir /s, del -> how many files and how much data the paths hold

  psql / mysql / sqlite3 DELETE, UPDATE, TRUNCATE, DROP TABLE -> how many rows, counted with the same WHERE
  terraform destroy / apply  -> how many resources go, and which of them hold data (databases, buckets, volumes)
  aws s3 rb / rm --recursive -> how many objects and how much data
  aws rds delete-db-*        -> the database's engine and size, and whether a final snapshot and backups are kept
  kubectl delete             -> the objects that match, and the cluster they're in

Used by the hooks (claude_hook.py, agent_hook.py), which run on the developer's machine: the gateway can't see
the repository, the database or the cloud account. Only reads: git commands here are local (no fetch, no network),
dry runs, or counts. Database counts run in a read-only session with a statement timeout; cloud and cluster
checks are list/describe calls with the same credentials the command itself would use. Everything is bounded in time
and size, and anything that fails is simply left out.
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import commands

BUDGET_SECONDS = 2.0        # for all local predictions on one command line
REMOTE_SECONDS = float(os.getenv("SQUIDBRAKE_EFFECTS_SECONDS", "10"))  # databases, clouds, clusters (only for those)
PLAN_SECONDS = float(os.getenv("SQUIDBRAKE_PLAN_SECONDS", "20"))       # a terraform plan, when it needs one
WALK_LIMIT = 20000          # files counted under the paths a delete names, at most
DELETE_PROGRAMS = {"rm", "remove-item", "ri", "rmdir", "rd", "del", "erase", "rimraf"}
WINDOWS_FLAG = re.compile(r"/[a-zA-Z]$")


def _git(cwd: str, *args: str, timeout: float = 2.0) -> str | None:
    try:
        r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"})
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def _names(lines: list[str], n: int = 3) -> str:
    shown = ", ".join(lines[:n])
    return shown + (f" and {len(lines) - n} more" if len(lines) > n else "")


def _size(n: float) -> str:
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return (f"{n:.0f} byte" + ("" if n == 1 else "s")) if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


# --------------------------------------------------------------------------- git

def _push(words: list[str], cwd: str) -> str | None:
    args = words[2:]
    force = any(a in ("-f", "--force") or a.startswith("--force-with-lease") or a.startswith("+") for a in args)
    if not force:
        return None
    plain = [a.lstrip("+") for a in args if not a.startswith("-")]
    remote = plain[0] if plain else "origin"
    branch = plain[1].split(":")[-1] if len(plain) > 1 else (_git(cwd, "rev-parse", "--abbrev-ref", "HEAD") or "").strip()
    local = plain[1].split(":")[0] if len(plain) > 1 and plain[1].split(":")[0] else "HEAD"
    if not branch or branch == "HEAD":
        return None
    target = f"{remote}/{branch}"
    if _git(cwd, "rev-parse", "--verify", "--quiet", f"refs/remotes/{target}") is None:
        return f"{target} isn't known on this machine yet, so nothing on it can be counted"
    lost = (_git(cwd, "log", "--format=%h %s", f"{local}..{target}") or "").splitlines()
    if not lost:
        return f"No commits on {target} would be lost (as of your last fetch)"
    return (f"Removes {len(lost)} commit{'s' if len(lost) != 1 else ''} from {target} that this branch doesn't have "
            f"(as of your last fetch): {_names([l.split(' ', 1)[-1] for l in lost])}")


def _changed_files(cwd: str, paths: list[str] | None = None) -> list[str]:
    out = _git(cwd, "status", "--porcelain", "--untracked-files=no", *(["--", *paths] if paths else []))
    return [l[3:] for l in (out or "").splitlines() if l.strip()]


def _reset(words: list[str], cwd: str) -> str | None:
    if "--hard" not in words:
        return None
    parts = []
    changed = _changed_files(cwd)
    if changed:
        parts.append(f"throws away uncommitted changes in {len(changed)} file{'s' if len(changed) != 1 else ''}: {_names(changed)}")
    ref = next((w for w in words[2:] if not w.startswith("-")), None)
    if ref:
        left = (_git(cwd, "log", "--format=%s", f"{ref}..HEAD") or "").splitlines()
        if left:
            parts.append(f"moves the branch off {len(left)} commit{'s' if len(left) != 1 else ''}: {_names(left)}")
    return ("It " + "; it ".join(parts)) if parts else "No uncommitted changes would be lost"


def _clean(words: list[str], cwd: str) -> str | None:
    flags = [w for w in words[2:] if w.startswith("-")]
    if not any("f" in f.lstrip("-") or f == "--force" for f in flags):
        return None
    keep = []  # the same flags as a dry run: -fdx -> -dx (plus -n), --force dropped
    for f in flags:
        if f.startswith("--"):
            if f not in ("--force", "--interactive", "--dry-run"):
                keep.append(f)
        elif rest := re.sub(r"[fni]", "", f[1:]):
            keep.append("-" + rest)
    out = _git(cwd, "clean", "-n", *keep, *[w for w in words[2:] if not w.startswith("-")])
    if out is None:
        return None
    files = [l.removeprefix("Would remove ").strip() for l in out.splitlines() if l.strip()]
    if not files:
        return "No untracked files would be deleted"
    return f"Deletes {len(files)} untracked file{'s' if len(files) != 1 else ''} git has never saved: {_names(files)}"


def _checkout(words: list[str], cwd: str) -> str | None:
    sub = words[1]
    if sub == "checkout" and "--" not in words and "." not in words:
        return None
    paths = [w for w in words[words.index("--") + 1:]] if "--" in words else [w for w in words[2:] if not w.startswith("-")]
    if sub == "restore" and ("--staged" in words and "--worktree" not in words):
        return None
    changed = _changed_files(cwd, paths or None)
    if not changed:
        return None
    return f"Overwrites uncommitted changes in {len(changed)} file{'s' if len(changed) != 1 else ''}: {_names(changed)}"


# --------------------------------------------------------------------------- deletes

def delete_targets(cmd: commands.Command, cwd: str) -> list[Path]:
    """The existing paths a delete command names (globs and ~ expanded)."""
    words, prog = cmd.words[1:], cmd.program
    if prog not in DELETE_PROGRAMS:
        return []
    out: list[Path] = []
    skip_next = False
    for w in words:
        if skip_next:
            skip_next = False
            continue
        if w.startswith("-"):
            if prog in ("remove-item", "ri") and w.lower() in ("-path", "-literalpath"):
                continue
            if prog in ("remove-item", "ri") and w.lower() in ("-include", "-exclude", "-filter"):
                skip_next = True
            continue
        if prog in ("rmdir", "rd", "del", "erase") and WINDOWS_FLAG.match(w):
            continue
        w = os.path.expandvars(os.path.expanduser(w.strip("'\"")))
        p = w if os.path.isabs(w) else os.path.join(cwd, w)
        for m in (glob.glob(p) if any(c in p for c in "*?[") else [p]):
            if os.path.lexists(m):
                out.append(Path(m))
    return out


def walk(paths: list[Path], deadline: float) -> tuple[int, int, bool]:
    """(files, bytes, complete) under the paths, stopping at WALK_LIMIT files or the deadline."""
    files = size = 0
    for p in paths:
        if p.is_file() or p.is_symlink():
            files += 1
            size += p.lstat().st_size
            continue
        for root, _dirs, names in os.walk(p):
            for n in names:
                files += 1
                try:
                    size += os.lstat(os.path.join(root, n)).st_size
                except OSError:
                    pass
                if files >= WALK_LIMIT or time.monotonic() > deadline:
                    return files, size, False
    return files, size, True


def _delete(cmd: commands.Command, cwd: str, deadline: float) -> str | None:
    targets = delete_targets(cmd, cwd)
    if not targets:
        return None
    files, size, complete = walk(targets, deadline)
    def shown(t: Path) -> str:  # inside the project: the short path the developer typed
        try:
            return os.path.relpath(t, cwd) if Path(t).resolve().is_relative_to(Path(cwd).resolve()) else str(t)
        except ValueError:      # another drive on Windows
            return str(t)
    where = _names([shown(t) for t in targets], 2)
    more = "+" if not complete else ""
    return f"Deletes {files:,}{more} file{'s' if files != 1 else ''} ({_size(size)}{more}) in {where}"


# --------------------------------------------------------------------------- running other tools (read-only calls)

def _left(deadline: float) -> float:
    return deadline - time.monotonic()


def _env(cmd: commands.Command, extra: dict | None = None) -> dict:
    """The environment the command would run with: ours, plus any FOO=bar it sets in front of itself."""
    env = dict(os.environ)
    for w in commands._words(cmd.raw or ""):
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", w)
        if not m:
            break
        env[m.group(1)] = os.path.expandvars(m.group(2))
    return {**env, **(extra or {})}


def _run(args: list[str], timeout: float, env: dict | None = None, cwd: str | None = None) -> tuple[str | None, bool]:
    """(stdout, finished) of a read-only call. stdout is None if the program isn't here or failed; when time runs
    out, it's whatever was printed so far and finished is False."""
    exe = shutil.which(args[0])
    if not exe or timeout <= 0:
        return None, False
    try:
        r = subprocess.run([exe, *args[1:]], capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd,
                           stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as e:
        out = e.output
        return (out.decode(errors="replace") if isinstance(out, bytes) else out), False
    except (OSError, subprocess.SubprocessError):
        return None, False
    return (r.stdout if r.returncode == 0 else None), True


def _plural(n: int, word: str) -> str:
    return f"{n:,} {word}{'' if n == 1 else 's'}"


# --------------------------------------------------------------------------- databases: count the rows first

SQL_PROGRAMS = {"psql", "mysql", "mariadb", "sqlite3"}
IDENT = r'(?:"[^"]+"|`[^`]+`|\[[^\]]+\]|[A-Za-z_][\w$]*)'
TABLE = rf"{IDENT}(?:\.{IDENT}){{0,2}}"
# Never run as part of a count, even read-only: functions that act, wait, or reach outside the database
SQL_SIDE_EFFECTS = re.compile(r"\b(pg_terminate_backend|pg_cancel_backend|pg_sleep\w*|pg_reload_conf|pg_read_\w+|"
                              r"pg_ls_dir|pg_advisory\w*|pg_notify|lo_\w+|dblink\w*|set_config|nextval|setval|copy|"
                              r"load_file|sleep|benchmark|outfile|dumpfile|load_extension|writefile|readfile|"
                              r"attach|pragma)\b", re.I)


def _statements(sql: str) -> list[str]:
    out, buf, quote = [], [], None
    for ch in sql:
        if quote:
            quote = None if ch == quote else quote
        elif ch in "'\"`":
            quote = ch
        elif ch == ";":
            out.append("".join(buf)); buf = []
            continue
        buf.append(ch)
    out.append("".join(buf))
    return [s.strip() for s in out if s.strip()]


def _top_level(sql: str, word: str) -> int:
    """Where `word` first appears as a keyword outside quotes and brackets, or -1."""
    depth, quote = 0, None
    for i, ch in enumerate(sql):
        if quote:
            quote = None if ch == quote else quote
        elif ch in "'\"`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and sql[i:i + len(word)].lower() == word and (i == 0 or not (sql[i - 1].isalnum() or sql[i - 1] == "_")) \
                and not (sql[i + len(word):i + len(word) + 1].isalnum() or sql[i + len(word):i + len(word) + 1] == "_"):
            return i
    return -1


def sql_targets(sql: str) -> list[tuple[str, str, str | None]] | None:
    """(verb, table, where) for each statement, or None unless every statement is one we can count safely:
    DELETE, UPDATE, TRUNCATE or DROP TABLE, with no side-effect functions in the WHERE."""
    stmts = _statements(sql)
    if not stmts or len(stmts) > 3:
        return None
    out: list[tuple[str, str, str | None]] = []
    for s in stmts:
        if (cut := _top_level(s, "returning")) >= 0:
            s = s[:cut].rstrip()
        if m := re.match(rf"(?is)delete\s+from\s+(?:only\s+)?({TABLE})(\s+(?:as\s+)?(?!where\b)\w+)?\s*(.*)$", s):
            table, alias, rest = m.group(1), m.group(2) or "", m.group(3).strip()
            if rest and not re.match(r"(?is)where\b", rest):
                return None                                     # USING, LIMIT, ...: not counted
            out.append(("delete", table + alias, rest[5:].strip() or None if rest else None))
        elif m := re.match(rf"(?is)update\s+(?:only\s+)?({TABLE})(\s+(?:as\s+)?(?!set\b)\w+)?\s+set\s+(.*)$", s):
            table, alias, rest = m.group(1), m.group(2) or "", m.group(3)
            if _top_level(rest, "from") >= 0:
                return None                                     # UPDATE ... FROM: not counted
            w = _top_level(rest, "where")
            out.append(("update", table + alias, rest[w + 5:].strip() or None if w >= 0 else None))
        elif m := re.match(rf"(?is)truncate\s+(?:table\s+)?(?:only\s+)?({TABLE}(?:\s*,\s*{TABLE})*)"
                           r"(?:\s+(?:cascade|restrict|restart\s+identity|continue\s+identity))*$", s):
            out += [("truncate", t.strip(), None) for t in m.group(1).split(",")]
        elif m := re.match(rf"(?is)drop\s+table\s+(?:if\s+exists\s+)?({TABLE}(?:\s*,\s*{TABLE})*)(?:\s+(?:cascade|restrict))?$", s):
            out += [("drop", t.strip(), None) for t in m.group(1).split(",")]
        else:
            return None
    if any(w and SQL_SIDE_EFFECTS.search(w) for _, _, w in out):
        return None
    return out[:5]


def _count_query(table: str, where: str | None) -> str:
    if where:
        return f"SELECT (SELECT count(*) FROM {table} WHERE {where}), (SELECT count(*) FROM {table})"
    return f"SELECT count(*) FROM {table}"


def _rows_message(verb: str, table: str, where: str | None, counts: list[int], label: str) -> str:
    name = table.split()[0]
    at = f" ({label})" if label else ""
    if where and len(counts) == 2:
        hit, total = counts
        every = hit == total and total > 0
        if verb == "delete":
            return (f"Deletes all {_plural(total, 'row')} in {name}{at}: the WHERE matches every row" if every
                    else f"Deletes {_plural(hit, 'row')} of {total:,} in {name}{at}")
        return (f"Changes all {_plural(total, 'row')} in {name}{at}: the WHERE matches every row" if every
                else f"Changes {_plural(hit, 'row')} of {total:,} in {name}{at}")
    n = counts[0]
    return {"delete": f"Deletes all {_plural(n, 'row')} in {name}{at}: there's no WHERE",
            "update": f"Changes all {_plural(n, 'row')} in {name}{at}: there's no WHERE",
            "truncate": f"Empties {name}{at}: {_plural(n, 'row')}",
            "drop": f"Drops table {name}{at} with its {_plural(n, 'row')}"}[verb]


def _sql_text(words: list[str], cwd: str, flags: tuple[str, ...], file_flags: tuple[str, ...]) -> str | None:
    """The SQL a client runs from -c/-e or a -f file (small local files only)."""
    for i, w in enumerate(words):
        nxt = words[i + 1] if i + 1 < len(words) else ""
        if w in flags or re.fullmatch(r"-[A-Za-z]*[" + "".join(f[1] for f in flags if len(f) == 2) + "]", w):
            return nxt
        for f in flags:
            if f.startswith("--") and w.startswith(f + "="):
                return w.split("=", 1)[1]
        if w in file_flags or any(f.startswith("--") and w.startswith(f + "=") for f in file_flags):
            path = Path(cwd, w.split("=", 1)[1] if "=" in w else nxt)
            try:
                return path.read_text(encoding="utf-8", errors="replace") if path.stat().st_size < 100_000 else None
            except OSError:
                return None
    return None


def _client_args(words: list[str], value_flags: set[str], drop_flags: set[str], drop_letters: str,
                 attached: tuple[str, ...] = ()) -> list[str]:
    """Only the connection arguments of a database client command: where to connect and as whom.
    drop_letters: short flags whose value is SQL or a file, also when combined (`psql -tAc "..."`)."""
    out, i = [], 0
    while i < len(words):
        w = words[i]
        if w in value_flags:
            out += words[i:i + 2]; i += 2; continue
        if any(w.startswith(f + "=") for f in value_flags if f.startswith("--")) or \
                any(w.startswith(f) and len(w) > 2 for f in value_flags | set(attached) if len(f) == 2):
            out.append(w); i += 1; continue
        if w in drop_flags or re.fullmatch(rf"-[A-Za-z]*[{drop_letters}]", w):
            i += 2; continue
        if not w.startswith("-"):
            out.append(w)
        i += 1
    return out


def _label(conn: list[str]) -> str:
    """Which database, for the approver: host/dbname from a URL or -h/-d flags."""
    for w in conn:
        if m := re.match(r"^\w+://(?:[^@/]*@)?([^/:?]+)(?::\d+)?/([^?]+)", w):
            return f"{m.group(2)} on {m.group(1)}"
    host = next((conn[i + 1] for i, w in enumerate(conn[:-1]) if w in ("-h", "--host")), "")
    db = next((conn[i + 1] for i, w in enumerate(conn[:-1]) if w in ("-d", "--dbname", "-D", "--database")), "")
    return " on ".join(x for x in (db, host) if x)


def _sql(cmd: commands.Command, cwd: str, deadline: float) -> list[str]:
    words = [os.path.expandvars(w) for w in cmd.words[1:]]
    prog = cmd.program
    if prog == "sqlite3":
        pos = [w for w in words if not w.startswith("-")]
        if len(pos) < 2:
            return []
        db, sql = Path(cwd, pos[0]), pos[1]
        targets = sql_targets(sql)
        if not targets or not db.is_file():
            return []
        out = []
        import sqlite3   # here, not at the top: every hook call loads this file, few touch a SQLite database
        con = sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True, timeout=1)
        try:
            con.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10000)
            for verb, table, where in targets:
                counts = list(con.execute(_count_query(table, where)).fetchone())
                out.append(_rows_message(verb, table, where, counts, db.name))
        except sqlite3.Error:
            pass
        finally:
            con.close()
        return out
    if prog == "psql":
        sql = _sql_text(words, cwd, ("-c", "--command"), ("-f", "--file"))
        conn = _client_args(words, {"-h", "--host", "-p", "--port", "-U", "--username", "-d", "--dbname"},
                            {"-c", "--command", "-f", "--file", "-o", "--output", "-L", "--log-file", "-v", "--set",
                             "--variable", "-P", "--pset"}, "cf")
        options = (os.environ.get("PGOPTIONS", "") + " -c default_transaction_read_only=on -c statement_timeout=5000").strip()
        env = _env(cmd, {"PGOPTIONS": options, "PGCONNECT_TIMEOUT": "3"})
        run = lambda q: _run(["psql", *conn, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", q],
                             _left(deadline), env, cwd)
        split = "|"
    else:                                                       # mysql, mariadb
        sql = _sql_text(words, cwd, ("-e", "--execute"), ())
        conn = _client_args(words, {"-h", "--host", "-P", "--port", "-u", "--user", "-D", "--database", "-S", "--socket",
                                    "--password", "--defaults-file", "--defaults-extra-file"},
                            {"-e", "--execute"}, "e", attached=("-p",))   # -pSECRET only; a bare -p would prompt
        env = _env(cmd)
        # MAX_EXECUTION_TIME stops the count on the server too (MySQL); MariaDB reads the hint as a comment
        run = lambda q: _run([prog, *conn, "-N", "-B", "--connect-timeout=3", "-e", "SET SESSION TRANSACTION READ ONLY; "
                              + q.replace("SELECT ", "SELECT /*+ MAX_EXECUTION_TIME(5000) */ ", 1)], _left(deadline), env, cwd)
        split = "\t"
    targets = sql_targets(sql or "")
    if not targets:
        return []
    out = []
    for verb, table, where in targets:
        text, done = run(_count_query(table, where))
        line = next((l for l in (text or "").splitlines() if l.strip()), "") if done else ""
        try:
            counts = [int(x) for x in line.strip().split(split)]
        except ValueError:
            continue
        out.append(_rows_message(verb, table, where, counts, _label(conn)))
    return out


# --------------------------------------------------------------------------- terraform: what a plan would destroy

DATA_TYPES = re.compile(r"(db_instance|rds_cluster|docdb|neptune|redshift|dynamodb_table|elasticache|memorydb|"
                        r"opensearch|elasticsearch|s3_bucket$|storage_bucket$|storage_account$|ebs_volume|"
                        r"efs_file_system|fsx|backup_vault|sql_database|sql_server|database|bigquery_dataset|"
                        r"bigquery_table|bigtable|spanner|firestore|cosmosdb|compute_disk|managed_disk|kms_key|"
                        r"secretsmanager_secret|key_vault)", re.I)


def _tf_type(address: str) -> str:
    parts = re.sub(r"\[[^\]]*\]", "", address).split(".")
    return parts[-2] if len(parts) >= 2 else ""


def _holding_data(addresses: list[str]) -> list[str]:
    return [a for a in addresses if DATA_TYPES.search(_tf_type(a))]


def _tf_summary(verb: str, addresses: list[str], where: str) -> str:
    data = _holding_data(addresses)
    msg = f"{verb} {_plural(len(addresses), 'resource')}{where}"
    if data:
        return msg + f", including {len(data)} that hold{'s' if len(data) == 1 else ''} data: {_names(data)}"
    return msg + f": {_names(addresses)}"


def _terraform(cmd: commands.Command, cwd: str, deadline: float) -> str | None:
    words = [os.path.expandvars(w) for w in cmd.words]
    tf, chdir = words[0], [w for w in words[1:] if w.startswith("-chdir=")]
    rest = [w for w in words[1:] if not w.startswith("-chdir=")]
    sub = next((w for w in rest if not w.startswith("-")), None)
    if sub not in ("destroy", "apply"):
        return None
    args = rest[rest.index(sub) + 1:]
    plan_args, targets, positional, i = [], [], [], 0
    while i < len(args):
        a = args[i]
        if a in ("-var", "-var-file", "-target", "-replace") and i + 1 < len(args):
            plan_args += [f"{a}={args[i + 1]}"]; i += 2; continue
        if re.match(r"-(var|var-file|target|replace)=", a):
            plan_args.append(a)
        elif not a.startswith("-"):
            positional.append(a)
        i += 1
    targets = [a.split("=", 1)[1] for a in plan_args if a.startswith("-target=")]
    env = _env(cmd, {"TF_IN_AUTOMATION": "1", "TF_INPUT": "0"})
    ws, _ = _run([tf, *chdir, "workspace", "show"], min(3, _left(deadline)), env, cwd)
    ws = (ws or "").strip()
    where = f" in workspace {ws}" if ws and ws != "default" else ""

    if sub == "destroy" or "-destroy" in args:
        text, done = _run([tf, *chdir, "state", "list", *targets], _left(deadline), env, cwd)
        if text is None or not done:
            return None
        gone = [l.strip() for l in text.splitlines() if l.strip() and not re.match(r"(.*\.)?data\.", l.strip())]
        if not gone:
            return f"Destroys nothing{where}: the state has no matching resources"
        return _tf_summary("Destroys", gone, where)

    plan_file, tmp = (positional[0] if positional else None), None
    try:
        if not plan_file:                                       # plan against the saved state (no refresh, no lock)
            fd, tmp = tempfile.mkstemp(suffix=".tfplan")
            os.close(fd)
            _, done = _run([tf, *chdir, "plan", "-refresh=false", "-lock=false", "-input=false", "-no-color",
                            f"-out={tmp}", *plan_args], PLAN_SECONDS, env, cwd)
            if not done:
                return None
            plan_file = tmp
        text, done = _run([tf, *chdir, "show", "-json", plan_file], 10, env, cwd)
        if not text or not done:
            return None
        changes = json.loads(text).get("resource_changes") or []
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    acts = [(c.get("address", "?"), (c.get("change") or {}).get("actions") or []) for c in changes if c.get("mode") != "data"]
    gone = [a for a, x in acts if x == ["delete"]]
    replaced = [a for a, x in acts if "delete" in x and "create" in x]
    if not gone and not replaced:
        adds = sum(1 for _, x in acts if x == ["create"])
        updates = sum(1 for _, x in acts if x == ["update"])
        return f"Destroys nothing{where}: adds {adds:,} and changes {updates:,} resources (plan against the saved state)"
    parts = []
    if gone:
        parts.append(_tf_summary("Destroys", gone, where))
    if replaced:
        parts.append(_tf_summary("Replaces (destroys, then creates again)", replaced, "" if gone else where))
    return "; ".join(parts) + " (plan against the saved state)"


# --------------------------------------------------------------------------- AWS: what a delete takes with it

AWS_GLOBALS = ("--profile", "--region", "--endpoint-url")
AWS_SWITCHES = {"--recursive", "--force", "--dryrun", "--quiet", "--only-show-errors", "--skip-final-snapshot",
                "--delete-automated-backups", "--no-delete-automated-backups", "--debug", "--no-verify-ssl",
                "--no-paginate", "--no-sign-request", "--no-cli-pager"}


def _aws(cmd: commands.Command, cwd: str, deadline: float) -> str | None:
    words = [os.path.expandvars(w) for w in cmd.words[1:]]
    keep, pos, flags, i = [], [], {}, 0
    while i < len(words):
        w = words[i]
        if w in AWS_GLOBALS and i + 1 < len(words):
            keep += words[i:i + 2]; i += 2; continue
        if any(w.startswith(g + "=") for g in AWS_GLOBALS):
            keep.append(w); i += 1; continue
        if w.startswith("--"):
            name, _, value = w.partition("=")
            if name not in AWS_SWITCHES and not value and i + 1 < len(words) and not words[i + 1].startswith("-"):
                value = words[i + 1]; i += 1
            flags[name] = value
        else:
            pos.append(w)
        i += 1
    env = _env(cmd)
    if pos[:2] in (["s3", "rb"], ["s3", "rm"]) and len(pos) > 2 and pos[2].startswith("s3://"):
        if (pos[1] == "rb" and "--force" not in flags) or (pos[1] == "rm" and "--recursive" not in flags) \
                or "--dryrun" in flags:
            return None                                         # an empty bucket, one object, or a dry run
        text, done = _run(["aws", "s3", "ls", pos[2], "--recursive", "--summarize", *keep], _left(deadline), env, cwd)
        if text is None:
            return None
        if done and (m := re.search(r"Total Objects:\s*(\d+)\s*Total Size:\s*(\d+)", text)):
            files, size = int(m.group(1)), int(m.group(2))
            more = ""
        else:                                                   # still listing when time ran out: what it saw so far
            rows = [l.split(None, 3) for l in text.splitlines()]
            rows = [r for r in rows if len(r) == 4 and r[2].isdigit()]
            files, size, more = len(rows), sum(int(r[2]) for r in rows), "+"
        what = "the bucket and all" if pos[1] == "rb" else "all"
        return f"Deletes {what} {files:,}{more} object{'s' if files != 1 else ''} ({_size(size)}{more}) in {pos[2]}"
    if pos[:2] in (["rds", "delete-db-instance"], ["rds", "delete-db-cluster"]):
        cluster = pos[1] == "delete-db-cluster"
        name = flags.get("--db-cluster-identifier" if cluster else "--db-instance-identifier")
        if not name:
            return None
        parts = [f"Deletes RDS {'cluster' if cluster else 'database'} {name}"]
        text, done = _run(["aws", "rds", "describe-db-clusters" if cluster else "describe-db-instances",
                           "--db-cluster-identifier" if cluster else "--db-instance-identifier", name,
                           "--output", "json", *keep], _left(deadline), env, cwd)
        protected = False
        try:
            db = json.loads(text)["DBClusters" if cluster else "DBInstances"][0] if text and done else {}
            if db:
                size = f", {db['AllocatedStorage']} GB" if db.get("AllocatedStorage") else ""
                parts[0] += f" ({db.get('Engine', '?')}{size})"
                protected = bool(db.get("DeletionProtection"))
        except (ValueError, KeyError, IndexError, TypeError):
            pass
        if "--skip-final-snapshot" in flags:
            parts.append("no final snapshot is taken (--skip-final-snapshot)")
        elif flags.get("--final-db-snapshot-identifier"):
            parts.append(f"a final snapshot {flags['--final-db-snapshot-identifier']} is kept")
        if "--no-delete-automated-backups" not in flags:
            parts.append("its automated backups are removed with it (AWS's default)")
        if protected:
            parts.append("deletion protection is on, so AWS refuses until someone turns it off")
        return "; ".join(parts)
    return None


# --------------------------------------------------------------------------- Kubernetes: what a delete matches

KUBE_DELETE_ONLY = {"--grace-period", "--force", "--now", "--wait", "--cascade", "--ignore-not-found", "--timeout",
                    "--dry-run", "-i", "--interactive", "--all", "--raw"}
KUBE_VALUED = {"--grace-period", "--timeout", "--raw"}      # the others take a value only as --flag=value


def _kubectl(cmd: commands.Command, cwd: str, deadline: float) -> str | None:
    words = [os.path.expandvars(w) for w in cmd.words]
    rest = words[1:]
    at = next((i for i, w in enumerate(rest) if not w.startswith("-") and (i == 0 or not rest[i - 1] in
               ("-n", "--namespace", "--context", "--kubeconfig", "-l", "--selector", "-f", "--filename"))), None)
    if at is None or rest[at].lower() != "delete" or any(w.startswith("--dry-run") for w in rest):
        return None
    args, after, i = rest[:at] + ["get"], rest[at + 1:], 0
    while i < len(after):                                       # the same selection, without delete's own options
        w = after[i]
        if w.split("=", 1)[0] in KUBE_DELETE_ONLY:
            if "=" not in w and w in KUBE_VALUED and i + 1 < len(after) and not after[i + 1].startswith("-"):
                i += 1
        else:
            args.append(w)
        i += 1
    env = _env(cmd)
    text, done = _run([words[0], *args, "-o", "name", "--ignore-not-found"], _left(deadline), env, cwd)
    if text is None or not done:
        return None
    names = [l.strip() for l in text.splitlines() if l.strip()]
    if not names:
        return "Nothing matches it right now"
    get = lambda flag: next((rest[i + 1] for i, w in enumerate(rest[:-1]) if w == flag), None)
    ns = "all namespaces" if any(w in ("-A", "--all-namespaces") for w in rest) else \
        f"namespace {get('-n') or get('--namespace')}" if (get('-n') or get('--namespace')) else ""
    context = get("--context") or (_run([words[0], "config", "current-context"], min(2, _left(deadline)), env, cwd)[0] or "").strip()
    where = " in " + " on ".join(x for x in (ns, f"cluster {context}" if context else "") if x) if ns or context else ""
    inside = " and everything in them" if any(n.startswith("namespace/") for n in names) else ""
    return f"Deletes {_plural(len(names), 'Kubernetes object')}{where}{inside}: {_names(names)}"


# --------------------------------------------------------------------------- entry point

def predict(line: str, cwd: str | None = None) -> list[str]:
    """Plain-English lines saying what the command line would change. Empty when there's nothing to measure."""
    cwd = cwd or os.getcwd()
    start = time.monotonic()
    deadline, remote = start + BUDGET_SECONDS, start + REMOTE_SECONDS
    out: list[str] = []
    try:
        reading = commands.read(line)
    except Exception:
        return out
    for cmd in reading.commands:
        w = [x for x in cmd.words]
        local = cmd.program not in SQL_PROGRAMS | {"terraform", "tofu", "aws", "kubectl", "oc"}
        if time.monotonic() > (deadline if local else remote):
            continue
        try:
            if cmd.program == "git" and len(w) > 1:
                fn = {"push": _push, "reset": _reset, "clean": _clean, "checkout": _checkout, "restore": _checkout}.get(w[1])
                msg = fn(w, cwd) if fn else None
            elif cmd.program in SQL_PROGRAMS:
                msg = _sql(cmd, cwd, remote)
            elif cmd.program in ("terraform", "tofu"):
                msg = _terraform(cmd, cwd, remote)
            elif cmd.program == "aws":
                msg = _aws(cmd, cwd, remote)
            elif cmd.program in ("kubectl", "oc"):
                msg = _kubectl(cmd, cwd, remote)
            else:
                msg = _delete(cmd, cwd, deadline)
        except Exception:
            msg = None
        for m in ([msg] if isinstance(msg, str) else msg or []):
            if m and m[:400] not in out:
                out.append(m[:400])
    return out[:5]

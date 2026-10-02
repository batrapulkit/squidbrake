"""
Read a shell command the way a careful person would, before it runs.

An agent's shell command is one tool call that can hide many actions: `ls && rm -rf ~/`, `bash -c "..."`,
`curl ... | sh`. Matching the whole string with a regex misses those (that is how a denylist gets bypassed),
so this splits the line into its commands (quote-aware), steps into `bash -c` / `sudo` / `xargs` / `$(...)`,
and sorts each command into one of:

  catastrophic  wipes a disk, the whole filesystem or a home folder: rm -rf /, rm -rf ~, mkfs, dd onto a disk
  irreversible  destroys or publishes something that can't simply be undone: rm -r, git push --force,
                git reset --hard, terraform destroy, kubectl delete, cloud deletes, DROP TABLE, docker volume rm
  hidden        runs code that can't be read here: eval, curl | sh, base64 -d | bash, powershell -EncodedCommand
  read_only     only looks: ls, cat, grep, git status / log / diff
  other         anything else

It never runs, expands or evaluates anything. Unknown programs are "other", never "read_only".
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

SEVERITY = ("read_only", "other", "hidden", "irreversible", "catastrophic")  # least to most serious


@dataclass
class Command:
    program: str                 # e.g. "rm", "git", "remove-item"
    words: list[str]             # the command's own words, program first
    kind: str = "other"          # see SEVERITY
    why: str = ""                # plain-English reason, shown to the approver
    raw: str = ""


@dataclass
class Reading:
    """What a whole command line does."""
    commands: list[Command] = field(default_factory=list)
    hidden: list[str] = field(default_factory=list)      # reasons some of it can't be read
    writes_files: bool = False                           # output redirected into a file

    @property
    def kind(self) -> str:
        kinds = [c.kind for c in self.commands] + (["hidden"] if self.hidden else [])
        if not kinds:
            return "other"
        worst = max(kinds, key=SEVERITY.index)
        if worst == "read_only" and self.writes_files:
            return "other"
        return worst

    def worst(self) -> Command | None:
        return max(self.commands, key=lambda c: SEVERITY.index(c.kind), default=None)

    def summary(self) -> str:
        kind = self.kind
        if kind == "hidden" and self.hidden:
            return self.hidden[0]
        cmd = self.worst()
        return cmd.why if cmd and cmd.why else ""


# --------------------------------------------------------------------------- splitting

_OPERATORS = ("&&", "||", ";", "|", "&", "\n")


def _split_top(line: str) -> tuple[list[str], list[str]]:
    """Split on && || ; | & and newlines outside quotes. -> (commands, substitutions found inside $(...) / ``)."""
    parts, subs, buf = [], [], []
    quote: str | None = None
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(line[i:i + 2]); i += 2; continue
            if quote == '"' and line.startswith("$(", i):
                end = _match_paren(line, i + 1)
                subs.append(line[i + 2:end]); buf.append(line[i:end + 1]); i = end + 1; continue
            if quote == '"' and ch == "`":
                end = line.find("`", i + 1); end = n if end < 0 else end
                subs.append(line[i + 1:end]); buf.append(line[i:end + 1]); i = end + 1; continue
            if ch == quote:
                quote = None
            buf.append(ch); i += 1; continue
        if ch in "'\"":
            quote = ch; buf.append(ch); i += 1; continue
        if ch == "\\" and i + 1 < n:
            buf.append(line[i:i + 2]); i += 2; continue
        if line.startswith("$(", i) and not line.startswith("$((", i):
            end = _match_paren(line, i + 1)
            subs.append(line[i + 2:end]); buf.append(line[i:end + 1]); i = end + 1; continue
        if line.startswith("<(", i) or line.startswith(">(", i):
            end = _match_paren(line, i + 1)
            subs.append(line[i + 2:end]); buf.append(line[i:end + 1]); i = end + 1; continue
        if ch == "`":
            end = line.find("`", i + 1); end = n if end < 0 else end
            subs.append(line[i + 1:end]); buf.append(line[i:end + 1]); i = end + 1; continue
        op = next((o for o in _OPERATORS if line.startswith(o, i)), None)
        # `2>&1` and `&>` are redirections, not the background operator
        if op == "&" and (line[i - 1:i] in (">", "<") or line.startswith("&>", i)):
            op = None
        if op:
            parts.append("".join(buf)); buf = []; i += len(op); continue
        buf.append(ch); i += 1
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()], subs


def _match_paren(s: str, open_at: int) -> int:
    depth, i, quote = 0, open_at, None
    while i < len(s):
        ch = s[i]
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(s)


_REDIRECT_OUT = re.compile(r"(?<![0-9&<])(?:[0-9]?>>?|&>)\s*(?!&)([^\s;|&]+)")
_HARMLESS_TARGETS = {"/dev/null", "nul", "$null", "/dev/stdout", "/dev/stderr"}


def _words(cmd: str) -> list[str]:
    # Non-POSIX so Windows paths keep their backslashes (C:\Users, d:\); outer quotes are stripped below.
    try:
        words = shlex.split(cmd, posix=False)
    except ValueError:
        words = cmd.split()
    return [_unquote(w) for w in words if w]


def _unquote(word: str) -> str:
    if len(word) >= 2 and word[0] == word[-1] and word[0] in "'\"":
        return word[1:-1]
    return word


# --------------------------------------------------------------------------- classification

WRAPPERS = {"sudo", "doas", "env", "time", "nohup", "nice", "ionice", "command", "exec", "builtin", "timeout",
            "stdbuf", "caffeinate", "npx", "call", "watch", "busybox"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
POWERSHELLS = {"powershell", "pwsh"}

READ_ONLY = {
    "ls", "dir", "cat", "type", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "ag", "ack",
    "find", "fd", "tree", "pwd", "cd", "echo", "printf", "wc", "sort", "diff", "cmp", "file", "stat", "du", "df",
    "which", "where", "whereis", "whoami", "id", "uname", "hostname", "date", "realpath", "basename", "dirname",
    "test", "true", "false", "sleep", "jq", "yq", "nl", "column", "od", "hexdump", "xxd", "md5sum", "sha256sum",
    "shasum", "cut", "tr", "comm", "join", "paste", "fold", "rev", "tac", "zcat", "lsof", "ps", "top", "free",
    "uptime", "get-childitem", "gci", "get-content", "gc", "select-string", "sls", "get-location", "gl",
    "test-path", "get-item", "gi", "resolve-path", "get-command", "gcm", "measure-object", "select-object",
    "where-object", "format-table", "format-list", "out-string", "get-date", "write-output", "write-host",
    "get-process", "gps", "sort-object", "get-filehash",
}
# Options that make an otherwise read-only program write, run code, or delete.
UNSAFE_OPTIONS = {
    "find": ("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"),
    "fd": ("-x", "--exec", "-X", "--exec-batch"),
    "rg": ("--pre",),
    "sort": ("-o", "--output"),
    "tree": ("-o",),
    "jq": (),
}
GIT_READ_ONLY = {"status", "log", "diff", "show", "blame", "rev-parse", "ls-files", "ls-tree", "describe",
                 "shortlog", "grep", "cat-file", "reflog", "whatchanged", "count-objects", "check-ignore",
                 "merge-base", "name-rev", "for-each-ref", "var", "help", "version"}
PS_REMOVE = {"remove-item", "ri", "rm", "del", "erase", "rmdir", "rd"}
CLOUD = {"aws", "gcloud", "gsutil", "az", "doctl", "flyctl", "fly", "heroku", "vercel", "netlify", "railway",
         "supabase", "firebase", "wrangler", "oci", "linode-cli", "hcloud"}
DESTRUCTIVE_WORDS = re.compile(r"^(delete|destroy|terminate|remove|rm|rb|purge|deregister|drop|wipe|erase|"
                               r"uninstall|disable-backup|delete-.*|.*-delete|remove-.*|terminate-.*)$", re.I)
SQL_DESTRUCTIVE = re.compile(r"\b(drop\s+(table|database|schema|index)|truncate\b|delete\s+from\s+\w+\s*(;|$)|"
                             r"dropdatabase\s*\(|\.drop\s*\(|flushall|flushdb)", re.I)
HTTP_CLIS = {"curl", "wget", "http", "https", "xh", "httpie", "invoke-webrequest", "iwr", "invoke-restmethod", "irm"}
API_DELETE = re.compile(r"\bmutation\b[^{]*\{\s*\w*(delete|destroy|remove|drop|purge|wipe)\w*\s*\(|"
                        r"\"(action|op|operation)\"\s*:\s*\"(delete|destroy|remove|drop)\w*\"", re.I)
SQL_CLIS = {"psql", "mysql", "mariadb", "sqlite3", "mongosh", "mongo", "redis-cli", "sqlcmd", "clickhouse-client",
            "cockroach", "duckdb"}

# Paths that hold secrets: reading them is never "only looking" (it's how keys get stolen and sent out).
SECRET_PATH = re.compile(r"(^|[\\/~.])(\.env(\.[\w-]+)?|\.ssh|id_rsa|id_ed25519|id_ecdsa|\.pem|\.p12|\.pfx|\.key|"
                         r"\.aws|\.azure|\.gcloud|\.config[\\/]gcloud|\.kube|\.docker[\\/]config\.json|\.netrc|"
                         r"\.npmrc|\.pypirc|\.git-credentials|credentials|secrets?|\.vault-token|token|shadow|"
                         r"keychain|\.gnupg|wallet)([\\/.\s]|$)", re.I)
SECRET_EXT = re.compile(r"\.(pem|p12|pfx|key|keystore|jks|kdbx|ppk)$", re.I)

_ROOTS = re.compile(r"^(/+\*?|/\.\*?|~/?\*?|\$\{?home\}?/?\*?|\$env:userprofile\\?\*?|%userprofile%\\?|"
                    r"[a-z]:[\\/]?\*?|[a-z]:[\\/]\.\*?|\\\\?\*?)$", re.I)
_SYSTEM_DIRS = re.compile(r"^(/(bin|boot|dev|etc|lib|lib64|opt|proc|root|sbin|srv|sys|usr|var|home|users|"
                          r"system|library|applications|private)|[a-z]:[\\/](windows|program files[^\\/]*|users|"
                          r"programdata))[\\/]?\*?$", re.I)


def _is_catastrophic_target(path: str) -> bool:
    p = path.strip().strip("\"'").rstrip()
    return bool(_ROOTS.match(p) or _SYSTEM_DIRS.match(p))


def _flags(words: list[str]) -> set[str]:
    return {w for w in words[1:] if w.startswith("-") and w != "-"}


def _short_letters(words: list[str]) -> set[str]:
    return {ch for w in words[1:] if re.match(r"^-[A-Za-z]{1,4}$", w) for ch in w[1:]}


def _positional(words: list[str]) -> list[str]:
    return [w for w in words[1:] if not w.startswith("-")]


def _strip_wrappers(words: list[str]) -> list[str]:
    while words:
        w = words[0].lower()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]):          # FOO=bar cmd
            words = words[1:]; continue
        if w in WRAPPERS:
            words = words[1:]
            while words and (words[0].startswith("-") or (w in ("timeout", "watch") and re.match(r"^\d", words[0]))
                             or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0])):
                words = words[1:]
            if w == "watch" and len(words) == 1 and " " in words[0]:   # watch "rm -rf ~": it runs the string via sh -c
                words = _words(words[0])
            continue
        break
    return words


def _program(word: str) -> str:
    p = word.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return p[:-4] if p.endswith(".exe") else p


def classify(words: list[str], raw: str = "", depth: int = 0) -> tuple[list[Command], list[str]]:
    """One simple command (already split into words). -> (commands, hidden-reasons)."""
    words = _strip_wrappers(words)
    if not words:
        return [], []
    prog = _program(words[0])
    lower = [w.lower() for w in words]
    cmd = Command(program=prog, words=words, raw=raw)

    # ---- shells running a string: read the string
    # -c, also combined with other short flags: `bash -lc "..."` (Codex runs every command this way), `sh -ec`, `bash -c -l`
    c_at = next((i for i, w in enumerate(words[1:], 1) if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", w)), None)
    if prog in SHELLS and c_at is not None:
        inner = next((w for w in words[c_at + 1:] if not w.startswith("-")), "")
        return _read(inner, depth + 1) if depth < 4 else ([], ["a command nested too deep to read"])
    if prog in POWERSHELLS:
        if any(w.startswith("-e") and "enc" in w or w in ("-e", "-ec") for w in lower[1:]):
            return [], ["runs a base64-encoded PowerShell script (-EncodedCommand), which can't be read before it runs"]
        for flag in ("-command", "-c"):
            if flag in lower[1:]:
                i = lower.index(flag) + 1
                inner = " ".join(words[i:])
                return _read(inner, depth + 1) if depth < 4 else ([], ["a command nested too deep to read"])
    if prog in ("cmd",) and any(w in ("/c", "/k") for w in lower[1:]):
        i = next(i for i, w in enumerate(lower) if w in ("/c", "/k")) + 1
        return _read(" ".join(words[i:]), depth + 1) if depth < 4 else ([], ["a command nested too deep to read"])
    if prog == "xargs":
        rest = words[1:]
        while rest and rest[0].startswith("-"):
            rest = rest[2:] if rest[0] in ("-I", "-n", "-P", "-L", "-d", "-E", "-s") else rest[1:]
        return classify(rest, raw, depth) if rest else ([cmd], [])

    # ---- code that can't be read
    if prog in ("eval", "iex", "invoke-expression"):
        return [], [f"runs code built at run time ({prog}), which can't be read before it runs"]

    # ---- catastrophic
    if prog == "diskutil" and lower[1:2] in (["erasedisk"], ["erasevolume"], ["secureerase"]):
        cmd.kind, cmd.why = "catastrophic", f"erases a disk or volume ({' '.join(words[:3])})"
        return [cmd], []
    if prog == "tmutil" and lower[1:2] == ["delete"]:
        cmd.kind, cmd.why = "irreversible", f"deletes Time Machine backups ({' '.join(words[:3])})"
        return [cmd], []
    if prog.startswith("mkfs") or prog in ("wipefs", "diskpart", "format", "fdisk", "sfdisk", "parted", "gdisk"):
        if prog != "format" or any(re.match(r"^[a-z]:$", w, re.I) for w in lower[1:]):
            cmd.kind, cmd.why = "catastrophic", f"formats or repartitions a disk ({' '.join(words[:3])})"
            return [cmd], []
    if prog == "dd" and any(w.startswith("of=/dev/") for w in lower[1:]):
        cmd.kind, cmd.why = "catastrophic", f"writes raw data onto a disk device ({next(w for w in words if w.lower().startswith('of='))})"
        return [cmd], []
    if prog in ("chmod", "chown", "chgrp") and ("-r" in {f.lower() for f in _flags(words)} or "--recursive" in lower) \
            and any(_is_catastrophic_target(p) for p in _positional(words)):
        cmd.kind, cmd.why = "catastrophic", f"changes permissions on the whole system ({' '.join(words)})"
        return [cmd], []

    # ---- deleting files
    if prog in ("rm", "unlink", "shred", "srm") or prog in PS_REMOVE:
        return [_deletion(cmd, words, prog)], []
    if prog in ("rimraf", "del-cli"):
        return [_deletion(cmd, [words[0], "-r", *words[1:]], prog)], []
    if prog == "find" and ("-delete" in lower or any(w in ("-exec", "-execdir", "-ok", "-okdir") for w in lower)):
        if "-delete" in lower:
            cmd.kind, cmd.why = "irreversible", f"deletes every file it finds ({' '.join(words)})"
            return [cmd], []
        i = next(i for i, w in enumerate(lower) if w in ("-exec", "-execdir", "-ok", "-okdir")) + 1
        inner = [w for w in words[i:] if w not in (";", "\\;", "+", "{}")]
        found, hidden = classify(inner, raw, depth + 1) if inner else ([], [])
        kind = max((c.kind for c in found), key=SEVERITY.index, default="other")
        cmd.kind = "other" if kind == "read_only" else kind
        cmd.why = next((c.why for c in found if c.why), "")
        return [cmd], hidden

    # ---- git
    if prog == "git":
        return [_git(cmd, words)], []

    # ---- infrastructure and cloud
    if prog in ("terraform", "tofu", "terragrunt"):
        sub = [w for w in lower[1:] if not w.startswith("-")][:2]
        if sub[:1] == ["destroy"] or "-destroy" in lower or sub == ["state", "rm"] or sub == ["workspace", "delete"]:
            cmd.kind, cmd.why = "irreversible", f"destroys infrastructure ({' '.join(words[:4])})"
        elif sub[:1] == ["apply"] and ("-auto-approve" in lower or "--auto-approve" in lower):
            cmd.kind, cmd.why = "irreversible", "applies infrastructure changes without a plan review (-auto-approve)"
        return [cmd], []
    if prog == "pulumi" and any(w in ("destroy", "rm") for w in lower[1:3]):
        cmd.kind, cmd.why = "irreversible", f"destroys infrastructure ({' '.join(words[:3])})"
        return [cmd], []
    if prog in ("kubectl", "oc", "k"):
        sub = [w for w in lower[1:] if not w.startswith("-")][:3]      # may include a flag's value (-n prod)
        if any(w in ("delete", "drain") for w in sub) or ("scale" in sub and "--replicas=0" in lower):
            cmd.kind, cmd.why = "irreversible", f"deletes or drains Kubernetes resources ({' '.join(words[:4])})"
        return [cmd], []
    if prog == "helm" and any(w in ("uninstall", "delete", "del", "un") for w in lower[1:2]):
        cmd.kind, cmd.why = "irreversible", f"uninstalls a Helm release ({' '.join(words[:3])})"
        return [cmd], []
    if prog in CLOUD:
        verbs = []
        for w in lower[1:]:
            if w.startswith("-") or len(verbs) == 4:
                break
            verbs.append(w)
        if any(DESTRUCTIVE_WORDS.match(v) for v in verbs) or (prog == "aws" and verbs[:2] == ["s3", "rm"]):
            cmd.kind, cmd.why = "irreversible", f"deletes cloud resources ({' '.join(words[:4])})"
        return [cmd], []
    if prog in ("docker", "podman", "nerdctl"):
        sub = [w for w in lower[1:] if not w.startswith("-")][:2]
        if sub in (["system", "prune"], ["volume", "rm"], ["volume", "prune"], ["image", "prune"]) \
                or (sub[:1] == ["compose"] and "down" in lower and ("-v" in lower or "--volumes" in lower)) \
                or (sub[:1] == ["rm"] and ("-v" in lower or "--volumes" in lower)):
            cmd.kind, cmd.why = "irreversible", f"deletes containers' data ({' '.join(words[:4])})"
        return [cmd], []

    # ---- API calls that delete (curl -X DELETE, GraphQL mutations like volumeDelete / deleteRepository)
    if prog in HTTP_CLIS:
        text = " ".join(words[1:])
        method = next((words[i + 1].upper() for i, w in enumerate(words[:-1]) if w in ("-X", "--request", "-Method")), "")
        method = method or next((w[2:].upper() for w in words[1:] if re.match(r"^-X[A-Za-z]+$", w)), "")
        if method == "DELETE" or API_DELETE.search(text):
            cmd.kind, cmd.why = "irreversible", f"sends an API request that deletes something ({' '.join(words[:3])[:80]})"
        return [cmd], []

    # ---- databases
    if prog in SQL_CLIS:
        text = " ".join(words[1:])
        if SQL_DESTRUCTIVE.search(text):
            cmd.kind, cmd.why = "irreversible", f"runs destructive SQL ({SQL_DESTRUCTIVE.search(text).group(0)})"
        return [cmd], []

    # ---- publishing and machine state
    if (prog in ("npm", "pnpm", "yarn") and "publish" in lower[1:3]) or (prog == "cargo" and "publish" in lower[1:2]) \
            or (prog == "twine" and "upload" in lower[1:2]) or (prog == "gh" and lower[1:3] in (["repo", "delete"],
                                                                                              ["release", "delete"])):
        cmd.kind, cmd.why = "irreversible", f"publishes or deletes something public ({' '.join(words[:3])})"
        return [cmd], []
    if prog in ("shutdown", "reboot", "halt", "poweroff", "stop-computer", "restart-computer") \
            or (prog == "init" and lower[1:2] in (["0"], ["6"])):
        cmd.kind, cmd.why = "irreversible", f"shuts down or restarts the machine ({' '.join(words[:2])})"
        return [cmd], []
    if prog == "crontab" and "-r" in lower:
        cmd.kind, cmd.why = "irreversible", "deletes every scheduled job (crontab -r)"
        return [cmd], []
    if prog == "truncate" or (prog == "mv" and any(w in ("/dev/null", "nul") for w in lower[1:])):
        cmd.kind, cmd.why = "irreversible", f"empties or discards files ({' '.join(words[:3])})"
        return [cmd], []

    # ---- only looks
    if prog in READ_ONLY:
        bad = UNSAFE_OPTIONS.get(prog, ())
        if any(SECRET_PATH.search(w) or SECRET_EXT.search(w) for w in words[1:] if not w.startswith("-")):
            cmd.why = f"reads a file that may hold secrets ({' '.join(words[:4])})"   # "other": a person decides
        elif not any(w == b or w.startswith(b + "=") for w in words[1:] for b in bad):
            cmd.kind = "read_only"
    return [cmd], []


def _deletion(cmd: Command, words: list[str], prog: str) -> Command:
    lower = [w.lower() for w in words]
    letters = _short_letters(words)
    targets = [w for w in _positional(words) if not re.match(r"^/[a-z]$", w, re.I)]   # cmd.exe switches like /s /q
    recursive = ("r" in letters or "R" in letters or "--recursive" in lower
                 or "/s" in lower[1:]                                  # rmdir /s, del /s
                 or any(w.startswith("-rec") for w in lower[1:]))      # PowerShell -Recurse
    if "--no-preserve-root" in lower or any(_is_catastrophic_target(t) for t in targets) and recursive:
        where = next((t for t in targets if _is_catastrophic_target(t)), "/")
        label = "your home folder" if where.startswith(("~", "$")) or "userprofile" in where.lower() \
            else "a whole drive" if re.match(r"^[a-z]:[\\/]?\*?$", where, re.I) else "the whole filesystem" if where.startswith("/") and len(where.rstrip("/*")) == 0 \
            else f"the system folder {where}"
        cmd.kind, cmd.why = "catastrophic", f"deletes {label} ({' '.join(words)})"
    elif recursive:
        cmd.kind, cmd.why = "irreversible", f"deletes folders and everything in them ({' '.join(words)})"
    else:
        cmd.kind, cmd.why = "irreversible", f"deletes files ({' '.join(words)})"
    return cmd


def _git(cmd: Command, words: list[str]) -> Command:
    rest = words[1:]
    while rest and rest[0].startswith("-"):                    # git -C dir / -c k=v / --no-pager ...
        rest = rest[2:] if rest[0] in ("-C", "-c", "--git-dir", "--work-tree") else rest[1:]
    if not rest:
        cmd.kind = "read_only"
        return cmd
    sub, args = rest[0].lower(), [w.lower() for w in rest[1:]]
    letters = {ch for w in rest[1:] if re.match(r"^-[A-Za-z]+$", w) for ch in w[1:]}
    if sub == "push" and ("--force" in args or "--force-with-lease" in args or "f" in letters
                          or "--delete" in args or "--mirror" in args
                          or any(a.startswith("+") or (a.startswith(":") and len(a) > 1) for a in args)):
        cmd.kind, cmd.why = "irreversible", f"rewrites or deletes history on the remote ({' '.join(words)})"
    elif sub == "reset" and "--hard" in args:
        cmd.kind, cmd.why = "irreversible", "throws away uncommitted work (git reset --hard)"
    elif sub == "clean" and ("f" in letters or "--force" in args):
        cmd.kind, cmd.why = "irreversible", f"deletes untracked files ({' '.join(words)})"
    elif sub == "branch" and ("D" in letters or ("d" in letters and "f" in letters) or "--delete" in args and "--force" in args):
        cmd.kind, cmd.why = "irreversible", f"force-deletes a branch ({' '.join(words)})"
    elif sub in ("checkout", "restore") and ("." in args or "--" in args and args[-1:] == ["."]):
        cmd.kind, cmd.why = "irreversible", f"throws away uncommitted changes ({' '.join(words)})"
    elif sub == "stash" and args[:1] in (["drop"], ["clear"]):
        cmd.kind, cmd.why = "irreversible", f"deletes stashed work ({' '.join(words)})"
    elif sub in ("filter-branch", "filter-repo") or (sub == "update-ref" and "-d" in args):
        cmd.kind, cmd.why = "irreversible", f"rewrites repository history ({' '.join(words[:3])})"
    elif sub == "reflog" and args[:1] in (["expire"], ["delete"]):
        cmd.kind, cmd.why = "irreversible", f"deletes the record used to recover lost commits ({' '.join(words[:3])})"
    elif sub in GIT_READ_ONLY and not any(a.startswith("--output") for a in args):
        cmd.kind = "read_only"
    elif sub == "branch" and all(a.startswith("-") for a in args) and not letters & {"d", "D", "m", "M", "c", "C"}:
        cmd.kind = "read_only"
    elif sub == "remote" and (not args or args in (["-v"], ["--verbose"]) or args[:1] in (["get-url"], ["show"])):
        cmd.kind = "read_only"
    elif sub == "stash" and args[:1] in (["list"], ["show"]):
        cmd.kind = "read_only"
    elif sub == "config" and any(a in ("--get", "--list", "-l", "--get-all") for a in args):
        cmd.kind = "read_only"
    elif sub == "tag" and (not args or args[:1] in (["-l"], ["--list"])):
        cmd.kind = "read_only"
    return cmd


_PIPE_TO_SHELL = re.compile(r"\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\|\s*(sudo\s+)?(python[0-9.]*|perl|ruby|node|php)\b(?!\s+-m\s)"
                            r"|\|\s*(iex|invoke-expression)\b", re.I)


def _read(line: str, depth: int = 0) -> tuple[list[Command], list[str]]:
    commands, hidden = [], []
    if _PIPE_TO_SHELL.search(line) and re.search(r"\b(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod|"
                                                 r"base64|certutil|xxd\s+-r)\b", line, re.I):
        hidden.append("downloads or decodes code and runs it straight away, so it can't be read before it runs")
    parts, subs = _split_top(line)
    for sub in subs:
        c, h = _read(sub, depth + 1) if depth < 4 else ([], ["a command nested too deep to read"])
        commands += c; hidden += h
    for part in parts:
        c, h = classify(_words(part), raw=part, depth=depth)
        commands += c; hidden += h
    return commands, hidden


def read(line: str) -> Reading:
    """What a command line does. Never runs anything."""
    commands, hidden = _read(line or "")
    writes = any(t.lower() not in _HARMLESS_TARGETS for t in _REDIRECT_OUT.findall(_unquoted(line or "")))
    return Reading(commands=commands, hidden=list(dict.fromkeys(hidden)), writes_files=writes)


def _unquoted(line: str) -> str:
    """The line with quoted text blanked out, so `echo "a > b"` isn't read as a redirection."""
    return re.sub(r"'[^']*'|\"(?:\\.|[^\"\\])*\"", "''", line)


def command_of(input: object) -> str | None:
    """The command string in a shell tool's input: {"command": "..."}, {"cmd": ...}, {"command": "rm", "args": [...]}."""
    if isinstance(input, str):
        return input
    if not isinstance(input, dict):
        return None
    for key in ("command", "cmd", "script", "commandLine", "command_line"):
        value = input.get(key)
        if isinstance(value, str) and value.strip():
            args = input.get("args") or input.get("arguments")
            if isinstance(args, list) and args:
                return value + " " + " ".join(shlex.quote(str(a)) for a in args)
            return value
        if isinstance(value, list) and value:
            return " ".join(shlex.quote(str(a)) for a in value)
    return None

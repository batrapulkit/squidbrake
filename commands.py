"""
Read a shell command the way a careful person would, before it runs.

An agent's shell command is one tool call that can hide many actions: `ls && rm -rf ~/`, `bash -c "..."`,
`curl ... | sh`. Matching the whole string with a regex misses those (that is how a denylist gets bypassed),
so this splits the line into its commands (quote-aware), steps into `bash -c` / `sudo` / `xargs` / `$(...)`,
and sorts each command into one of:

  catastrophic  wipes a disk, the whole filesystem or a home folder: rm -rf /, rm -rf ~, mkfs, dd onto a disk
  irreversible  destroys or publishes something that can't simply be undone: every delete (rm, git rm, docker rm,
                DELETE FROM, even rm -rf node_modules), git push --force, git reset --hard, terraform destroy,
                kubectl delete, cloud deletes, DROP TABLE
  hidden        runs code that can't be read here: eval, curl | sh, base64 -d | bash, powershell -EncodedCommand
  rename        renames or moves something: mv, git mv, Rename-Item, git branch -m, aws s3 mv, ALTER TABLE ... RENAME
  secret        shows a secret to the agent: cat id_rsa / key.pem / ~/.kube/config, gh auth token, a keychain password
  read_only     only looks: ls, cat, grep, git status / log / diff
  other         anything else

It never runs, expands or evaluates anything. Unknown programs are "other", never "read_only".
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

SEVERITY = ("read_only", "other", "rename", "secret", "hidden", "irreversible", "catastrophic")  # least to most serious


@dataclass
class Command:
    program: str                 # e.g. "rm", "git", "remove-item"
    words: list[str]             # the command's own words, program first
    kind: str = "other"          # see SEVERITY
    why: str = ""                # plain-English reason, shown to the approver
    raw: str = ""
    rebuildable: bool = False    # a delete of build output, caches or temp files only (the terminal guard lets it run)


@dataclass
class Reading:
    """What a whole command line does."""
    commands: list[Command] = field(default_factory=list)
    hidden: list[str] = field(default_factory=list)      # reasons some of it can't be read
    writes_files: bool = False                           # output redirected into a file

    @property
    def unknown(self) -> list[str]:
        """Programs this reading doesn't know (not a shell built-in, a common developer tool, or one it classifies):
        what they do is up to them. Recorded, so a team can see what would wait if unknown programs had to."""
        return list(dict.fromkeys(c.program for c in self.commands
                                  if c.kind == "other" and c.program not in KNOWN and not _looks_like_path(c.program)))

    @property
    def scripts(self) -> list[str]:
        """Script files this line runs (python x.py, node x.js, bash x.sh, ./x, pwsh -File x.ps1)."""
        return list(dict.fromkeys(p for c in self.commands if (p := _script_of(c.words))))

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
            "stdbuf", "caffeinate", "npx", "bunx", "call", "watch", "busybox"}
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
# Global options that take a value, given before the verbs (an unknown one just adds a word to the verbs read)
CLOUD_VALUE_OPTIONS = {"--profile", "--region", "--project", "--output", "-o", "--endpoint-url", "--subscription",
                       "--account", "--configuration", "--zone", "--app", "-a", "--remote", "-r", "--org", "--team",
                       "--context", "--config", "--format", "--query", "--color", "--verbosity", "--resource-group",
                       "-g", "--impersonate-service-account", "--billing-project", "--env", "-e", "--cwd", "--scope"}
DESTRUCTIVE_WORDS = re.compile(r"^(delete|destroy|terminate|remove|rm|rb|purge|deregister|drop|wipe|erase|"
                               r"uninstall|disable-backup|delete-.*|.*-delete|remove-.*|terminate-.*|"
                               r".*:(destroy|delete|remove|reset|wipe|purge|rm))$", re.I)   # heroku pg:reset, apps:destroy
SQL_DESTRUCTIVE = re.compile(r"\b(drop\s+(table|database|schema|index|view|column)|truncate\b|delete\s+from\b|"
                             r"update\s+[\w.\"`]+\s+set\b(?:(?!\bwhere\b)[^;])*(;|$)|"   # UPDATE with no WHERE: every row
                             r"dropdatabase\s*\(|\.drop\s*\(|flushall|flushdb)", re.I)
SQL_RENAME = re.compile(r"\b(alter\s+(table|database|schema|view|index)\s+[\w.\"`]+\s+rename\b|rename\s+(table|database)\b|"
                        r"\.renameCollection\s*\(|\brename\b\s+\S+\s+\S+\s*$)", re.I)
REDIS_DELETE = {"del", "unlink", "hdel", "srem", "zrem", "lrem", "xdel", "getdel"}
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
# Not a secret, though the name says so: a template (.env.example), or code and docs about secrets (secrets.py, token.ts)
NOT_SECRET = re.compile(r"(example|sample|template|dist)$|\.(py|js|mjs|cjs|ts|tsx|jsx|go|rb|rs|java|kt|cs|php|swift|"
                        r"c|h|cc|cpp|md|mdx|txt|rst|html|css|scss|sh|ps1|sql|ya?ml\.j2)$", re.I)
# Programs that print what's in a file (ls, stat or find only say it's there)
CONTENT_READERS = {"cat", "type", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "ag", "ack", "nl",
                   "od", "hexdump", "xxd", "zcat", "tac", "cut", "sort", "jq", "yq", "diff", "cmp", "column", "paste",
                   "get-content", "gc", "select-string", "sls"}
PATTERN_FIRST = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "select-string", "sls"}


def _secret_files(prog: str, words: list[str]) -> list[str]:
    """Files holding secrets that this read-only command would print."""
    if prog not in CONTENT_READERS:
        return []
    args = _positional(words)
    if prog in PATTERN_FIRST and not any(w in ("-e", "-f", "--regexp", "--file", "-pattern") for w in words[1:]):
        args = args[1:]                                      # grep PATTERN FILE...: the pattern isn't a file
    return [w for w in args if (SECRET_PATH.search(w) or SECRET_EXT.search(w)) and not NOT_SECRET.search(w.rstrip("/"))]


def _prints_secret(prog: str, lower: list[str]) -> str | None:
    """CLIs that print a password or a token: the agent (and whoever reads its transcript) then has it."""
    sub = [w for w in lower[1:] if not w.startswith("-")]
    if prog == "security" and (sub[:1] == ["dump-keychain"] or (
            sub[:1] in (["find-generic-password"], ["find-internet-password"]) and any(re.match(r"^-[a-z]*[wg]", w) for w in lower))):
        return f"prints a password from the keychain ({' '.join(lower[:2])})"
    if prog == "gh" and sub[:2] == ["auth", "token"] or (prog == "gh" and sub[:2] == ["auth", "status"]
                                                        and ("-t" in lower or "--show-token" in lower)):
        return "prints your GitHub token (gh auth token)"
    if prog == "gcloud" and "auth" in sub[:2] and any(w in ("print-access-token", "print-identity-token") for w in sub):
        return "prints a Google Cloud access token"
    if prog == "az" and sub[:2] == ["account", "get-access-token"]:
        return "prints an Azure access token"
    if prog == "aws" and sub[:2] == ["configure", "get"] and any(re.search(r"secret|token", w) for w in sub[2:]):
        return f"prints an AWS secret ({' '.join(lower[:4])})"
    if prog == "aws" and sub[:2] == ["configure", "export-credentials"]:
        return "prints your AWS credentials (aws configure export-credentials)"
    if prog == "heroku" and sub[:1] == ["auth:token"]:
        return "prints your Heroku token (heroku auth:token)"
    if prog == "op" and (sub[:1] == ["read"] or ("--reveal" in lower and sub[:1] == ["item"])):
        return f"prints a secret from 1Password ({' '.join(lower[:2])})"
    if prog in ("bw", "lpass", "pass", "gopass") and sub[:1] in (["get"], ["show"]):
        return f"prints a password from a password manager ({' '.join(lower[:2])})"
    if prog == "vault" and (sub[:2] == ["kv", "get"] or sub[:1] == ["read"]):
        return f"prints a secret from Vault ({' '.join(lower[:3])})"
    if prog in ("kubectl", "oc") and sub[:1] == ["get"] and sub[1:2] and re.match(r"^secrets?(/|$)", sub[1]) \
            and any(w in ("-o", "--output") or w.startswith(("-o", "--output=")) for w in lower[2:]):
        return "prints Kubernetes secrets (kubectl get secret -o ...)"
    return None

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


# Interpreters given their program as an argument instead of a file: the program is right there, but it's another
# language, so this reading can't tell what it does. A file (python x.py) or a module (python -m pytest) isn't this.
INLINE_CODE = {
    "python": ("-c",), "py": ("-c",), "pypy": ("-c",), "pypy3": ("-c",),
    "node": ("-e", "--eval", "-p", "--print"), "nodejs": ("-e", "--eval", "-p", "--print"),
    "bun": ("-e", "--eval", "-p", "--print"), "deno": ("eval",),
    "perl": ("-e", "-E"), "ruby": ("-e",), "php": ("-r",), "lua": ("-e",), "luajit": ("-e",),
    "osascript": ("-e",), "rscript": ("-e",), "julia": ("-e", "--eval"), "groovy": ("-e",),
}


def _inline_code_flag(prog: str, lower: list[str]) -> str | None:
    base = re.sub(r"[0-9.]+$", "", prog)               # python3.12 -> python
    flags = INLINE_CODE.get(base) or INLINE_CODE.get(prog)
    if not flags:
        return None
    if base == "deno":
        return "eval" if lower[1:2] == ["eval"] else None
    for w in lower[1:]:
        if w in flags:
            return w
        # combined short flags: python -Bc, perl -we
        if re.fullmatch(r"-[a-z]{2,4}", w) and any(len(f) == 2 and w.endswith(f[1]) for f in flags):
            return w
        if w == "-m" or not w.startswith("-"):
            return None                                    # a module or a script file comes first: that's what runs
    return None


SELF = ("squidbrake", "squidbreak")


def _turns_off_squidbrake(prog: str, lower: list[str]) -> str | None:
    """Commands that take Squidbrake out of the way: they wait for a person even when an agent asks nicely."""
    args = " ".join(lower[1:])
    if prog in SELF:
        sub = [w for w in lower[1:] if not w.startswith("-")]
        if "--remove" in lower or sub[:2] in (["service", "stop"], ["service", "remove"], ["service", "uninstall"]) \
                or sub[:1] in (["stop"], ["uninstall"], ["resume"]):
            return f"turns Squidbrake off or takes it out of the agents ({' '.join(lower[:4])})"
        if sub[:1] in (["remove-key"],):
            return f"removes a Squidbrake key ({' '.join(lower[:3])})"
    if prog in ("pip", "pip3", "pipx", "uv", "brew", "conda") and "uninstall" in lower[1:3] \
            and any(s in args for s in SELF):
        return f"uninstalls Squidbrake ({' '.join(lower[:4])})"
    if prog in ("kill", "pkill", "killall", "taskkill", "stop-process", "spps", "launchctl", "systemctl") \
            and re.search(r"squidbrake|squidbreak|server\.py|pythonw|python", args):
        return f"stops Squidbrake (or the Python it runs in) ({' '.join(lower[:4])})"
    if prog == "reg" and lower[1:2] == ["delete"] and "currentversion\\run" in args:
        return "takes Squidbrake out of what starts at login (reg delete ...\\Run)"
    if prog in ("remove-itemproperty", "rp") and "currentversion\\run" in args:
        return "takes Squidbrake out of what starts at login (Remove-ItemProperty ...\\Run)"
    return None


SSH_VALUE_FLAGS = set("BbcDEeFIiJLlmOoPpQRSWw")
EXEC_VALUE_FLAGS = {"-e", "--env", "-u", "--user", "-w", "--workdir", "--env-file", "-c", "--container", "-n",
                    "--namespace", "--context"}


def _remote_command(prog: str, words: list[str]) -> tuple[str, str] | None:
    """`ssh host 'cmd'`, `docker exec box cmd`, `kubectl exec pod -- cmd` -> (where, cmd), else None."""
    lower = [w.lower() for w in words]
    if prog == "ssh":
        i = 1
        while i < len(words) and words[i].startswith("-"):
            flag = words[i]
            i += 2 if len(flag) == 2 and flag[1] in SSH_VALUE_FLAGS else 1
        if i + 1 < len(words):
            return words[i], " ".join(_unquote(w) for w in words[i + 1:])
        return None
    if prog in ("docker", "podman", "nerdctl") and lower[1:2] == ["exec"]:
        i = 2
        while i < len(words) and words[i].startswith("-"):
            i += 2 if words[i] in EXEC_VALUE_FLAGS else 1
        if i + 1 < len(words):
            return f"container {words[i]}", " ".join(_unquote(w) for w in words[i + 1:])
        return None
    if prog in ("kubectl", "oc", "k") and "exec" in lower[1:3] and "--" in words:
        at = words.index("--")
        if at + 1 < len(words):
            rest = [w for i, w in enumerate(words[1:at], 1) if not w.startswith("-") and w.lower() != "exec"
                    and words[i - 1] not in EXEC_VALUE_FLAGS]
            pod = rest[0] if rest else "a pod"
            return f"pod {pod}", " ".join(_unquote(w) for w in words[at + 1:])
    return None


def _gh_command(words: list[str]) -> list[str]:
    i = 1
    while i < len(words):
        word = words[i]
        if word in ("-R", "--repo", "--hostname"):
            i += 2
        elif word.startswith(("--repo=", "--hostname=")) or (word.startswith("-R") and len(word) > 2):
            i += 1
        else:
            break
    return words[i:]


def _gh_option(words: list[str], flag: str, short: str = "", boolean: bool = False) -> str:
    # Do not interpret option-looking payload values or arguments after -- as flags.
    value_flags = {"-f", "-F", "--field", "--raw-field", "-H", "--header", "--input",
                   "--hostname", "-q", "--jq", "-t", "--template", "-R", "--repo",
                   "-d", "--description", "-b", "--body", "--subject", "--title", "--homepage"}
    value, i = "", 0
    while i < len(words) and words[i] != "--":
        word = words[i]
        if word == flag or (short and word == short):
            if boolean:
                value = "true"
            elif i + 1 < len(words):
                i += 1
                value = words[i]
        elif word.startswith(flag + "="):
            value = word.split("=", 1)[1]
        elif short and word.startswith(short) and len(word) > len(short):
            value = word[len(short):]
            if value.startswith("="):
                value = value[1:]
        elif word in value_flags:
            i += 1
        i += 1
    return value.lower()


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
    if re.search(r"\$\(|`|^\$", words[0]):
        return [], ["runs a program whose name is only known when it runs"]
    if (flag := _inline_code_flag(prog, lower)):
        return [], [f"runs a program written inline ({prog} {flag}), which a shell reading can't follow; a person "
                    f"reads it first"]

    # ---- Squidbrake itself: an agent turning off what checks it waits for a person
    if (why := _turns_off_squidbrake(prog, lower)):
        cmd.kind, cmd.why = "irreversible", why
        return [cmd], []
    if (why := _prints_secret(prog, lower)):
        cmd.kind, cmd.why = "secret", why
        return [cmd], []

    # ---- catastrophic
    if prog == "diskutil":
        if lower[1:2] in (["erasedisk"], ["erasevolume"], ["secureerase"], ["zerodisk"], ["randomdisk"], ["reformat"]):
            cmd.kind, cmd.why = "catastrophic", f"erases a disk or volume ({' '.join(words[:3])})"
            return [cmd], []
        if lower[1:2] == ["partitiondisk"]:
            cmd.kind, cmd.why = "catastrophic", f"formats or repartitions a disk ({' '.join(words[:3])})"
            return [cmd], []
        if lower[1:2] == ["apfs"] and lower[2:3] in (["deletecontainer"], ["deletevolume"]):
            cmd.kind, cmd.why = "catastrophic", f"deletes an APFS container or volume ({' '.join(words[:3])})"
            return [cmd], []
    if prog == "tmutil" and lower[1:2] == ["delete"]:
        cmd.kind, cmd.why = "irreversible", f"deletes Time Machine backups ({' '.join(words[:3])})"
        return [cmd], []
    if prog == "vssadmin" and lower[1:2] == ["delete"]:
        cmd.kind, cmd.why = "irreversible", f"deletes Volume Shadow Copy restore points ({' '.join(words[:3])})"
        return [cmd], []
    if prog == "reg" and lower[1:2] == ["delete"]:
        cmd.kind, cmd.why = "irreversible", f"deletes registry keys and their values ({' '.join(words[:3])})"
        return [cmd], []
    if prog == "wmic" and lower[1:2] == ["shadowcopy"] and "delete" in lower[2:]:
        cmd.kind, cmd.why = "irreversible", f"deletes Volume Shadow Copy restore points ({' '.join(words[:3])})"
        return [cmd], []
    if prog == "wbadmin" and lower[1:3] == ["delete", "catalog"]:
        cmd.kind, cmd.why = "irreversible", f"deletes the Windows backup catalog, so backups can't be restored ({' '.join(words[:3])})"
        return [cmd], []
    if prog == "bcdedit" and "recoveryenabled" in lower \
            and any(w in ("no", "false", "0") for w in lower[lower.index("recoveryenabled") + 1:]):
        cmd.kind, cmd.why = "irreversible", f"switches off Windows recovery at boot ({' '.join(words[:5])})"
        return [cmd], []
    if prog == "cipher" and any(w.lower().startswith("/w") for w in lower[1:]):
        cmd.kind, cmd.why = "irreversible", f"overwrites free disk space so deleted data can't be recovered ({' '.join(words[:2])})"
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
    # piped (Get-Partition -DriveLetter D | Format-Volume) or positional (Format-Volume D) wipes too; only help doesn't
    if prog in ("format-volume", "clear-disk") and not any(w in ("-?", "-help", "/?") for w in lower[1:]):
        cmd.kind, cmd.why = "catastrophic", f"wipes a whole disk ({' '.join(words[:3])})"
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

    # ---- database reset and migration commands
    # Framework and database tools wipe a whole database with one word.
    # These are irreversible: the data is gone, there is no undo.
    text = " ".join(lower[1:])
    if prog == "supabase" and "db" in lower and "reset" in lower:
        cmd.kind, cmd.why = "irreversible", f"resets or wipes the database ({' '.join(words[:4])})"
        return [cmd], []
    if prog == "dropdb" \
            or (prog in ("rails", "rake") and any(w in ("db:drop", "db:reset") for w in lower)) \
            or (prog in ("python", "python3", "py") and "manage.py" in lower and "flush" in lower) \
            or (prog == "manage.py" and "flush" in lower) \
            or (prog == "pg_restore" and ("--clean" in lower or "-c" in lower)) \
            or (prog == "prisma" and "migrate" in lower and "reset" in lower) \
            or (prog == "prisma" and "db" in lower and "push" in lower and "accept-data-loss" in text):
        cmd.kind, cmd.why = "irreversible", f"resets or wipes the database ({' '.join(words[:4])})"
        return [cmd], []

    # ---- infrastructure and cloud
    if prog in ("terraform", "tofu", "terragrunt"):
        sub = [w for w in lower[1:] if not w.startswith("-")][:2]
        if sub[:1] == ["destroy"] or "-destroy" in lower or sub == ["state", "rm"] or sub == ["workspace", "delete"]:
            cmd.kind, cmd.why = "irreversible", f"destroys infrastructure ({' '.join(words[:4])})"
        elif sub[:1] == ["apply"] and ("-auto-approve" in lower or "--auto-approve" in lower):
            cmd.kind, cmd.why = "irreversible", "applies infrastructure changes without a plan review (-auto-approve)"
        elif sub[:1] == ["apply"]:
            cmd.kind, cmd.why = "irreversible", f"changes real infrastructure ({' '.join(words[:3])})"
        return [cmd], []
    if prog == "pulumi" and any(w in ("destroy", "rm") for w in lower[1:3]):
        cmd.kind, cmd.why = "irreversible", f"destroys infrastructure ({' '.join(words[:3])})"
        return [cmd], []
    if prog == "pulumi" and any(w in ("up", "update") for w in lower[1:2]):
        cmd.kind, cmd.why = "irreversible", f"changes real infrastructure ({' '.join(words[:2])})"
        return [cmd], []
    # ---- a command sent to another machine or container: read that command too
    if (remote := _remote_command(prog, words)) is not None and depth < 4:
        where, line = remote
        inner, hidden = _read(line, depth + 1)
        for c in inner:
            if c.kind != "other" and c.why:
                c.why = f"{c.why}, on {where}"
        return [cmd, *inner], hidden
    if prog in ("kubectl", "oc", "k"):
        sub = [w for w in lower[1:] if not w.startswith("-")][:3]      # may include a flag's value (-n prod)
        if any(w in ("delete", "drain") for w in sub) or ("scale" in sub and "--replicas=0" in lower):
            cmd.kind, cmd.why = "irreversible", f"deletes or drains Kubernetes resources ({' '.join(words[:4])})"
        return [cmd], []
    if prog == "helm" and any(w in ("uninstall", "delete", "del", "un") for w in lower[1:2]):
        cmd.kind, cmd.why = "irreversible", f"uninstalls a Helm release ({' '.join(words[:3])})"
        return [cmd], []
    if prog in CLOUD:
        verbs, i = [], 1
        while i < len(lower) and len(verbs) < 4:
            w = lower[i]
            if w.startswith("-") and verbs:
                break                            # aws s3 rm s3://x --recursive: the verbs end at the first option
            if w.startswith("-"):                # options before the verbs: aws --profile prod s3 rm, gsutil -m rm
                i += 2 if w in CLOUD_VALUE_OPTIONS and i + 1 < len(lower) else 1
                continue
            verbs.append(w); i += 1
        if any(DESTRUCTIVE_WORDS.match(v) for v in verbs) or (prog == "aws" and verbs[:2] == ["s3", "rm"]):
            cmd.kind, cmd.why = "irreversible", f"deletes cloud resources ({' '.join(words[:4])})"
        elif verbs[1:2] == ["mv"] and verbs[:1] in (["s3"], ["storage"]) or (prog == "gsutil" and verbs[:1] == ["mv"]):
            cmd.kind, cmd.why = "rename", f"moves cloud files, deleting them where they were ({' '.join(words[:4])})"
        elif any(v in ("sync", "rsync") for v in verbs[:3]) and any(
                w == "--delete" or w.startswith("--delete-") or (prog == "gsutil" and w == "-d") for w in lower):
            cmd.kind, cmd.why = "irreversible", f"deletes whatever the destination has that the source doesn't ({' '.join(words[:4])})"
        elif off := BACKUPS_OFF.search(" ".join(lower[1:])):
            cmd.kind, cmd.why = "irreversible", f"switches off backups or deletion protection ({off.group(0)})"
        return [cmd], []
    if prog in ("docker", "podman", "nerdctl"):
        sub = [w for w in lower[1:] if not w.startswith("-")][:2]
        if sub in (["system", "prune"], ["volume", "rm"], ["volume", "prune"], ["image", "prune"]) \
                or (sub[:1] == ["compose"] and "down" in lower and ("-v" in lower or "--volumes" in lower)) \
                or (sub[:1] == ["rm"] and ("-v" in lower or "--volumes" in lower)):
            cmd.kind, cmd.why = "irreversible", f"deletes containers' data ({' '.join(words[:4])})"
        elif sub[:1] in (["rm"], ["rmi"]) or (sub[1:2] in (["rm"], ["prune"], ["remove"]) and sub[:1] in (
                ["container"], ["image"], ["network"], ["builder"], ["buildx"], ["context"], ["secret"], ["config"])):
            cmd.kind, cmd.why = "irreversible", f"deletes containers, images or networks ({' '.join(words[:4])})"
        elif sub[:1] == ["push"] or sub == ["image", "push"]:
            cmd.kind, cmd.why = "irreversible", \
                f"pushes an image to a registry, overwriting the tag for everyone who pulls it ({' '.join(words[:3])})"
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
        elif prog == "redis-cli" and (hit := next((w for w in lower[1:] if w in REDIS_DELETE), None)):
            cmd.kind, cmd.why = "irreversible", f"deletes Redis data ({hit.upper()})"
        elif SQL_RENAME.search(text):
            cmd.kind, cmd.why = "rename", f"renames a table or database ({SQL_RENAME.search(text).group(0).strip()})"
        elif PRODUCTION.search(text) and (SQL_WRITES.search(text) or "<" in words[1:] or any(
                w in ("-f", "--file", "-i", "source") or w.startswith("--file=") for w in lower[1:])):
            cmd.kind, cmd.why = "irreversible", "changes a production database (an SQL file or a write)"
        return [cmd], []

    # ---- GitHub operations that delete data or override protections
    if prog == "gh" and _gh_option(words[1:], "--help", "-h", boolean=True) not in ("true", "1", "t"):
        gh_words = _gh_command(words)
        gh_lower = [word.lower() for word in gh_words]
        why = ""
        if gh_lower[:2] == ["secret", "delete"]:
            why = "deletes a GitHub secret"
        elif len(gh_lower) > 1 and gh_lower[1] in ("delete", "remove", "rm") and gh_lower[0] != "api":
            why = f"deletes on GitHub (gh {' '.join(gh_words[:2])})"
        elif gh_lower[:1] == ["api"] and _gh_option(gh_words[1:], "--method", "-X") == "delete":
            why = "sends a GitHub API request that deletes data"
        elif gh_lower[:2] == ["pr", "merge"] and _gh_option(gh_words[2:], "--admin", boolean=True) in ("true", "1", "t"):
            why = "merges a pull request with administrator privileges, which can bypass required checks"
        elif gh_lower[:2] == ["repo", "edit"] and _gh_option(gh_words[2:], "--visibility") == "public":
            why = "makes a GitHub repository public"
        if why:
            cmd.kind, cmd.why = "irreversible", why
            return [cmd], []
        if gh_lower[:2] == ["repo", "rename"]:
            cmd.kind, cmd.why = "rename", "renames a GitHub repository (links and clones that use the old name break)"
            return [cmd], []

    # ---- publishing and machine state
    why = None
    if prog in ("npm", "pnpm", "yarn") and "unpublish" in lower[1:3]:
        why = "removes a published package from the npm registry; others' installs can break and the version can't be reused"
    elif prog in ("bun", "poetry", "uv") and lower[1:2] == ["publish"]:
        why = f"publishes a package to a public registry; a released version can't be replaced ({' '.join(words[:2])})"
    elif prog in ("python", "python3", "py") and lower[1:4] == ["-m", "twine", "upload"]:
        why = "uploads a package to PyPI; a released version can't be replaced"
    elif prog == "gem" and lower[1:2] == ["push"]:
        why = "publishes a gem to RubyGems; a released version can't be replaced"
    elif prog == "mvn" and "deploy" in lower[1:]:
        why = "deploys build artifacts to a remote Maven repository"
    if why:
        cmd.kind, cmd.why = "irreversible", why
        return [cmd], []
    if (prog in ("npm", "pnpm", "yarn") and "publish" in lower[1:3]) or (prog == "cargo" and "publish" in lower[1:2]) \
            or (prog == "twine" and "upload" in lower[1:2]) or (prog == "gh" and lower[1:3] in (["repo", "delete"],
                                                                                              ["release", "delete"])) \
            or (prog == "gh" and lower[1:3] in (["gist", "create"], ["repo", "create"])
                and ("--public" in lower or (lower[2] == "create" and lower[1] == "gist" and "-p" in lower)
                     or "--visibility=public" in lower
                     or ("--visibility" in lower and "public" in lower))):
        cmd.kind, cmd.why = "irreversible", f"publishes or deletes something public ({' '.join(words[:3])})"
        return [cmd], []
    if prog in ("shutdown", "reboot", "halt", "poweroff", "stop-computer", "restart-computer") \
            or (prog == "init" and lower[1:2] in (["0"], ["6"])):
        cmd.kind, cmd.why = "irreversible", f"shuts down or restarts the machine ({' '.join(words[:2])})"
        return [cmd], []
    if prog == "crontab" and "-r" in lower:
        cmd.kind, cmd.why = "irreversible", "deletes every scheduled job (crontab -r)"
        return [cmd], []
    if prog == "truncate" or prog in ("clear-content", "clc") or (prog == "mv" and any(w in ("/dev/null", "nul") for w in lower[1:])) \
            or (prog == "cp" and lower[1:2] == ["/dev/null"] and len(_positional(words)) == 2):
        cmd.kind, cmd.why = "irreversible", f"empties or discards files ({' '.join(words[:3])})"
        return [cmd], []
    # `> f` or `: > f` with nothing written: the file is emptied (appending with >> isn't)
    if (prog in (":", "true") or re.fullmatch(r"[0-9]?>.*", words[0])) \
            and any(re.fullmatch(r"[0-9]?>([^>&].*)?", w) for w in words) \
            and (targets := [t for t in _redirected(words) if t.lower() not in _HARMLESS_TARGETS]):
        cmd.kind, cmd.why = "irreversible", f"empties {targets[0]} (> with nothing written)"
        return [cmd], []
    if prog == "kill" and len(words) >= 3 and words[-1] == "-1":            # kill -9 -1 (`kill -1 PID` is SIGHUP)
        cmd.kind, cmd.why = "irreversible", "kills every process you own (kill -1)"
        return [cmd], []
    # PowerShell reaching .NET: [System.IO.File]::Delete("x"), [IO.Directory]::Delete("x", $true), (Get-Item x).Delete()
    if re.search(r"\]::delete\s*\(|\)\.delete\(\s*\)", " ".join(lower)):
        cmd.kind, cmd.why = "irreversible", f"deletes files ({' '.join(words)})"
        return [cmd], []

    # ---- other deletes: any PowerShell Remove-* cmdlet (Remove-ADUser, Remove-AzResourceGroup, ...)
    if prog.startswith("remove-") and not any(w in ("-whatif", "-?") for w in lower[1:]):
        cmd.kind, cmd.why = "irreversible", f"deletes something ({' '.join(words[:3])})"
        return [cmd], []

    # ---- renames and moves: the old name stops working, so a person says yes
    if prog in ("mv", "move", "move-item", "mi", "rename-item", "ren", "rename", "rni") and len(_positional(words)) >= 2 \
            or prog in ("rename-item", "rni") and len(words) > 1:
        cmd.kind, cmd.why = "rename", f"renames or moves files ({' '.join(words)[:100]})"
        return [cmd], []

    # ---- only looks
    if prog in READ_ONLY:
        bad = UNSAFE_OPTIONS.get(prog, ())
        if (found := _secret_files(prog, words)):
            cmd.kind, cmd.why = "secret", f"shows the agent a file that may hold secrets ({found[0]})"
        elif any(SECRET_PATH.search(w) or SECRET_EXT.search(w) for w in words[1:] if not w.startswith("-")):
            cmd.why = f"looks at a file that may hold secrets ({' '.join(words[:4])})"   # ls ~/.ssh: "other"
        elif not any(w == b or w.startswith(b + "=") for w in words[1:] for b in bad):
            cmd.kind = "read_only"
    return [cmd], []


BACKUPS_OFF = re.compile(r"--backup-retention-period[ =]0\b|--no-deletion-protection\b|--deletion-protection[ =]false\b|"
                         r"--no-backup\b|--no-enable-point-in-time-recovery\b|--retention-period[ =]0\b|"
                         r"put-bucket-versioning\b.*status=suspended")
PRODUCTION = re.compile(r"\bprod(uction)?\b|\bprod_|_prod\b|\bprd\b", re.I)
SQL_WRITES = re.compile(r"\b(insert\s+into|update\s+\S+\s+set|alter\s+table|create\s+(table|index)|grant|revoke)\b", re.I)

REGENERABLE = {"node_modules", "dist", "build", "out", ".next", ".nuxt", ".svelte-kit", ".turbo", ".cache", ".parcel-cache",
               "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".venv", "venv", "coverage",
               ".coverage", "htmlcov", "target", ".gradle"}


TEMP_DIR = re.compile(r"^(/tmp|/private/tmp|/var/tmp|/private/var/folders/[^/]+/[^/]+/T|/var/folders/[^/]+/[^/]+/T|"
                      r"\$\{?TMPDIR\}?)/[^/]+", re.I)
THROWAWAY = re.compile(r"(\.(log|tmp|temp|pyc|pyo|bak|swp|swo|orig|rej)|^\.DS_Store)$", re.I)


def _regenerable(target: str) -> bool:
    """A build output or cache folder inside the project (relative path, no wildcards, no climbing out), or a file in
    the temp folder."""
    t = target.strip("'\"").replace("\\", "/").rstrip("/")
    if TEMP_DIR.match(t) and not any(c in t for c in "*?[{") and ".." not in t.split("/"):
        return True                              # something inside the temp folder, never the folder itself
    if not t or t.startswith(("/", "~", "$", "%")) or re.match(r"^[a-z]:", t, re.I) or any(c in t for c in "*?[{"):
        return False
    parts = [p for p in t.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return False
    # build output and caches, and throwaway files: logs, temp files, editor backups, anything under tmp/
    return parts[-1].lower() in REGENERABLE or bool(THROWAWAY.search(parts[-1])) or parts[0].lower() in ("tmp", "temp")


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
    elif targets and all(_regenerable(t) for t in targets):
        # rm -rf node_modules dist: rebuilt by the next build, but still a delete, so a person says yes
        cmd.kind, cmd.why, cmd.rebuildable = "irreversible", f"deletes build output, caches or temp files ({' '.join(words)})", True
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
    elif sub == "rm" and ("f" in letters or "--force" in args) and "--cached" not in args:
        cmd.kind, cmd.why = "irreversible", f"deletes files with their uncommitted changes ({' '.join(words)})"
    elif sub == "rm" and "--cached" not in args and "--dry-run" not in args and "n" not in letters:
        cmd.kind, cmd.why = "irreversible", f"deletes files ({' '.join(words)})"
    elif (sub == "branch" and ("d" in letters or "--delete" in args)) or (sub == "tag" and ("d" in letters or "--delete" in args)) \
            or (sub in ("worktree", "remote") and args[:1] in (["remove"], ["rm"], ["prune"])):
        cmd.kind, cmd.why = "irreversible", f"deletes a {sub} ({' '.join(words)})"
    elif sub == "mv" or (sub == "branch" and letters & {"m", "M"}) or (sub == "remote" and args[:1] == ["rename"]):
        cmd.kind, cmd.why = "rename", f"renames or moves ({' '.join(words)})"
    elif (sub == "checkout" and ("." in args or "--" in args[:-1])) or (    # `git checkout -- file`, `git restore file`
            sub == "restore" and any(not a.startswith("-") for a in args)
            and not (("--staged" in args or "S" in letters) and not ("--worktree" in args or "W" in letters))):
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


# A shell or interpreter reading its program from a pipe: `cat setup.sh | bash`, `... | python3`. Flags only, no script.
_STDIN_TO_SHELL = re.compile(r"\|\s*(sudo\s+)?((ba|z|da|k)?sh|python[0-9.]*|perl|ruby|node|php|pwsh|powershell)"
                             r"(\s+-(?![ce]\b|-command\b|m\b)[A-Za-z-]+)*\s*($|[;&|)])", re.I)
# A shell or `source` reading another command's output as its program: `bash <(curl ...)`, `source <(...)`, `. <(...)`.
_SUBST_TO_SHELL = re.compile(r"(^|[\s;&|(])(source|\.|(ba|z|da|k)?sh|python[0-9.]*|perl|ruby|node)\s+(-\S+\s+)*<\(",
                             re.I)
# Sending data to another machine, and secrets that must not go there: environment variables, SSH and cloud keys,
# .env files, key files. A sender counts when it carries data: a body, a form, an upload, a redirect, or a copy.
_SENDER = re.compile(r"\b(curl|wget|nc|ncat|netcat|socat|scp|sftp|rsync|invoke-webrequest|iwr|invoke-restmethod|irm)\b"
                     r"(?=[^|;&]*(\s(-d|--data\S*|-F|--form\S*|-T|--upload-file|--json|--post-data|--post-file|"
                     r"--body-file|-Body|-InFile)(\s|=|$)|\s<|\s\S+:\S*\s*$|\s\S+@\S+:))", re.I)
_SECRET = re.compile(r"\$\((env|printenv|set|export\s+-p)\)|`(env|printenv)`|(^|[|;&]\s*)(env|printenv)\s*\||"
                     r"(~|\$HOME|\$\{HOME\}|%USERPROFILE%)?[\\/]\.ssh[\\/]?|\.aws[\\/]|(^|[\s@=<'\"/])\.env(\.\w+)?\b|"
                     r"\bid_(rsa|dsa|ecdsa|ed25519)\b|\.(pem|p12|pfx|key)\b|\bcredentials\b|\.npmrc\b|\.netrc\b|"
                     r"\.git-credentials\b|\.kube[\\/]config\b|\.docker[\\/]config\.json", re.I)


def downloads(line: str) -> list[str]:
    """Files a command line writes from the network: curl -o F / -O, wget [-O F] URL, Invoke-WebRequest -OutFile F."""
    return _downloaded(read(line).commands)


def _redirected(words: list[str]) -> list[str]:
    """Where a command's output goes into a file: `> f`, `>> f`, `>f`, `2> f`, and `tee f`."""
    out = []
    for i, x in enumerate(words):
        if m := re.fullmatch(r"[0-9&]?>>?(.*)", x):
            target = m.group(1) or (words[i + 1] if i + 1 < len(words) else "")
            out.append(_unquote(target))
    if words and _program(words[0]) in ("tee", "tee-object"):
        out += [_unquote(x) for x in words[1:] if not x.startswith("-")]
    return [x for x in out if x and x.lower() not in _HARMLESS_TARGETS and not x.startswith("&")]


def writes(line: str) -> list[str]:
    """Files a command line writes with a shell: redirected output (`cat > x.py <<EOF`, `echo ... >> f`) and tee."""
    return list(dict.fromkeys(f for c in read(line).commands for f in _redirected(c.words)))


FETCHERS = {"curl", "wget", "invoke-webrequest", "iwr", "invoke-restmethod", "irm"}


def _downloaded(cmds: list[Command]) -> list[str]:
    out = []
    for c in cmds:
        w, low = c.words, [x.lower() for x in c.words]
        url = next((_unquote(x) for x in w[1:] if re.match(r"^['\"]?https?://", x)), "")
        name = url.split("?")[0].rstrip("/").rsplit("/", 1)[-1] if url else ""
        if c.program in FETCHERS and url:
            out += _redirected(w)                       # `curl URL > x.sh`, `wget -qO- URL >> x.sh`
        if c.program == "curl":
            for i, x in enumerate(w):
                if (x == "--output" or re.match(r"^-[A-Za-z]*o$", x)) and i + 1 < len(w):     # -o, -so, -sSLo
                    out.append(_unquote(w[i + 1]))
                elif x.startswith("--output="):
                    out.append(_unquote(x.split("=", 1)[1]))
            if ("-O" in w or "--remote-name" in low) and name:
                out.append(name)
        elif c.program == "wget" and url:
            target = next((w[i + 1] for i, x in enumerate(w[:-1]) if x in ("-O", "--output-document")), None)
            if not re.search(r"-\w*O-", " ".join(w)):         # -O- / -qO-: to stdout (a redirect, above)
                out.append(_unquote(target) if target else name)
        elif c.program in ("invoke-webrequest", "iwr"):
            out += [_unquote(w[i + 1]) for i, x in enumerate(low[:-1]) if x == "-outfile"]
    return [x for x in out if x and x != "-"]


def executes(line: str) -> list[str]:
    """Files a command line runs, sources or makes runnable: scripts, `source f`, `. f`, `chmod +x f`."""
    return _ran(read(line))


def _ran(reading: "Reading") -> list[str]:
    found = list(reading.scripts)
    for c in reading.commands:
        if c.program in ("source", ".") and len(c.words) > 1:
            found.append(_unquote(c.words[1]))
        elif c.program == "chmod" and any(re.match(r"^([ugoa]*\+\w*x|[0-7]*[1357][0-7]{0,2})$", x) for x in c.words[1:]):
            found += [_unquote(x) for x in c.words[1:] if not x.startswith(("+", "-")) and not re.match(r"^[ugoa]*[+=]|^[0-7]+$", x)]
    return list(dict.fromkeys(found))


_PIPE_TO_SHELL = re.compile(r"\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\|\s*(sudo\s+)?(python[0-9.]*|perl|ruby|node|php)\b(?!\s+-m\s)"
                            r"|\|\s*(iex|invoke-expression)\b", re.I)


def _read(line: str, depth: int = 0) -> tuple[list[Command], list[str]]:
    commands, hidden = [], []
    if _PIPE_TO_SHELL.search(line) and re.search(r"\b(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod|"
                                                 r"base64|certutil|xxd\s+-r)\b", line, re.I):
        hidden.append("downloads or decodes code and runs it straight away, so it can't be read before it runs")
    elif depth == 0 and _STDIN_TO_SHELL.search(line):
        hidden.append("pipes code into a shell or interpreter, so what runs can't be read before it runs")
    if depth == 0 and _SUBST_TO_SHELL.search(line):
        hidden.append("runs the output of another command as code (<(...)), which can't be read before it runs")
    if depth == 0 and (send := _SENDER.search(line)) and (secret := _SECRET.search(line)):
        commands.append(Command(program=send.group(1).lower(), words=[send.group(1)], kind="irreversible",
                                why=f"sends secrets out ({secret.group(0).strip()} reaches {send.group(1)})", raw=line))
    parts, subs = _split_top(line)
    for sub in subs:
        c, h = _read(sub, depth + 1) if depth < 4 else ([], ["a command nested too deep to read"])
        commands += c; hidden += h
    for part in parts:
        c, h = classify(_words(part), raw=part, depth=depth)
        commands += c; hidden += h
    return commands, hidden


# Programs a developer's machine runs all day. Not "safe" (each is still read for what it does); just not unknown.
KNOWN = READ_ONLY | SHELLS | POWERSHELLS | {
    "git", "gh", "glab", "npm", "npx", "pnpm", "yarn", "bun", "node", "deno", "tsc", "tsx", "ts-node", "vite", "next",
    "jest", "vitest", "mocha", "eslint", "prettier", "biome", "python", "python3", "py", "pip", "pip3", "pipx", "uv",
    "poetry", "pdm", "hatch", "pytest", "tox", "nox", "ruff", "black", "isort", "mypy", "pyright", "flake8", "pylint",
    "coverage", "make", "cmake", "ninja", "gcc", "g++", "clang", "cc", "ld", "go", "gofmt", "cargo", "rustc", "rustup",
    "java", "javac", "mvn", "gradle", "gradlew", "kotlin", "dotnet", "msbuild", "nuget", "ruby", "gem", "bundle",
    "rake", "rails", "php", "composer", "perl", "swift", "xcodebuild", "pod", "flutter", "dart", "docker", "podman",
    "kubectl", "helm", "terraform", "tofu", "pulumi", "ansible", "aws", "gcloud", "az", "curl", "wget", "ssh", "scp",
    "rsync", "tar", "zip", "unzip", "gzip", "gunzip", "mkdir", "touch", "cp", "mv", "ln", "chmod", "chown", "rm",
    "rmdir", "sed", "awk", "xargs", "tee", "env", "export", "set", "unset", "source", ".", "alias", "history", "clear",
    "code", "cursor", "open", "start", "explorer", "claude", "codex", "gemini", "squidbrake", "psql", "mysql",
    "sqlite3", "redis-cli", "mongosh", "brew", "apt", "apt-get", "dnf", "yum", "pacman", "choco", "winget", "scoop",
    "set-location", "sl", "new-item", "ni", "copy-item", "cp", "move-item", "mi", "set-content", "sc", "add-content",
    "out-file", "remove-item", "invoke-webrequest", "iwr", "invoke-restmethod", "irm", "start-process", "saps",
}


def _looks_like_path(prog: str) -> bool:
    return prog.endswith((".sh", ".py", ".js", ".mjs", ".ts", ".ps1", ".bat", ".cmd", ".rb", ".pl"))


SCRIPT_RUNNERS = {"python", "py", "pypy", "node", "nodejs", "bun", "tsx", "ts-node", "ruby", "perl", "php", "bash",
                  "sh", "zsh", "dash", "ksh", "fish", "pwsh", "powershell", "deno", "osascript", "rscript", "lua"}


def _script_of(words: list[str]) -> str | None:
    words = _strip_wrappers(words)
    if not words:
        return None
    prog = _program(words[0])
    base = re.sub(r"[0-9.]+$", "", prog)
    if words[0].startswith(("./", ".\\", "/", "~")) or _looks_like_path(prog) and prog != "":
        return words[0] if _looks_like_path(prog) or words[0].startswith(("./", ".\\")) else None
    if prog in ("uv", "poetry", "pipenv", "pdm", "hatch", "rye") and words[1:2] == ["run"]:
        inner = [w for w in words[2:] if not w.startswith("-")]
        return _script_of(inner) or (inner[0] if inner and re.search(r"\.(py|pyw)$", inner[0]) else None)
    if base not in SCRIPT_RUNNERS and prog not in SCRIPT_RUNNERS:
        return None
    rest = words[1:]
    if base in ("pwsh", "powershell"):                  # its flags take values (-ExecutionPolicy Bypass): only -File
        named = next((rest[i + 1] for i, w in enumerate(rest[:-1]) if w.lower() in ("-file", "-f")), None)
        return named or next((w for w in rest if w.lower().endswith(".ps1")), None)
    if prog == "deno" and rest[:1] == ["run"]:
        rest = rest[1:]
    i = 0
    while i < len(rest):
        w = rest[i]
        if w.lower() in ("-file", "-f") and base in ("pwsh", "powershell"):
            return rest[i + 1] if i + 1 < len(rest) else None
        if w == "-m" or w in ("-c", "-e", "-r", "--eval", "-p", "--print", "-command") or w.lower() == "-command":
            return None                                    # a module, or inline code (read elsewhere)
        if not w.startswith("-"):
            return w
        i += 1
    return None


def read(line: str) -> Reading:
    """What a command line does. Never runs anything."""
    commands, hidden = _read(line or "")
    writes = any(t.lower() not in _HARMLESS_TARGETS for t in _REDIRECT_OUT.findall(_unquoted(line or "")))
    r = Reading(commands=commands, hidden=list(dict.fromkeys(hidden)), writes_files=writes)
    # `curl URL -o x.sh && sh x.sh`: downloaded and run in one line (across tool calls, server.written_then_run)
    name = lambda f: f.replace("\\", "/").removeprefix("./")
    if both := {name(f) for f in _downloaded(commands)} & {name(f) for f in _ran(r)}:
        r.hidden.append(f"downloads {sorted(both)[0]} and runs it in the same command, so it can't be read first")
    return r


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

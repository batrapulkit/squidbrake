#!/usr/bin/env sh
# Squidbrake installer for macOS / Linux.
#   curl -fsSL <server>/install.sh | sh
# With SQUIDBRAKE_URL and SQUIDBRAKE_AGENT_KEY set (a hosted dashboard), it also connects every agent on this computer.
# With SQUIDBRAKE_PILOT and SQUIDBRAKE_PILOT_SERVER set, it also offers to join that pilot (it asks first).
#
# It installs Squidbrake in its own folder and never depends on pipx or Homebrew versions:
#   1. a Python 3.10+ already here  -> its own virtual environment in ~/.squidbrake/app
#   2. otherwise (macOS ships 3.9)   -> uv, which brings its own Python (uv is installed first if it isn't here)
# Running it again upgrades Squidbrake in place, the same way it was installed: the agents' hooks run that copy, so
# a failed upgrade (offline, a proxy) leaves the working one as it was.
#
# Everything is inside main(), run on the last line: if the download stops halfway, nothing runs.
set -u

say()  { printf '%s\n' "$*"; }
ok()   { printf '  [OK] %s\n' "$*"; }
fail() { printf '\n  [X] %s\n\n' "$*"; offer_report "$*"; exit 1; }

# Asks first ([y/N], Enter is no; never without a terminal), then sends only the lines shown above as "What it
# said", with this computer's home folder written as ~, so the Squidbrake team can see why it failed and help.
# SQUIDBRAKE_SEND_REPORT=yes|no answers it ahead (support / tests).
offer_report() {
  [ -n "${LOG:-}" ] && [ -s "$LOG" ] && command -v curl >/dev/null 2>&1 || return 0
  answer="${SQUIDBRAKE_SEND_REPORT:-}"
  if [ -z "$answer" ]; then
    (exec </dev/tty) 2>/dev/null || return 0
    printf 'Send the "What it said" lines above to the Squidbrake team, so they can help? Only those lines go,\n'
    printf 'with your home folder shown as ~ (nothing else from this computer). [y/N] '
    read -r answer </dev/tty || answer=""
  fi
  case "$answer" in y|Y|yes|Yes|YES) ;; *) return 0 ;; esac
  tail -n 15 "$LOG" | awk -v h="$HOME" 'h != "" { while ((i = index($0, h)) > 0) $0 = substr($0, 1, i - 1) "~" substr($0, i + length(h)) } { print }' > "$LOG.send"
  code=$(printf '%s' "${SQUIDBRAKE_PILOT:-}" | tr -cd 'a-z0-9-')
  step=$(printf '%s' "$1" | cut -c1-80 | tr -cd 'A-Za-z0-9 .,-' | tr ' ' '+')
  os=$(uname -sm 2>/dev/null | tr -cd 'A-Za-z0-9 ._-' | tr ' ' '+')
  if curl -fsS -m 15 -X POST -H "Content-Type: text/plain; charset=utf-8" --data-binary @"$LOG.send" \
       "${SQUIDBRAKE_PILOT_SERVER:-https://pilots.squidbrake.com}/v1/install-report?installer=sh&code=$code&os=$os&step=$step" >/dev/null 2>&1
  then say "  Sent. Thank you: the Squidbrake team will see what went wrong."
  else say "  Couldn't send it. Send a screenshot of this window to whoever sent you this link instead."; fi
  rm -f "$LOG.send"
}
works() { [ -n "$1" ] && [ -x "$1" ] && "$1" --version >/dev/null 2>&1; }
new_enough() { [ -n "$1" ] && "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; }
# the last lines of what a step printed, when it failed (pip and uv say why: a proxy, no network, ...)
show_log() { [ -s "$LOG" ] && { say ""; say "  What it said:"; tail -n 15 "$LOG" | sed 's/^/    /'; }; }

# macOS without Apple's developer tools: /usr/bin/python3 is a stub that opens an "Install Command Line Developer
# Tools?" window (a long download), and its Python is 3.9 anyway. Don't touch it then.
usable() {
  case "$1" in /usr/bin/python3|/usr/bin/python)
    [ "$(uname)" = Darwin ] && ! xcode-select -p >/dev/null 2>&1 && return 1 ;;
  esac
  new_enough "$1"
}

find_python() {
  for c in python3.13 python3.12 python3.11 python3.10 python3 python \
           /opt/homebrew/bin/python3 /usr/local/bin/python3 "$HOME/.pyenv/shims/python3"; do
    p=$(command -v "$c" 2>/dev/null || true)
    if usable "$p"; then printf '%s' "$p"; return 0; fi
  done
  return 1
}

find_uv() {
  for u in "$(command -v uv 2>/dev/null || true)" "${UV_INSTALL_DIR:-}/uv" "${XDG_BIN_HOME:-}/uv" \
           "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do
    [ -n "$u" ] && [ -x "$u" ] && { printf '%s' "$u"; return 0; }
  done
  return 1
}

with_venv() {    # $1 = a Python 3.10+
  if [ -x "$APP/bin/python" ] && "$APP/bin/python" -c 'import sys' >/dev/null 2>&1; then
    say "Upgrading Squidbrake in $APP"
  else
    say "Using $("$1" --version 2>&1) at $1"
    rm -rf "$APP"
    if ! "$1" -m venv "$APP" >"$LOG" 2>&1 || ! [ -x "$APP/bin/python" ]; then
      rm -rf "$APP"     # half made (e.g. Debian/Ubuntu without python3-venv): don't leave it for the next run
      say "That Python can't make a virtual environment (on Debian/Ubuntu: sudo apt install python3-venv); trying uv instead."
      return 1
    fi
  fi
  say "Downloading Squidbrake (about a minute)..."
  "$APP/bin/python" -m pip install --quiet --disable-pip-version-check --upgrade pip >/dev/null 2>&1 || true
  # truststore: use this computer's certificates, so it also works behind company proxies that inspect HTTPS.
  # The newest version by name first; if that one isn't downloadable yet, whatever PyPI's list has.
  if pip_install --upgrade "$SPEC" || pip_install --use-feature=truststore --upgrade "$SPEC" \
     || { [ "$SPEC" != squidbrake ] && pip_install --upgrade squidbrake; }; then
    ln -sf "$APP/bin/squidbrake" "$BIN/squidbrake"
    works "$BIN/squidbrake" && SB="$BIN/squidbrake"
  fi
  [ -n "$SB" ] && return 0
  if [ -n "$HAD_APP" ] && works "$APP/bin/squidbrake"; then
    show_log
    ln -sf "$APP/bin/squidbrake" "$BIN/squidbrake"
    say ""
    say "  [!] Couldn't download the new version (see above); you still have $("$APP/bin/squidbrake" --version 2>&1)."
    say "      Your agents keep working. Run this again when the network is back."
    SB="$BIN/squidbrake"; KEPT=1
    return 0
  fi
  show_log
  say "Downloading with pip failed (see above); trying uv instead."
  return 1
}

with_uv() {
  UV=$(find_uv || true)
  if [ -z "$UV" ]; then
    command -v curl >/dev/null 2>&1 || fail "Squidbrake needs Python 3.10+ or uv, and curl to fetch uv. Install Python from https://www.python.org/downloads/ and run this again."
    say "Installing uv (Astral's Python installer), which brings its own Python..."
    curl -LsSf https://astral.sh/uv/install.sh 2>"$LOG" | env UV_NO_MODIFY_PATH=1 sh >>"$LOG" 2>&1 || true
    UV=$(find_uv || true)
    [ -n "$UV" ] || { show_log; fail "Couldn't install uv (see above). Install Python 3.10+ from https://www.python.org/downloads/ and run this again."; }
  fi
  say "Using uv at $UV"
  say "Downloading Squidbrake and its Python (about a minute)..."
  # UV_NATIVE_TLS: this computer's certificates, so company proxies that inspect HTTPS (Zscaler, ...) work too
  if ! (cd "${TMPDIR:-/tmp}" 2>/dev/null || cd "$HOME"; export UV_NATIVE_TLS=1 UV_TOOL_BIN_DIR="$BIN"
        uvi() { "$UV" tool install --quiet --force --refresh-package squidbrake --python-preference managed --python 3.12 "$1"; }
        uvi "$SPEC" || { [ "$SPEC" != squidbrake ] && uvi squidbrake; }) >"$LOG" 2>&1; then
    if works "$BIN/squidbrake"; then
      show_log
      say ""
      say "  [!] Couldn't download the new version (see above); you still have $("$BIN/squidbrake" --version 2>&1)."
      SB="$BIN/squidbrake"; KEPT=1
      return 0
    fi
    show_log
    fail "Installing Squidbrake with uv failed (see above). Send these lines to whoever sent you this link."
  fi
  works "$BIN/squidbrake" && SB="$BIN/squidbrake"
}

add_to_path() {
  [ -n "${SQUIDBRAKE_NO_PATH:-}" ] && return 0
  case ":$PATH:" in *":$BIN:"*) return 0 ;; esac
  line="export PATH=\"$BIN:\$PATH\""
  case "$(basename "${SHELL:-sh}")" in
    zsh)  rc="$HOME/.zshrc" ;;
    bash) if [ "$(uname)" = Darwin ]; then rc="$HOME/.bash_profile"; else rc="$HOME/.bashrc"; fi ;;
    fish) mkdir -p "$HOME/.config/fish/conf.d"
          grep -qsF "$BIN" "$HOME/.config/fish/conf.d/squidbrake.fish" \
            || printf '# Squidbrake\nfish_add_path -g "%s"\n' "$BIN" > "$HOME/.config/fish/conf.d/squidbrake.fish"
          return 0 ;;
    *)    rc="$HOME/.profile" ;;
  esac
  grep -qsF "$BIN" "$rc" || printf '\n# Squidbrake\n%s\n' "$line" >> "$rc"     # one file, quoted: HOME may have spaces
}

pip_install() { "$APP/bin/python" -m pip install --quiet --disable-pip-version-check --no-cache-dir "$@" >"$LOG" 2>&1; }

# What to install: the newest release by name, asked of PyPI directly. PyPI's list of files is cached for up to
# 10 minutes after a release, and pip and uv then pick the one before. SQUIDBRAKE_VERSION=X.Y.Z pins one;
# SQUIDBRAKE_VERSION=any skips asking (support / tests).
latest_spec() {
  v="${SQUIDBRAKE_VERSION:-}"
  if [ -z "$v" ] && command -v curl >/dev/null 2>&1; then
    v=$(curl -fsS -m 10 https://pypi.org/pypi/squidbrake/json 2>/dev/null | grep -o '"version": *"[^"]*"' | head -n 1 \
        | sed 's/.*"\([^"]*\)"$/\1/')
  fi
  v=$(printf '%s' "$v" | tr -cd '0-9a-z.')
  case "$v" in ""|any) printf 'squidbrake' ;; *) printf 'squidbrake==%s' "$v" ;; esac
}

main() {
  APP="${SQUIDBRAKE_APP_DIR:-$HOME/.squidbrake/app}"
  BIN="${SQUIDBRAKE_BIN_DIR:-$HOME/.local/bin}"
  SB=""; KEPT=""
  SPEC=$(latest_spec)
  HAD_APP=""; [ -x "$APP/bin/squidbrake" ] && HAD_APP=1

  say ""
  say "Installing Squidbrake (brakes for AI agents)..."
  say ""
  if grep -qsi microsoft /proc/version; then
    say "  [!] This is WSL (Linux inside Windows). Agents you run in Windows (Cursor, Claude Code for Windows, ...)"
    say "      are only covered by the Windows installer; run that in PowerShell. Installing for WSL's own agents."
    say ""
  fi
  mkdir -p "$BIN" "$(dirname "$APP")" || fail "Couldn't create $BIN. Check your home folder can be written to."
  LOG=$(mktemp 2>/dev/null || printf '%s' "$HOME/.squidbrake/install.log")

  # The same way as last time: the agents' hooks run that copy of Squidbrake
  if [ "${SQUIDBRAKE_INSTALL_WITH:-}" = uv ]; then how=uv
  elif [ -n "$HAD_APP" ]; then how=venv
  elif [ -e "$BIN/squidbrake" ] && find_uv >/dev/null; then how=uv
  else how=venv; fi

  if [ "$how" = venv ]; then
    if [ -n "$HAD_APP" ] && [ -x "$APP/bin/python" ]; then with_venv "$APP/bin/python" || with_uv
    else
      PY=$(find_python || true)
      if [ -n "$PY" ]; then with_venv "$PY" || with_uv; else with_uv; fi
    fi
  else
    with_uv
  fi

  [ -n "$SB" ] || fail "Squidbrake didn't install. Send the lines above to whoever sent you this link."
  rm -f "$LOG"
  say ""
  ok "Installed: $("$SB" --version)"
  add_to_path

  if [ -n "${SQUIDBRAKE_URL:-}" ] && [ -n "${SQUIDBRAKE_AGENT_KEY:-}" ]; then
    # a hosted dashboard: nothing to run locally, just route the agents through it
    case "$SQUIDBRAKE_AGENT_KEY" in *YOUR_AGENT_KEY*)
      fail "Put your agent key (from your start page) in place of gw_YOUR_AGENT_KEY and run it again." ;; esac
    if command -v curl >/dev/null 2>&1; then
      curl -fsS -m 20 -H "X-Gateway-Key: $SQUIDBRAKE_AGENT_KEY" "$SQUIDBRAKE_URL/v1/me" >/dev/null 2>&1 \
        || fail "Couldn't reach your dashboard with that key. Check you used the AGENT key from your start page, and run it again."
    fi
    ok "Your dashboard answers."
    if command -v claude >/dev/null 2>&1 || [ -d "$HOME/.claude" ]; then
      "$SB" connect claude-code --url "$SQUIDBRAKE_URL" --key "$SQUIDBRAKE_AGENT_KEY" --yes --hook-only >/dev/null 2>&1 \
        && ok "Claude Code: every tool call (commands, edits, web, MCP) goes through it." \
        || say "  [!] Claude Code couldn't be connected; run: squidbrake connect claude-code --url $SQUIDBRAKE_URL --key YOUR_AGENT_KEY"
    fi
    # every other coding agent installed here: its terminal commands and file actions (hooks) ...
    "$SB" connect agents --agent all --url "$SQUIDBRAKE_URL" --key "$SQUIDBRAKE_AGENT_KEY" --yes 2>&1 | sed 's/^/  /'
    # ... and its own MCP servers (GitHub, Stripe, databases...) go through it too
    "$SB" connect guard --agent all --url "$SQUIDBRAKE_URL" --key "$SQUIDBRAKE_AGENT_KEY" --yes 2>&1 | sed 's/^/  /'
    # check every connected agent's hook end to end (it sends one harmless 'echo' through the dashboard)
    "$SB" doctor --quick 2>/dev/null | sed -n '/\[/p'
    say ""
    say "Last step: quit and reopen your agents (Cursor: Cmd+Q, then open it again), then work as usual."
    say "Your dashboard: $SQUIDBRAKE_URL/dashboard"
    say "Something not right later? Open a new terminal and run:  squidbrake doctor"
    say ""
    exit 0
  fi

  if [ -n "${SQUIDBRAKE_PILOT:-}" ] && [ -n "${SQUIDBRAKE_PILOT_SERVER:-}" ]; then
    # stdin is this script (curl | sh): ask on the terminal. /dev/tty can exist and still not open (no terminal:
    # Docker without -t, ssh with a command, CI), so try opening it first.
    if (exec </dev/tty) 2>/dev/null; then
      "$SB" pilot join "$SQUIDBRAKE_PILOT" --server "$SQUIDBRAKE_PILOT_SERVER" </dev/tty
    else
      say ""
      say "To join the pilot (it asks first), run:  squidbrake pilot join $SQUIDBRAKE_PILOT --server $SQUIDBRAKE_PILOT_SERVER"
    fi
  fi

  if [ -n "$KEPT" ]; then exit 0; fi
  # Everything else in one go: runs in the background, every agent here connected and checked, the dashboard opened
  # signed in (onboard.py). SQUIDBRAKE_SETUP=0 stops after installing. Questions go to the terminal (stdin is this
  # script); with no terminal it asks nothing.
  if [ "${SQUIDBRAKE_SETUP:-}" != 0 ]; then
    if (exec </dev/tty) 2>/dev/null; then "$SB" setup </dev/tty; else "$SB" setup </dev/null; fi && exit 0
    SETUP_FAILED=1
    say ""
    say "Setup stopped (see above). To do it step by step:"
  fi
  case ":$PATH:" in *":$BIN:"*) run="squidbrake" ;; *) run="$BIN/squidbrake   (or open a new terminal and run: squidbrake)" ;; esac
  cat <<EOF

Next:
  1. Run:  $run
     It prints your keys (save them) and opens the dashboard. It asks once whether to keep running in the
     background and at every login. Say yes: if it isn't running, your agents' actions are blocked until it is.
  2. In another terminal, connect your agents:  squidbrake connect all
  3. Restart your agents and work as usual. Watch it at http://localhost:8080/dashboard

EOF
  # installed, but setup didn't finish: say so to whoever ran this (scripts check the exit code)
  if [ -n "${SETUP_FAILED:-}" ]; then exit 1; fi
}

main "$@"

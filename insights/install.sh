#!/usr/bin/env sh
# Squidbrake installer for macOS / Linux.
#   curl -fsSL <server>/install.sh | sh
# With SQUIDBRAKE_URL and SQUIDBRAKE_AGENT_KEY set (a hosted dashboard), it also connects every agent on this computer.
# With SQUIDBRAKE_PILOT and SQUIDBRAKE_PILOT_SERVER set, it also offers to join that pilot (it asks first).
#
# It installs Squidbrake in its own folder and never depends on pipx or Homebrew versions:
#   1. a Python 3.10+ already here  -> its own virtual environment in ~/.squidbrake/app
#   2. otherwise (macOS ships 3.9)   -> uv, which brings its own Python (uv is installed first if it isn't here)
# Running it again upgrades Squidbrake in place.
set -u
APP="${SQUIDBRAKE_APP_DIR:-$HOME/.squidbrake/app}"
BIN="${SQUIDBRAKE_BIN_DIR:-$HOME/.local/bin}"
SB=""

say()  { printf '%s\n' "$*"; }
ok()   { printf '  [OK] %s\n' "$*"; }
fail() { printf '\n  [X] %s\n\n' "$*"; exit 1; }
works() { [ -n "$1" ] && [ -x "$1" ] && "$1" --version >/dev/null 2>&1; }
new_enough() { [ -n "$1" ] && "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; }

say ""
say "Installing Squidbrake (brakes for AI agents)..."
say ""
mkdir -p "$BIN"

# ---- 1. a Python 3.10+ that's already here: a private virtual environment
PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3 python \
         /opt/homebrew/bin/python3 /usr/local/bin/python3 "$HOME/.pyenv/shims/python3"; do
  p=$(command -v "$c" 2>/dev/null || true)
  if new_enough "$p"; then PY="$p"; break; fi
done
[ "${SQUIDBRAKE_INSTALL_WITH:-}" = uv ] && PY=""     # support / tests: go straight to uv
if [ -n "$PY" ]; then
  say "Using $("$PY" --version 2>&1) at $PY"
  if "$PY" -m venv --clear "$APP" >/dev/null 2>&1 \
     && "$APP/bin/python" -m pip install --quiet --disable-pip-version-check --upgrade pip >/dev/null 2>&1 \
     && "$APP/bin/python" -m pip install --quiet --disable-pip-version-check --upgrade squidbrake; then
    ln -sf "$APP/bin/squidbrake" "$BIN/squidbrake"
    works "$BIN/squidbrake" && SB="$BIN/squidbrake"
  fi
  [ -n "$SB" ] || say "That Python couldn't make a virtual environment; trying uv instead."
fi

# ---- 2. uv, which brings its own Python
if [ -z "$SB" ]; then
  UV=$(command -v uv 2>/dev/null || true)
  [ -z "$UV" ] && [ -x "$HOME/.local/bin/uv" ] && UV="$HOME/.local/bin/uv"
  [ -z "$UV" ] && [ -x "$HOME/.cargo/bin/uv" ] && UV="$HOME/.cargo/bin/uv"
  if [ -z "$UV" ]; then
    command -v curl >/dev/null 2>&1 || fail "Squidbrake needs Python 3.10+ or uv, and curl to fetch uv. Install Python from https://www.python.org/downloads/ and run this again."
    say "Installing uv (Astral's Python installer), which brings its own Python..."
    curl -LsSf https://astral.sh/uv/install.sh | env UV_NO_MODIFY_PATH=1 sh >/dev/null 2>&1 || true
    [ -x "$HOME/.local/bin/uv" ] && UV="$HOME/.local/bin/uv"
    [ -z "$UV" ] && [ -x "$HOME/.cargo/bin/uv" ] && UV="$HOME/.cargo/bin/uv"
    [ -n "$UV" ] || fail "Couldn't install uv. Install Python 3.10+ from https://www.python.org/downloads/ and run this again."
  fi
  say "Using uv at $UV"
  (cd /tmp && UV_TOOL_BIN_DIR="$BIN" "$UV" tool install --quiet --force --python-preference managed --python 3.12 squidbrake) \
    || fail "Installing Squidbrake with uv failed (see the lines above). Send them to whoever sent you this link."
  works "$BIN/squidbrake" && SB="$BIN/squidbrake"
fi

[ -n "$SB" ] || fail "Squidbrake didn't install. Send the lines above to whoever sent you this link."
say ""
ok "Installed: $("$SB" --version)"

# The squidbrake command in new terminals: add the folder to the shell's startup file once
[ -n "${SQUIDBRAKE_NO_PATH:-}" ] || case ":$PATH:" in *":$BIN:"*) ;; *)
  for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    if [ -f "$rc" ] || [ "$rc" = "$HOME/.zshrc" -a "$(uname)" = "Darwin" ]; then
      grep -qs "$BIN" "$rc" || printf '\n# Squidbrake\nexport PATH="%s:$PATH"\n' "$BIN" >> "$rc"
    fi
  done ;;
esac

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
  if [ -r /dev/tty ]; then "$SB" pilot join "$SQUIDBRAKE_PILOT" --server "$SQUIDBRAKE_PILOT_SERVER" </dev/tty
  else "$SB" pilot join "$SQUIDBRAKE_PILOT" --server "$SQUIDBRAKE_PILOT_SERVER"; fi
fi

cat <<'EOF'

Next:
  1. Open a new terminal (so the 'squidbrake' command is found) and run:  squidbrake
     It prints your keys (save them), starts Squidbrake in the background and opens the dashboard.
     It starts again by itself whenever you log in. (Turn it off: squidbrake service stop)
  2. In another terminal, connect your agents:  squidbrake connect all
  3. Restart your agents and work as usual. Watch it at http://localhost:8080/dashboard

EOF

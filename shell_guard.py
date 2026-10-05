"""
A guard for the lines people type or paste into their own terminal (no agent involved, so no agent hook sees them).

  squidbrake shell-guard check "rm -rf ~/"        exit 0 run, 1 block, 2 ask (the reason goes to stderr)
  squidbrake shell-guard install --shell bash     prints the snippet for ~/.bashrc  (also: zsh, powershell)

`check` is a thin layer over commands.read(), so the terminal and the agent hooks always agree:
catastrophic -> block, irreversible or hidden -> ask, anything else -> run (silently).

It never edits an rc file: `install` only prints. It is a helper for people, not a gate: if the check itself fails
(an exception, `squidbrake` missing), the line runs. Local only; nothing is sent anywhere.
"""
from __future__ import annotations

import sys

RUN, BLOCK, ASK = "run", "block", "ask"
EXIT_CODES = {RUN: 0, BLOCK: 1, ASK: 2}
SHELLS = ("bash", "zsh", "powershell")


def check(line: str) -> tuple[str, str]:
    """(action, message) for one command line. The message is empty when the action is run."""
    import commands

    reading = commands.read(line)
    why = reading.summary() or line.strip()[:80]
    if reading.kind == "catastrophic":
        return BLOCK, f"Squidbrake: blocked: {why}"
    if reading.kind == "irreversible":
        return ASK, f"Squidbrake: this can't be undone: {why}"
    if reading.kind == "hidden":
        return ASK, f"Squidbrake: {why}"
    return RUN, ""


# --------------------------------------------------------------------------- snippets (printed, never installed)
# Each runs `squidbrake shell-guard check` before a line executes. Only exit codes 1 and 2 do anything, so a missing
# `squidbrake` (127) lets the line run, and main() turns any exception into 0. Interactive shells only.

BASH = r'''# Squidbrake terminal guard: checks each command line before it runs. Add to ~/.bashrc.
if [[ $- == *i* ]] && command -v squidbrake >/dev/null 2>&1; then
  __sb_armed=0
  __sb_arm() { __sb_armed=1; }
  __sb_debug() {
    # The DEBUG trap fires for every part of a pipeline; only the first one after the prompt checks the whole line.
    [[ $__sb_armed == 1 ]] || return 0
    __sb_armed=0
    local line rc ans
    line=$(HISTTIMEFORMAT= builtin history 1 | sed 's/^ *[0-9][0-9]*\*\{0,1\} *//')
    [[ $line == *"$BASH_COMMAND"* ]] || line=$BASH_COMMAND   # history skipped it (HISTCONTROL=ignorespace...)
    squidbrake shell-guard check -- "$line" </dev/null
    rc=$?
    [[ $rc == 1 ]] && return 1
    if [[ $rc == 2 ]]; then
      read -r -p "Run it anyway? [y/N] " ans </dev/tty || return 1
      [[ $ans == [yY]* ]] || return 1
    fi
    return 0
  }
  # Installed at the first prompt, when the rest of your rc files have loaded. trap -p can't see a DEBUG trap from inside
  # a sourced file or a function, so this check is a plain PROMPT_COMMAND string. If one is already set (VS Code shell
  # integration, bash-preexec, atuin...) it is left alone: replacing it would break that tool.
  __sb_install='if [[ -z $__sb_done ]]; then __sb_done=1; if [[ -n $(trap -p DEBUG) ]]; then echo "Squidbrake: a DEBUG trap is already set (VS Code shell integration, bash-preexec...), so the terminal guard is off in this bash." >&2; else shopt -s extdebug; trap __sb_debug DEBUG; fi; fi'
  if [[ "$(declare -p PROMPT_COMMAND 2>/dev/null)" == "declare -a"* ]]; then
    PROMPT_COMMAND+=("$__sb_install" __sb_arm)
  else
    PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND;}$__sb_install;__sb_arm"
  fi
fi
'''

ZSH = r'''# Squidbrake terminal guard: checks each command line before it runs. Add to ~/.zshrc.
if [[ -o interactive ]] && (( $+commands[squidbrake] )); then
  (( $+widgets[__squidbrake_orig_accept_line] )) || zle -A accept-line __squidbrake_orig_accept_line
  __squidbrake_accept_line() {
    local rc=0
    if [[ -n ${BUFFER//[[:space:]]/} ]]; then
      zle -I
      squidbrake shell-guard check -- "$BUFFER" </dev/null
      rc=$?
      if (( rc == 1 )); then
        print   # zle redraws the prompt one line up; without this it would overwrite the message
        zle reset-prompt
        return 0
      elif (( rc == 2 )); then
        local ans
        read -q "ans?Run it anyway? [y/N] " </dev/tty || { print; zle reset-prompt; return 0; }
        print
      fi
    fi
    zle __squidbrake_orig_accept_line
  }
  zle -N accept-line __squidbrake_accept_line
fi
'''

POWERSHELL = r'''# Squidbrake terminal guard: checks each command line before it runs. Add to your profile ($PROFILE).
function global:__SquidbrakeAllow([string]$line) {
  # True when the line may run. Any failure of the guard itself lets it run.
  try {
    if (-not $line -or -not $line.Trim()) { return $true }
    $ErrorActionPreference = 'Continue'
    $out = $line | squidbrake shell-guard check --stdin 2>&1
    $rc = $LASTEXITCODE
    if ($rc -ne 1 -and $rc -ne 2) { return $true }
    Write-Host ''
    Write-Host (($out | ForEach-Object { "$_" }) -join "`n")
    if ($rc -eq 1) { return $false }
    return ((Read-Host 'Run it anyway? [y/N]') -match '^[yY]')
  } catch { return $true }
}
if ((Get-Command squidbrake -ErrorAction SilentlyContinue) -and (Get-Module PSReadLine)) {
  Set-PSReadLineKeyHandler -Key Enter -ScriptBlock {
    $line = $null; $cursor = $null
    [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)
    if (-not (__SquidbrakeAllow $line)) {
      [Microsoft.PowerShell.PSConsoleReadLine]::AddToHistory($line)   # up-arrow gets it back to edit
      [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
    }
    [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
  }
}
'''

SNIPPETS = {"bash": BASH, "zsh": ZSH, "powershell": POWERSHELL}

USAGE = """usage: squidbrake shell-guard check [--stdin] [--] LINE   exit code 0 run, 1 block, 2 ask
       squidbrake shell-guard install --shell bash|zsh|powershell   print the snippet for your rc file"""


def main(argv: list[str]) -> int:
    if argv[:1] == ["check"]:
        rest = argv[1:]
        try:
            if rest[:1] == ["--stdin"]:
                line = sys.stdin.buffer.read().decode("utf-8-sig", "replace").strip()   # PowerShell 5.1 prefixes a BOM
            else:
                line = " ".join(rest[1:] if rest[:1] == ["--"] else rest)
            action, message = check(line)
        except Exception:
            return 0   # fail open: this is a helper for people, not a gate
        if message:
            print(message, file=sys.stderr)
        return EXIT_CODES[action]
    if argv[:1] == ["install"]:
        shell = argv[argv.index("--shell") + 1] if "--shell" in argv[:-1] else ""
        if shell not in SHELLS:
            print(USAGE, file=sys.stderr)
            return 64
        sys.stdout.write(SNIPPETS[shell])
        return 0
    print(USAGE, file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

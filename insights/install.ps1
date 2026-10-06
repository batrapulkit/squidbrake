# Squidbrake installer for Windows (PowerShell).
#   irm <server>/install.ps1 | iex
# With $env:SQUIDBRAKE_PILOT and $env:SQUIDBRAKE_PILOT_SERVER set, it also offers to join that pilot (it asks first).
# It installs Squidbrake in its own folder and never depends on pipx versions:
#   1. a Python 3.10+ already here  -> its own virtual environment in %USERPROFILE%\.squidbrake\app
#   2. otherwise                     -> uv, which brings its own Python (uv is installed first if it isn't here)
# Running it again upgrades Squidbrake in place.
$ErrorActionPreference = "Continue"
Write-Host "`nInstalling Squidbrake (brakes for AI agents)...`n" -ForegroundColor Cyan
function Fail($msg) { Write-Host "`n  [X] $msg`n" -ForegroundColor Red; throw "Squidbrake install stopped" }
function Works($exe) { if (-not $exe -or -not (Test-Path $exe)) { return $false }; & $exe --version *> $null; return ($LASTEXITCODE -eq 0) }

$app = if ($env:SQUIDBRAKE_APP_DIR) { $env:SQUIDBRAKE_APP_DIR } else { Join-Path $env:USERPROFILE ".squidbrake\app" }
$bin = if ($env:SQUIDBRAKE_BIN_DIR) { $env:SQUIDBRAKE_BIN_DIR } else { Join-Path $env:USERPROFILE ".local\bin" }
New-Item -ItemType Directory -Force -Path $bin | Out-Null
$sb = $null

try {
    # ---- 1. a Python 3.10+ that's already here: a private virtual environment
    $py = $null
    $cands = @()
    foreach ($v in @("3.13", "3.12", "3.11", "3.10")) { $cands += ,@("py", "-$v") }
    foreach ($c in @("python", "python3")) { $cands += ,@($c) }
    foreach ($c in $cands) {
        $cmd = Get-Command $c[0] -ErrorAction SilentlyContinue
        if (-not $cmd -or $cmd.Source -like "*WindowsApps*") { continue }
        $exe = & $cmd.Source @($c | Select-Object -Skip 1) -c "import sys; print(sys.executable if sys.version_info >= (3, 10) else '')" 2>$null
        if ($LASTEXITCODE -eq 0 -and $exe) { $py = "$exe".Trim(); break }
    }
    if ($env:SQUIDBRAKE_INSTALL_WITH -eq "uv") { $py = $null }     # support / tests: go straight to uv
    if ($py) {
        Write-Host "Using $(& $py --version 2>&1) at $py"
        & $py -m venv --clear $app 2>$null
        $vpy = Join-Path $app "Scripts\python.exe"
        if ($LASTEXITCODE -eq 0 -and (Test-Path $vpy)) {
            & $vpy -m pip install --quiet --disable-pip-version-check --upgrade pip 2>$null | Out-Null
            & $vpy -m pip install --quiet --disable-pip-version-check --upgrade squidbrake
            $exe = Join-Path $app "Scripts\squidbrake.exe"
            if (Works $exe) {
                # Copy the launcher (it knows its own Python) into a folder on PATH, so the venv's python.exe never
                # shadows anyone's Python. Replace any older squidbrake.exe there (an earlier pipx install), or Windows
                # would keep running that one: it looks for .exe before .cmd.
                $dest = Join-Path $bin "squidbrake.exe"
                try { Copy-Item $exe $dest -Force -ErrorAction Stop }
                catch {   # in use: move the old one aside, then copy
                    Move-Item $dest (Join-Path $bin "squidbrake.old-$(Get-Date -Format yyyyMMddHHmmss).exe") -Force -ErrorAction SilentlyContinue
                    Copy-Item $exe $dest -Force -ErrorAction SilentlyContinue
                }
                $shim = Join-Path $bin "squidbrake.cmd"   # from 0.6.3-0.6.4 installers; the .exe replaces it
                if (Test-Path $shim) { Move-Item $shim "$shim.old" -Force -ErrorAction SilentlyContinue }
                if (Works $dest) { $sb = $dest }
            }
        }
        if (-not $sb) { Write-Host "That Python couldn't make a virtual environment; trying uv instead." }
    }

    # ---- 2. uv, which brings its own Python
    if (-not $sb) {
        $uv = (Get-Command uv -ErrorAction SilentlyContinue).Source
        if (-not $uv -and (Test-Path (Join-Path $bin "uv.exe"))) { $uv = Join-Path $bin "uv.exe" }
        if (-not $uv) {
            Write-Host "Installing uv (Astral's Python installer), which brings its own Python..."
            $env:UV_NO_MODIFY_PATH = "1"; $env:UV_INSTALL_DIR = $bin
            try { Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression *> $null } catch { }
            if (Test-Path (Join-Path $bin "uv.exe")) { $uv = Join-Path $bin "uv.exe" }
            if (-not $uv) { Fail "Couldn't install uv. Install Python 3.10+ from https://www.python.org/downloads/ (tick 'Add python.exe to PATH') and run this again." }
        }
        Write-Host "Using uv at $uv"
        $env:UV_TOOL_BIN_DIR = $bin
        Push-Location $env:TEMP
        try { & $uv tool install --quiet --force --python-preference managed --python 3.12 squidbrake } finally { Pop-Location }
        if ($LASTEXITCODE -ne 0) { Fail "Installing Squidbrake with uv failed (see the lines above). Send them to whoever sent you this link." }
        if (Works (Join-Path $bin "squidbrake.exe")) { $sb = Join-Path $bin "squidbrake.exe" }
    }
    if (-not $sb) { Fail "Squidbrake didn't install. Send the lines above to whoever sent you this link." }
} catch { return }

# The squidbrake command in new windows: add the folder to the user's PATH once
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $env:SQUIDBRAKE_NO_PATH -and ($userPath -split ";") -notcontains $bin) {
    [Environment]::SetEnvironmentVariable("Path", (($userPath.TrimEnd(";") + ";" + $bin).TrimStart(";")), "User")
}
Write-Host "`n  [OK] Installed: $(& $sb --version)" -ForegroundColor Green

if ($env:SQUIDBRAKE_URL -and $env:SQUIDBRAKE_AGENT_KEY) {
    # a hosted dashboard: nothing to run locally, just route Claude Code through it
    if ($env:SQUIDBRAKE_AGENT_KEY -like "*YOUR_AGENT_KEY*") {
        Write-Host "`nPut your agent key (from your start page) in place of gw_YOUR_AGENT_KEY and run it again." -ForegroundColor Yellow
        return
    }
    try {
        $me = Invoke-RestMethod "$($env:SQUIDBRAKE_URL)/v1/me" -Headers @{ "X-Gateway-Key" = $env:SQUIDBRAKE_AGENT_KEY } -TimeoutSec 20
    } catch {
        Write-Host "`nCouldn't reach your dashboard with that key ($($_.Exception.Message)). Check you used the AGENT key from your start page, and run it again." -ForegroundColor Yellow
        return
    }
    Write-Host "`n  [OK] Your dashboard answers (signed in as '$($me.client)')." -ForegroundColor Green
    if ((Get-Command claude -ErrorAction SilentlyContinue) -or (Test-Path (Join-Path $env:USERPROFILE ".claude"))) {
        & $sb connect claude-code --url $env:SQUIDBRAKE_URL --key $env:SQUIDBRAKE_AGENT_KEY --yes --hook-only | Out-Null
        Write-Host "  [OK] Claude Code: every tool call (commands, edits, web, MCP) goes through it." -ForegroundColor Green
    }
    # every other coding agent installed here: its terminal commands and file actions (hooks) ...
    & $sb connect agents --agent all --url $env:SQUIDBRAKE_URL --key $env:SQUIDBRAKE_AGENT_KEY --yes | ForEach-Object { Write-Host "  $_" }
    # ... and its own MCP servers (GitHub, Stripe, databases...) go through it too
    & $sb connect guard --agent all --url $env:SQUIDBRAKE_URL --key $env:SQUIDBRAKE_AGENT_KEY --yes | ForEach-Object { Write-Host "  $_" }
    # check every connected agent's hook end to end (it sends one harmless 'echo' through the dashboard)
    & $sb doctor --quick 2>$null | Where-Object { $_ -match "\[" } | ForEach-Object { Write-Host $_ }
    Write-Host "`nLast step: quit and reopen your agents (Claude Code, Cursor, ...), then work as usual."
    Write-Host "Your dashboard: $($env:SQUIDBRAKE_URL)/dashboard"
    Write-Host "Something not right later? Open a new PowerShell window and run:  squidbrake doctor`n"
    return
}

if ($env:SQUIDBRAKE_PILOT -and $env:SQUIDBRAKE_PILOT_SERVER) {
    & $sb pilot join $env:SQUIDBRAKE_PILOT --server $env:SQUIDBRAKE_PILOT_SERVER
}

Write-Host "`nNext:" -ForegroundColor Cyan
Write-Host "  1. Open a NEW PowerShell window (so the 'squidbrake' command is found) and run:  squidbrake"
Write-Host "     It prints your keys (save them) and opens the dashboard. It asks once whether to keep running in the"
Write-Host "     background and at every login; say no to keep that window open instead. (Later: squidbrake start --background)"
Write-Host "  2. In another window, connect your agents:  squidbrake connect all"
Write-Host "  3. Restart your agents and work as usual. Watch it at http://localhost:8080/dashboard`n"

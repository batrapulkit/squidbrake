# Squidbrake installer for Windows (PowerShell).
#   irm <server>/install.ps1 | iex
# With $env:SQUIDBRAKE_PILOT and $env:SQUIDBRAKE_PILOT_SERVER set, it also offers to join that pilot (it asks first).
# It installs Squidbrake in its own folder and never depends on pipx versions:
#   1. a Python 3.10+ already here  -> its own virtual environment in %USERPROFILE%\.squidbrake\app
#   2. otherwise                     -> uv, which brings its own Python (uv is installed first if it isn't here)
# Running it again upgrades Squidbrake in place, the same way it was installed: the agents' hooks run that copy, so
# a failed upgrade (offline, a proxy) leaves the working one as it was.
$ErrorActionPreference = "Continue"
Write-Host "`nInstalling Squidbrake (brakes for AI agents)...`n" -ForegroundColor Cyan
function Fail($msg) { Write-Host "`n  [X] $msg`n" -ForegroundColor Red; OfferReport $msg; throw "Squidbrake install stopped" }
# Asks first ([y/N], Enter is no; never without a keyboard), then sends only the lines shown above as "What it
# said", with this computer's user folder written as ~, so the Squidbrake team can see why it failed and help.
# $env:SQUIDBRAKE_SEND_REPORT = yes|no answers it ahead (support / tests).
function OfferReport($msg) {
    if (-not (Test-Path $log) -or -not (Get-Item $log).Length) { return }
    $answer = $env:SQUIDBRAKE_SEND_REPORT
    if (-not $answer) {
        if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) { return }
        Write-Host 'Send the "What it said" lines above to the Squidbrake team, so they can help? Only those lines go,'
        $answer = Read-Host "with your user folder shown as ~ (nothing else from this computer). [y/N]"
    }
    if ($answer -notmatch '^(y|yes)$') { return }
    $text = (Get-Content $log -Tail 15) -join "`n"
    $text = $text -ireplace [regex]::Escape($env:USERPROFILE), "~"
    $server = if ($env:SQUIDBRAKE_PILOT_SERVER) { $env:SQUIDBRAKE_PILOT_SERVER } else { "https://pilots.squidbrake.com" }
    $pcode = ([string]$env:SQUIDBRAKE_PILOT) -replace '[^a-z0-9-]', ''
    $q = "installer=ps1&code=$pcode" +
         "&os=$([uri]::EscapeDataString("Windows $([Environment]::OSVersion.Version) $env:PROCESSOR_ARCHITECTURE PS$($PSVersionTable.PSVersion.Major)"))" +
         "&step=$([uri]::EscapeDataString(([string]$msg).Substring(0, [Math]::Min(80, ([string]$msg).Length))))"
    try {
        Invoke-RestMethod -Method Post -Uri "$server/v1/install-report?$q" -Body ([Text.Encoding]::UTF8.GetBytes($text)) `
            -ContentType "text/plain; charset=utf-8" -TimeoutSec 15 | Out-Null
        Write-Host "  Sent. Thank you: the Squidbrake team will see what went wrong."
    } catch { Write-Host "  Couldn't send it. Send a screenshot of this window to whoever sent you this link instead." }
}
function Works($exe) { if (-not $exe -or -not (Test-Path $exe)) { return $false }; & $exe --version *> $null; return ($LASTEXITCODE -eq 0) }
# The last lines of what a step printed, when it failed (pip and uv say why: a proxy, no network, antivirus...)
function ShowLog($log) {
    if (Test-Path $log) {
        Write-Host "`n  What it said:" -ForegroundColor Yellow
        Get-Content $log -Tail 15 | ForEach-Object { Write-Host "    $_" }
    }
}

# Locked-down laptops (AppLocker / Device Guard): scripts run in "constrained language", and programs in your user
# folder are usually blocked too. Say so instead of failing halfway.
if ($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage") {
    Write-Host "  [X] This computer only lets PowerShell run restricted scripts (set by your IT team), so Squidbrake can't be" -ForegroundColor Red
    Write-Host "      installed from here. Ask IT to allow it, or install it with:  pip install squidbrake`n" -ForegroundColor Red
    return
}

$app = if ($env:SQUIDBRAKE_APP_DIR) { $env:SQUIDBRAKE_APP_DIR } else { Join-Path $env:USERPROFILE ".squidbrake\app" }
$bin = if ($env:SQUIDBRAKE_BIN_DIR) { $env:SQUIDBRAKE_BIN_DIR } else { Join-Path $env:USERPROFILE ".local\bin" }
$log = Join-Path $env:TEMP "squidbrake-install.log"
New-Item -ItemType Directory -Force -Path $bin | Out-Null
$sb = $null; $kept = $false
$vpy = Join-Path $app "Scripts\python.exe"
$hadApp = Works (Join-Path $app "Scripts\squidbrake.exe")
# What to install: the newest release by name, asked of PyPI directly. PyPI's list of files is cached for up to
# 10 minutes after a release, and pip and uv then pick the one before. $env:SQUIDBRAKE_VERSION = "X.Y.Z" pins one;
# "any" skips asking (support / tests).
$ver = $env:SQUIDBRAKE_VERSION
if (-not $ver) { try { $ver = (Invoke-RestMethod "https://pypi.org/pypi/squidbrake/json" -TimeoutSec 10).info.version } catch {} }
$ver = ([string]$ver) -replace '[^0-9a-z.]', ''
$spec = if ($ver -and $ver -ne "any") { "squidbrake==$ver" } else { "squidbrake" }
# truststore / UV_NATIVE_TLS: use this computer's certificates, so it works behind company proxies that inspect HTTPS
$env:UV_NATIVE_TLS = "1"

# A background service holds the installed files open, and Windows won't replace files in use: stop it first, start
# it again at the end (whether or not the upgrade worked).
$service = $false
if (-not $env:SQUIDBRAKE_APP_DIR) { try { $service = $null -ne (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name Squidbrake -ErrorAction Stop) } catch {} }   # not for a test / custom folder
$old = Join-Path $bin "squidbrake.exe"
if ($service -and (Works $old)) {
    Write-Host "Stopping the background service while it upgrades..."
    & $old service stop *> $null
}

function CopyLauncher($exe) {
    # Copy the launcher (it knows its own Python) into a folder on PATH, so the venv's python.exe never shadows
    # anyone's Python. Replace any older squidbrake.exe there (an earlier pipx install), or Windows would keep
    # running that one: it looks for .exe before .cmd.
    $dest = Join-Path $bin "squidbrake.exe"
    try { Copy-Item $exe $dest -Force -ErrorAction Stop }
    catch {   # in use: move the old one aside, then copy
        Move-Item $dest (Join-Path $bin "squidbrake.old-$(Get-Date -Format yyyyMMddHHmmss).exe") -Force -ErrorAction SilentlyContinue
        Copy-Item $exe $dest -Force -ErrorAction SilentlyContinue
    }
    $shim = Join-Path $bin "squidbrake.cmd"   # from 0.6.3-0.6.4 installers; the .exe replaces it
    if (Test-Path $shim) { Move-Item $shim "$shim.old" -Force -ErrorAction SilentlyContinue }
    if (Works $dest) { return $dest }
    return $null
}

try {
    # ---- the same way as last time: the agents' hooks run that copy of Squidbrake
    $how = "venv"
    if ($env:SQUIDBRAKE_INSTALL_WITH -eq "uv") { $how = "uv" }
    elseif (-not $hadApp -and (Works $old) -and ((Get-Command uv -ErrorAction SilentlyContinue) -or (Test-Path (Join-Path $bin "uv.exe")))) { $how = "uv" }

    # ---- 1. a private virtual environment (kept and upgraded if it's already here)
    if ($how -eq "venv") {
        $py = $null
        if ($hadApp -and (Works $vpy)) { $py = $vpy; Write-Host "Upgrading Squidbrake in $app" }
        else {
            $cands = @()
            foreach ($v in @("3.14", "3.13", "3.12", "3.11", "3.10")) { $cands += ,@("py", "-$v") }
            foreach ($c in @("python", "python3")) { $cands += ,@($c) }
            foreach ($c in $cands) {
                $cmd = Get-Command $c[0] -ErrorAction SilentlyContinue
                if (-not $cmd -or $cmd.Source -like "*WindowsApps*") { continue }   # the Microsoft Store stub
                $exe = & $cmd.Source @($c | Select-Object -Skip 1) -c "import sys; print(sys.executable if sys.version_info >= (3, 10) else '')" 2>$null
                if ($LASTEXITCODE -eq 0 -and $exe) { $py = "$exe".Trim(); break }
            }
            if ($py) {
                Write-Host "Using $(& $py --version 2>&1) at $py"
                if (Test-Path $app) { Remove-Item $app -Recurse -Force -ErrorAction SilentlyContinue }   # broken: start over
                & $py -m venv $app *> $log
                if (-not (Works $vpy)) {
                    ShowLog $log
                    if (Test-Path $app) { Remove-Item $app -Recurse -Force -ErrorAction SilentlyContinue }
                    Write-Host "That Python can't make a virtual environment; trying uv instead."
                    $py = $null
                }
            }
        }
        if ($py) {
            Write-Host "Downloading Squidbrake (about a minute)..."
            & $vpy -m pip install --quiet --disable-pip-version-check --upgrade pip *> $null
            # the newest version by name first (truststore: this computer's certificates, for company proxies that
            # inspect HTTPS); if that one isn't downloadable yet, whatever PyPI's list has
            & $vpy -m pip install --quiet --disable-pip-version-check --no-cache-dir --upgrade $spec *> $log
            if ($LASTEXITCODE -ne 0) {
                & $vpy -m pip install --quiet --disable-pip-version-check --no-cache-dir --use-feature=truststore --upgrade $spec *> $log
            }
            if ($LASTEXITCODE -ne 0 -and $spec -ne "squidbrake") {
                & $vpy -m pip install --quiet --disable-pip-version-check --no-cache-dir --upgrade squidbrake *> $log
            }
            $exe = Join-Path $app "Scripts\squidbrake.exe"
            if ($LASTEXITCODE -eq 0 -and (Works $exe)) { $sb = CopyLauncher $exe }
            elseif ($hadApp -and (Works $exe)) {
                ShowLog $log
                $sb = CopyLauncher $exe; $kept = $true
                Write-Host "`n  [!] Couldn't download the new version (see above); you still have $(& $exe --version)." -ForegroundColor Yellow
                Write-Host "      Your agents keep working. Run this again when the network is back." -ForegroundColor Yellow
            }
            else { ShowLog $log; Write-Host "Downloading with pip failed (see above); trying uv instead." }
        }
    }

    # ---- 2. uv, which brings its own Python
    if (-not $sb) {
        $uv = (Get-Command uv -ErrorAction SilentlyContinue).Source
        if (-not $uv -and (Test-Path (Join-Path $bin "uv.exe"))) { $uv = Join-Path $bin "uv.exe" }
        if (-not $uv) {
            Write-Host "Installing uv (Astral's Python installer), which brings its own Python..."
            $env:UV_NO_MODIFY_PATH = "1"; $env:UV_INSTALL_DIR = $bin
            # In its own PowerShell: uv's installer ends with 'exit 1' on any error (e.g. the default Restricted
            # execution policy), and run here with Invoke-Expression that 'exit' would close the founder's window.
            $ps = (Get-Process -Id $PID).Path
            & $ps -NoProfile -ExecutionPolicy Bypass -Command "irm https://astral.sh/uv/install.ps1 | iex" *> $log
            if (Test-Path (Join-Path $bin "uv.exe")) { $uv = Join-Path $bin "uv.exe" }
            if (-not $uv) { ShowLog $log; Fail "Couldn't install uv (see above). Install Python 3.10+ from https://www.python.org/downloads/ (tick 'Add python.exe to PATH') and run this again." }
        }
        Write-Host "Using uv at $uv"
        Write-Host "Downloading Squidbrake and its Python (about a minute)..."
        $env:UV_TOOL_BIN_DIR = $bin
        Push-Location $env:TEMP
        try {
            & $uv tool install --quiet --force --refresh-package squidbrake --python-preference managed --python 3.12 $spec *> $log
            if ($LASTEXITCODE -ne 0 -and $spec -ne "squidbrake") {
                & $uv tool install --quiet --force --refresh-package squidbrake --python-preference managed --python 3.12 squidbrake *> $log
            }
        } finally { Pop-Location }
        if ($LASTEXITCODE -ne 0) {
            ShowLog $log
            if (Works $old) {
                $sb = $old; $kept = $true
                Write-Host "`n  [!] Couldn't download the new version (see above); you still have $(& $old --version)." -ForegroundColor Yellow
            }
            else { Fail "Installing Squidbrake with uv failed (see above). Send these lines to whoever sent you this link." }
        }
        elseif (Works (Join-Path $bin "squidbrake.exe")) { $sb = Join-Path $bin "squidbrake.exe" }
    }
    if (-not $sb) { Fail "Squidbrake didn't install. Send the lines above to whoever sent you this link." }
} catch {
    if ($service -and (Works $old)) { & $old start --background *> $null }
    return
}
Remove-Item $log -ErrorAction SilentlyContinue

# The squidbrake command in new windows (and this one): add the folder to the user's PATH once. Read and written as
# it's stored (REG_EXPAND_SZ), so entries like %JAVA_HOME%\bin stay as they are; a user with no PATH yet gets one.
$envKey = (Get-Item "HKCU:\").OpenSubKey("Environment", $true)
$userPath = [string]$envKey.GetValue("Path", "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
if (-not $env:SQUIDBRAKE_NO_PATH -and ($userPath -split ";") -notcontains $bin) {
    $envKey.SetValue("Path", (($userPath.TrimEnd(";") + ";" + $bin).TrimStart(";")), [Microsoft.Win32.RegistryValueKind]::ExpandString)
}
$envKey.Close()
if (($env:Path -split ";") -notcontains $bin) { $env:Path = "$env:Path;$bin" }
Write-Host "`n  [OK] Installed: $(& $sb --version)" -ForegroundColor Green

if ($service) {
    & $sb start --background *> $null
    Write-Host "  [OK] The background service is running again." -ForegroundColor Green
}

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
        & $sb connect claude-code --url $env:SQUIDBRAKE_URL --key $env:SQUIDBRAKE_AGENT_KEY --yes --hook-only *> $log
        if ($LASTEXITCODE -eq 0) { Write-Host "  [OK] Claude Code: every tool call (commands, edits, web, MCP) goes through it." -ForegroundColor Green }
        else { ShowLog $log; Write-Host "  [!] Claude Code couldn't be connected; run: squidbrake connect claude-code --url $($env:SQUIDBRAKE_URL) --key YOUR_AGENT_KEY" -ForegroundColor Yellow }
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

if ($kept -or $service) { return }
# Everything else in one go: runs in the background, every agent here connected and checked, the dashboard opened
# signed in (onboard.py). $env:SQUIDBRAKE_SETUP = "0" stops after installing.
if ($env:SQUIDBRAKE_SETUP -ne "0") {
    & $sb setup
    if ($LASTEXITCODE -eq 0) { return }
    Write-Host "`nSetup stopped (see above). To do it step by step:" -ForegroundColor Yellow
}
Write-Host "`nNext:" -ForegroundColor Cyan
Write-Host "  1. Run:  squidbrake"
Write-Host "     It prints your keys (save them) and opens the dashboard. It asks once whether to keep running in the"
Write-Host "     background and at every login. Say yes: if it isn't running, your agents' actions are blocked until it is."
Write-Host "  2. In another PowerShell window, connect your agents:  squidbrake connect all"
Write-Host "  3. Restart your agents and work as usual. Watch it at http://localhost:8080/dashboard`n"

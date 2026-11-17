# Microsoft Intune: install Squidbrake for the signed-in user and connect their agents to the team's gateway.
# Package it as a Win32 app (IntuneWinAppUtil.exe) with:
#   Install command    powershell.exe -NoProfile -ExecutionPolicy Bypass -File intune-install.ps1 -Url https://gateway.yourcompany.com -Key gw_...
#   Install behavior   User   (Squidbrake and the agents' settings live in the user's profile; SYSTEM has neither)
#   Detection rule     File exists: %USERPROFILE%\.local\bin\squidbrake.exe
# The key is the person's own agent key (dashboard > Team > Add someone, type AI agent, "Works for" that person). Each key works
# for one person, so assign the app per user, not once for every device. See docs/mdm.md.
param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Key)
$ErrorActionPreference = "Stop"
$env:SQUIDBRAKE_URL = $Url.TrimEnd("/")
$env:SQUIDBRAKE_AGENT_KEY = $Key
$env:SQUIDBRAKE_SEND_REPORT = "no"          # nobody is at the keyboard to answer
$env:SQUIDBRAKE_REF = "mdm"
$log = Join-Path $env:TEMP "squidbrake-intune.log"
Start-Transcript -Path $log -Force | Out-Null
try {
    Invoke-RestMethod https://pilots.squidbrake.com/install.ps1 | Invoke-Expression
    if (-not (Test-Path (Join-Path $env:USERPROFILE ".local\bin\squidbrake.exe"))) { throw "squidbrake.exe not installed (see $log)" }
} finally {
    Stop-Transcript | Out-Null
}

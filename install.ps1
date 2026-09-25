# Install DecoMonitor and start it at boot, before anyone logs on.
# Run this from an elevated PowerShell. Re-running keeps secret.txt and history.sqlite.
$ErrorActionPreference = "Stop"
$Root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    throw "Run install.ps1 in an elevated PowerShell. Registering a startup task as SYSTEM needs an administrator."
}

function Get-PythonInvocation {
    foreach ($pair in @(
        @{ File = "py"; Prefix = @("-3") },
        @{ File = "python"; Prefix = @() }
    )) {
        $cmd = Get-Command $pair.File -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        if ($cmd.Source -like "*\WindowsApps\*") { continue }
        & $pair.File @($pair.Prefix + @("-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"))
        if ($LASTEXITCODE -eq 0) {
            return @{ File = $pair.File; Prefix = $pair.Prefix }
        }
    }
    throw "Python 3.11 or newer is required. Install it from python.org and run this script again."
}

$python = Get-PythonInvocation
$venvDir = Join-Path $Root ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"
$venvPythonw = Join-Path $venvDir "Scripts\pythonw.exe"
if (-not (Test-Path $venvPython)) {
    & $python.File @($python.Prefix + @("-m", "venv", $venvDir))
    if ($LASTEXITCODE -ne 0) { throw "Could not create the virtual environment." }
}
& $venvPython -m pip install -r (Join-Path $Root "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "Could not install Python packages." }
if (-not (Test-Path $venvPythonw)) { $venvPythonw = $venvPython }

$server = Join-Path $Root "server.py"
schtasks.exe /End /TN DecoBandwidth 2>$null | Out-Null
Get-CimInstance Win32_Process | Where-Object {
    $_.Name -match '^pythonw?\.exe$' -and $_.CommandLine -and (($_.CommandLine -replace '"', '') -like "*$server*")
} | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

$secret = Join-Path $Root "secret.txt"
if (Test-Path $secret) {
    $user = "$env:USERDOMAIN\$env:USERNAME"
    & icacls.exe $secret /inheritance:r /grant:r "${user}:(R,W)" /grant:r "NT AUTHORITY\SYSTEM:(R,W)" | Out-Null
}

$action = New-ScheduledTaskAction -Execute $venvPythonw -Argument "`"$server`"" -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -DontStopOnIdleEnd `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
Register-ScheduledTask -TaskName "DecoBandwidth" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "DecoBandwidth"
Write-Output "DecoMonitor starts at boot. Dashboard: http://127.0.0.1:8787"

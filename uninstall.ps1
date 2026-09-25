# Remove the DecoMonitor startup task. Leaves secret.txt and history.sqlite in place.
$ErrorActionPreference = "Stop"
$Root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    throw "Run uninstall.ps1 in an elevated PowerShell."
}

schtasks.exe /End /TN DecoBandwidth 2>$null | Out-Null
$server = Join-Path $Root "server.py"
Get-CimInstance Win32_Process | Where-Object {
    $_.Name -match '^pythonw?\.exe$' -and $_.CommandLine -and (($_.CommandLine -replace '"', '') -like "*$server*")
} | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}
Unregister-ScheduledTask -TaskName "DecoBandwidth" -Confirm:$false -ErrorAction SilentlyContinue
Write-Output "Startup task removed. The database and password file were left in $Root"

param(
    [string]$InstallRoot = "C:\ProgramData\BlackBox",
    [string]$SourceDir = $PSScriptRoot
)

$ErrorActionPreference = "Stop"

Write-Host "BLACK BOX installer — creating directories and copying configuration."

New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $InstallRoot "logs") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $InstallRoot "config") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $InstallRoot "assets") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $InstallRoot "Quarantine") | Out-Null

Copy-Item -Force (Join-Path $SourceDir "config.ini") (Join-Path $InstallRoot "config.ini")
Get-ChildItem -Path $SourceDir -Filter "*.py" | Copy-Item -Destination $InstallRoot -Force
Copy-Item -Recurse -Force (Join-Path $SourceDir "dashboard_templates") (Join-Path $InstallRoot "dashboard_templates")

attrib +h (Join-Path $InstallRoot "Quarantine")

Write-Host "Installing Python dependencies (requires Python 3.10+ on PATH)."
python -m pip install --upgrade pip
python -m pip install -r (Join-Path $SourceDir "requirements.txt")

Write-Host "Registering Windows service (requires elevated PowerShell and pywin32)."
$python = (Get-Command python).Source
$script = Join-Path $InstallRoot "blackbox_daemon.py"
& $python $script install
Write-Host "Service registered. Start with: sc start BlackBox   (or: net start BlackBox)"

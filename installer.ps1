# filename: installer.ps1
# ============================================================
<#
.SYNOPSIS
Installs and configures the Black Box Parental Security Suite.

.DESCRIPTION
This script sets up the required directories, permissions, Python dependencies,
and creates the NSSM service for the Black Box daemon. Must be run as Administrator.
#>

# Require Admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please run this script as an Administrator!"
    Exit
}

$InstallDir = "C:\BLACKBOX"
$ProgramDataDir = "C:\ProgramData\BlackBox"
$PythonExec = "python" # Assume Python is in PATH
$NSSMUrl = "https://nssm.cc/release/nssm-2.24.zip"
$NSSMZip = "$env:TEMP\nssm.zip"
$NSSMExe = "$InstallDir\nssm.exe"

Write-Host "=== BLACK BOX INSTALLER ===" -ForegroundColor Cyan

# 1. Setup Directories
Write-Host "Creating directories..."
New-Item -Path "$ProgramDataDir\logs" -ItemType Directory -Force | Out-Null
New-Item -Path "$ProgramDataDir\secret" -ItemType Directory -Force | Out-Null
New-Item -Path "$ProgramDataDir\Quarantine" -ItemType Directory -Force | Out-Null
New-Item -Path "$ProgramDataDir\assets" -ItemType Directory -Force | Out-Null
New-Item -Path "$ProgramDataDir\config" -ItemType Directory -Force | Out-Null

# Hide the Quarantine directory
attrib +h +s "$ProgramDataDir\Quarantine"

# 2. Secure Secret Directory
Write-Host "Securing secret directory..."
$Acl = Get-Acl "$ProgramDataDir\secret"
$Acl.SetAccessRuleProtection($true, $false) # Disable inheritance
$RuleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$RuleAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$Acl.AddAccessRule($RuleSystem)
$Acl.AddAccessRule($RuleAdmin)
Set-Acl "$ProgramDataDir\secret" $Acl

# 3. Install Python Dependencies
Write-Host "Installing Python Dependencies..."
Start-Process -FilePath $PythonExec -ArgumentList "-m pip install -r $InstallDir\requirements.txt" -Wait -NoNewWindow

# 4. Download and configure NSSM
if (-not (Test-Path $NSSMExe)) {
    Write-Host "Downloading NSSM..."
    Invoke-WebRequest -Uri $NSSMUrl -OutFile $NSSMZip
    Expand-Archive -Path $NSSMZip -DestinationPath "$env:TEMP\nssm_extracted" -Force
    
    # Check Architecture
    if ([Environment]::Is64BitOperatingSystem) {
        Copy-Item "$env:TEMP\nssm_extracted\nssm-2.24\win64\nssm.exe" -Destination $NSSMExe -Force
    } else {
        Copy-Item "$env:TEMP\nssm_extracted\nssm-2.24\win32\nssm.exe" -Destination $NSSMExe -Force
    }
    Remove-Item $NSSMZip -Force
    Remove-Item "$env:TEMP\nssm_extracted" -Recurse -Force
}

# 5. Create Windows Service
$ServiceName = "BlackBoxDaemon"
Write-Host "Configuring Windows Service ($ServiceName)..."

# Stop and remove existing if present
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    Stop-Service -Name $ServiceName -Force
    & $NSSMExe remove $ServiceName confirm
}

# Install new service
& $NSSMExe install $ServiceName $PythonExec "$InstallDir\blackbox_daemon.py" "--start"
& $NSSMExe set $ServiceName AppDirectory $InstallDir
& $NSSMExe set $ServiceName DisplayName "Black Box Security Daemon"
& $NSSMExe set $ServiceName Description "Parental security suite enforcing ZAK-TRAP protocols."
& $NSSMExe set $ServiceName Start SERVICE_AUTO_START

# Configure DNS Sinkhole fallback (flushing cache)
Write-Host "Flushing DNS Cache to prepare for sinkhole interception..."
ipconfig /flushdns | Out-Null

Write-Host "`nInstallation Complete!" -ForegroundColor Green
Write-Host "Note: To test audio and notifications properly during development,"
Write-Host "do NOT start the service yet. Instead, run:" -ForegroundColor Yellow
Write-Host "python $InstallDir\blackbox_daemon.py --start" -ForegroundColor Yellow
Write-Host "`nTo run as a background service (no desktop popups):"
Write-Host "Start-Service $ServiceName"

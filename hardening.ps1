# ============================================================================
# Windows System Hardening Script
# ============================================================================
# This script implements comprehensive Windows security hardening measures
# including UAC, SmartScreen, services, scheduled tasks, and system policies.
#
# Requirements: Administrator privileges
# Usage: .\hardening.ps1
# ============================================================================

#Requires -RunAsAdministrator

param(
    [switch]$SkipUAC,
    [switch]$SkipServices,
    [switch]$SkipTasks,
    [switch]$SkipNetwork,
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"
$LogFile = "hardening-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogFile -Value $LogMessage
}

function Test-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check for administrator privileges
if (-not (Test-Admin)) {
    Write-Host "ERROR: This script requires Administrator privileges!" -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
    exit 1
}

Write-Log "Starting Windows System Hardening..." "INFO"
Write-Log "Log file: $LogFile" "INFO"

# ============================================================================
# 1. UAC Configuration - Set to Maximum Level
# ============================================================================
if (-not $SkipUAC) {
    Write-Log "Configuring UAC to maximum level..." "INFO"
    try {
        # Set UAC to always notify (highest level)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -ErrorAction Stop
        Write-Log "UAC configured to maximum level" "SUCCESS"
    } catch {
        Write-Log "Failed to configure UAC: $_" "ERROR"
    }
}

# ============================================================================
# 2. Windows SmartScreen Configuration
# ============================================================================
Write-Log "Enabling Windows SmartScreen..." "INFO"
try {
    # Enable SmartScreen for apps and files
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin" -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -ErrorAction Stop -Force
    Write-Log "SmartScreen enabled" "SUCCESS"
} catch {
    Write-Log "Failed to enable SmartScreen: $_" "ERROR"
}

# ============================================================================
# 3. Disable Autoplay
# ============================================================================
Write-Log "Disabling Autoplay..." "INFO"
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1 -ErrorAction Stop
    Write-Log "Autoplay disabled" "SUCCESS"
} catch {
    Write-Log "Failed to disable Autoplay: $_" "ERROR"
}

# ============================================================================
# 4. Screen Saver Lock Configuration
# ============================================================================
Write-Log "Configuring screen saver lock..." "INFO"
try {
    # Set screen saver timeout to 5 minutes and require password
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value 300 -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value 1 -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value 1 -ErrorAction Stop
    Write-Log "Screen saver lock configured (5 min timeout)" "SUCCESS"
} catch {
    Write-Log "Failed to configure screen saver: $_" "ERROR"
}

# ============================================================================
# 5. Disable Unnecessary Services
# ============================================================================
if (-not $SkipServices) {
    Write-Log "Disabling unnecessary services..." "INFO"
    $ServicesToDisable = @(
        "Telnet",                    # Telnet service
        "FTPSvc",                    # FTP Publishing Service
        "RemoteRegistry",            # Remote Registry
        "SSDPSRV",                   # SSDP Discovery (UPnP)
        "upnphost",                  # UPnP Device Host
        "W3SVC",                     # World Wide Web Publishing Service (if not needed)
        "XblAuthManager",            # Xbox Live Auth Manager (if not gaming)
        "XblGameSave",               # Xbox Live Game Save (if not gaming)
        "XboxGipSvc",                # Xbox Accessory Management Service
        "RemoteAccess",              # Routing and Remote Access
        "RemoteDesktopServices",     # Remote Desktop Services (if not needed)
        "WSearch"                    # Windows Search (optional - can impact performance)
    )
    
    foreach ($Service in $ServicesToDisable) {
        try {
            $svc = Get-Service -Name $Service -ErrorAction SilentlyContinue
            if ($svc) {
                if ($svc.Status -eq "Running") {
                    Stop-Service -Name $Service -Force -ErrorAction Stop
                    Write-Log "Stopped service: $Service" "INFO"
                }
                Set-Service -Name $Service -StartupType Disabled -ErrorAction Stop
                Write-Log "Disabled service: $Service" "SUCCESS"
            } else {
                Write-Log "Service not found: $Service (skipping)" "INFO"
            }
        } catch {
            Write-Log "Failed to disable service $Service : $_" "WARNING"
        }
    }
}

# ============================================================================
# 6. Remove/Disable Unnecessary Scheduled Tasks
# ============================================================================
if (-not $SkipTasks) {
    Write-Log "Disabling unnecessary scheduled tasks..." "INFO"
    $TasksToDisable = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Customer Experience Improvement Program\*",
        "\Microsoft\Windows\Windows Error Reporting\*"
    )
    
    foreach ($TaskPath in $TasksToDisable) {
        try {
            $tasks = Get-ScheduledTask -TaskPath $TaskPath -ErrorAction SilentlyContinue
            foreach ($task in $tasks) {
                Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
                Write-Log "Disabled scheduled task: $($task.TaskName)" "SUCCESS"
            }
        } catch {
            Write-Log "Failed to disable task $TaskPath : $_" "WARNING"
        }
    }
}

# ============================================================================
# 7. Network Adapter Hardening
# ============================================================================
if (-not $SkipNetwork) {
    Write-Log "Hardening network adapters..." "INFO"
    try {
        # Disable NetBIOS over TCP/IP
        $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        foreach ($adapter in $adapters) {
            Set-NetAdapterBinding -Name $adapter.Name -ComponentID "ms_tcpip6" -Enabled $false -ErrorAction SilentlyContinue
            Set-NetAdapterBinding -Name $adapter.Name -ComponentID "ms_netbios" -Enabled $false -ErrorAction SilentlyContinue
            Write-Log "Hardened network adapter: $($adapter.Name)" "SUCCESS"
        }
        
        # Disable LLMNR (Link-Local Multicast Name Resolution)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -ErrorAction SilentlyContinue -Force
        
        # Disable NetBIOS
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Value 2 -ErrorAction SilentlyContinue
        
        Write-Log "Network adapter hardening completed" "SUCCESS"
    } catch {
        Write-Log "Failed to harden network adapters: $_" "WARNING"
    }
}

# ============================================================================
# 8. Remove Shared Folders (if not needed)
# ============================================================================
Write-Log "Checking for shared folders..." "INFO"
try {
    $shares = Get-SmbShare | Where-Object {$_.Name -ne "ADMIN$" -and $_.Name -ne "C$" -and $_.Name -ne "IPC$"}
    foreach ($share in $shares) {
        Write-Log "Found shared folder: $($share.Name) at $($share.Path)" "WARNING"
        # Uncomment the next line to automatically remove shares (use with caution)
        # Remove-SmbShare -Name $share.Name -Force -ErrorAction Stop
    }
    if ($shares.Count -eq 0) {
        Write-Log "No unnecessary shared folders found" "SUCCESS"
    }
} catch {
    Write-Log "Failed to check shared folders: $_" "WARNING"
}

# ============================================================================
# 9. Disable Windows Features (if not needed)
# ============================================================================
Write-Log "Checking Windows features..." "INFO"
try {
    # Disable SMBv1 (legacy and insecure)
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue
    Write-Log "SMBv1 disabled (if present)" "SUCCESS"
} catch {
    Write-Log "Failed to disable SMBv1: $_" "WARNING"
}

# ============================================================================
# 10. Windows Defender Configuration
# ============================================================================
Write-Log "Verifying Windows Defender status..." "INFO"
try {
    $defenderStatus = Get-MpComputerStatus
    if ($defenderStatus.RealTimeProtectionEnabled) {
        Write-Log "Windows Defender is enabled and running" "SUCCESS"
    } else {
        Write-Log "WARNING: Windows Defender real-time protection is not enabled!" "WARNING"
        # Enable real-time protection
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Write-Log "Enabled Windows Defender real-time protection" "SUCCESS"
    }
    
    # Enable cloud protection
    Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
    Write-Log "Windows Defender cloud protection enabled" "SUCCESS"
} catch {
    Write-Log "Failed to configure Windows Defender: $_" "WARNING"
}

# ============================================================================
# 11. System Update Verification
# ============================================================================
Write-Log "Checking Windows Update status..." "INFO"
try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $searchResult = $updateSearcher.Search("IsInstalled=0")
    
    if ($searchResult.Updates.Count -gt 0) {
        Write-Log "WARNING: $($searchResult.Updates.Count) updates are available" "WARNING"
        Write-Log "Run 'Get-WindowsUpdate' or use Windows Update to install updates" "INFO"
    } else {
        Write-Log "System is up to date" "SUCCESS"
    }
} catch {
    Write-Log "Could not check update status: $_" "WARNING"
}

# ============================================================================
# 12. Hosts File Reset (to default)
# ============================================================================
Write-Log "Resetting hosts file to default..." "INFO"
try {
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $defaultHosts = @"
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
"@
    Set-Content -Path $hostsPath -Value $defaultHosts -Force -ErrorAction Stop
    Write-Log "Hosts file reset to default" "SUCCESS"
} catch {
    Write-Log "Failed to reset hosts file: $_" "ERROR"
}

# ============================================================================
# 13. OneDrive Removal (if requested)
# ============================================================================
Write-Log "Checking for OneDrive..." "INFO"
try {
    $onedrivePath = "$env:SystemRoot\System32\OneDriveSetup.exe"
    if (Test-Path $onedrivePath) {
        Write-Log "OneDrive found. To remove, run: $onedrivePath /uninstall" "INFO"
        # Uncomment to automatically remove OneDrive (use with caution)
        # & $onedrivePath /uninstall
    } else {
        Write-Log "OneDrive not found or already removed" "INFO"
    }
} catch {
    Write-Log "Failed to check OneDrive: $_" "WARNING"
}

Write-Log "Windows System Hardening completed!" "SUCCESS"
Write-Log "Review the log file: $LogFile" "INFO"
Write-Host "`nHardening script completed. Please review the log file for details." -ForegroundColor Green


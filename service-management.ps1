# ============================================================================
# Windows Service Management Script
# ============================================================================
# This script manages Windows services, disabling unnecessary and potentially
# dangerous services while ensuring critical services remain running.
#
# Requirements: Administrator privileges
# Usage: .\service-management.ps1 [-Disable] [-ListOnly]
# ============================================================================

#Requires -RunAsAdministrator

param(
    [switch]$Disable,
    [switch]$ListOnly
)

$ErrorActionPreference = "Continue"
$LogFile = "service-management-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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

Write-Log "Starting Windows Service Management..." "INFO"

# ============================================================================
# Services to Disable (Security Risk)
# ============================================================================
$ServicesToDisable = @(
    @{Name="Telnet"; Description="Telnet service - insecure remote access"},
    @{Name="FTPSvc"; Description="FTP Publishing Service - insecure file transfer"},
    @{Name="RemoteRegistry"; Description="Remote Registry - allows remote registry access"},
    @{Name="SSDPSRV"; Description="SSDP Discovery - UPnP service"},
    @{Name="upnphost"; Description="UPnP Device Host - UPnP service"},
    @{Name="W3SVC"; Description="World Wide Web Publishing Service - web server"},
    @{Name="XblAuthManager"; Description="Xbox Live Auth Manager - gaming service"},
    @{Name="XblGameSave"; Description="Xbox Live Game Save - gaming service"},
    @{Name="XboxGipSvc"; Description="Xbox Accessory Management Service"},
    @{Name="RemoteAccess"; Description="Routing and Remote Access"},
    @{Name="RemoteDesktopServices"; Description="Remote Desktop Services"},
    @{Name="WSearch"; Description="Windows Search - indexing service"},
    @{Name="Spooler"; Description="Print Spooler - if printers not needed"},
    @{Name="Themes"; Description="Themes service - if not using themes"},
    @{Name="TabletInputService"; Description="Tablet PC Input Service"},
    @{Name="WbioSrvc"; Description="Windows Biometric Service - if not using biometrics"}
)

# ============================================================================
# List Services
# ============================================================================
Write-Log "Analyzing services..." "INFO"

$serviceReport = @()

foreach ($svcInfo in $ServicesToDisable) {
    $svcName = $svcInfo.Name
    $svcDesc = $svcInfo.Description
    
    try {
        $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($service) {
            $serviceReport += [PSCustomObject]@{
                Name = $svcName
                DisplayName = $service.DisplayName
                Status = $service.Status
                StartType = (Get-CimInstance Win32_Service -Filter "Name='$svcName'").StartMode
                Description = $svcDesc
                Action = "Should Disable"
            }
            
            Write-Log "Found service: $svcName ($($service.DisplayName)) - Status: $($service.Status) - StartType: $((Get-CimInstance Win32_Service -Filter "Name='$svcName'").StartMode)" "INFO"
        } else {
            Write-Log "Service not found: $svcName (may not be installed)" "INFO"
        }
    } catch {
        Write-Log "Error checking service $svcName : $_" "WARNING"
    }
}

# Export service report
$serviceReport | Export-Csv -Path "service-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv" -NoTypeInformation
Write-Log "Service report exported to CSV" "SUCCESS"

if ($ListOnly) {
    Write-Host "`nService analysis complete. Review the CSV report for details." -ForegroundColor Green
    exit 0
}

# ============================================================================
# Disable Services
# ============================================================================
if ($Disable) {
    Write-Log "Disabling unnecessary services..." "INFO"
    
    foreach ($svcInfo in $ServicesToDisable) {
        $svcName = $svcInfo.Name
        
        try {
            $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($service) {
                # Stop the service if it's running
                if ($service.Status -eq "Running") {
                    Stop-Service -Name $svcName -Force -ErrorAction Stop
                    Write-Log "Stopped service: $svcName" "SUCCESS"
                }
                
                # Disable the service
                Set-Service -Name $svcName -StartupType Disabled -ErrorAction Stop
                Write-Log "Disabled service: $svcName" "SUCCESS"
            } else {
                Write-Log "Service not found: $svcName (skipping)" "INFO"
            }
        } catch {
            Write-Log "Failed to disable service $svcName : $_" "WARNING"
        }
    }
    
    Write-Log "Service management completed!" "SUCCESS"
} else {
    Write-Host "`nService analysis complete. Run with -Disable to apply changes." -ForegroundColor Yellow
    Write-Host "Review the service report CSV for details." -ForegroundColor Green
}


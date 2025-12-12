# ============================================================================
# Unauthorized Application Removal Script
# ============================================================================
# This script identifies and removes potentially dangerous or unauthorized
# applications including CCleaner, TeamViewer, Wireshark, Nmap, Ophcrack, Hashcat.
#
# Requirements: Administrator privileges
# Usage: .\app-removal.ps1 [-Remove] [-ListOnly]
# ============================================================================

#Requires -RunAsAdministrator

param(
    [switch]$Remove,
    [switch]$ListOnly
)

$ErrorActionPreference = "Continue"
$LogFile = "app-removal-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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

Write-Log "Starting Unauthorized Application Detection..." "INFO"

# ============================================================================
# Applications to Remove (Security Risk)
# ============================================================================
$AppsToRemove = @(
    @{Name="CCleaner"; Patterns=@("*CCleaner*", "*Piriform*"); Reason="Potentially unwanted software"},
    @{Name="TeamViewer"; Patterns=@("*TeamViewer*"); Reason="Remote access tool - security risk"},
    @{Name="Wireshark"; Patterns=@("*Wireshark*"); Reason="Network analysis tool - can be used maliciously"},
    @{Name="Nmap"; Patterns=@("*Nmap*", "*Zenmap*"); Reason="Network scanning tool - can be used maliciously"},
    @{Name="Ophcrack"; Patterns=@("*Ophcrack*"); Reason="Password cracking tool"},
    @{Name="Hashcat"; Patterns=@("*Hashcat*"); Reason="Password cracking tool"},
    @{Name="Metasploit"; Patterns=@("*Metasploit*"); Reason="Penetration testing framework"},
    @{Name="John the Ripper"; Patterns=@("*John*", "*JtR*"); Reason="Password cracking tool"},
    @{Name="Aircrack"; Patterns=@("*Aircrack*"); Reason="Wireless security tool"},
    @{Name="Cain & Abel"; Patterns=@("*Cain*", "*Abel*"); Reason="Password recovery tool"}
)

# ============================================================================
# Detect Installed Applications
# ============================================================================
Write-Log "Scanning for unauthorized applications..." "INFO"

$foundApps = @()

# Method 1: Check via Win32_Product (slower but comprehensive)
Write-Log "Checking installed programs via WMI..." "INFO"
try {
    $installedApps = Get-CimInstance Win32_Product | Select-Object Name, Version, Vendor, InstallDate
    
    foreach ($appInfo in $AppsToRemove) {
        foreach ($pattern in $appInfo.Patterns) {
            $matches = $installedApps | Where-Object {$_.Name -like $pattern}
            foreach ($match in $matches) {
                $foundApps += [PSCustomObject]@{
                    Name = $match.Name
                    Version = $match.Version
                    Vendor = $match.Vendor
                    InstallDate = $match.InstallDate
                    Reason = $appInfo.Reason
                    DetectionMethod = "WMI"
                }
                Write-Log "Found: $($match.Name) v$($match.Version) - $($appInfo.Reason)" "WARNING"
            }
        }
    }
} catch {
    Write-Log "Error checking WMI products: $_" "WARNING"
}

# Method 2: Check via Registry (faster)
Write-Log "Checking installed programs via Registry..." "INFO"
try {
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($regPath in $regPaths) {
        $regApps = Get-ItemProperty $regPath -ErrorAction SilentlyContinue | 
            Where-Object {$_.DisplayName -ne $null}
        
        foreach ($appInfo in $AppsToRemove) {
            foreach ($pattern in $appInfo.Patterns) {
                $matches = $regApps | Where-Object {$_.DisplayName -like $pattern}
                foreach ($match in $matches) {
                    # Avoid duplicates
                    if (-not ($foundApps | Where-Object {$_.Name -eq $match.DisplayName})) {
                        $foundApps += [PSCustomObject]@{
                            Name = $match.DisplayName
                            Version = $match.DisplayVersion
                            Vendor = $match.Publisher
                            InstallDate = $match.InstallDate
                            Reason = $appInfo.Reason
                            DetectionMethod = "Registry"
                            UninstallString = $match.UninstallString
                        }
                        Write-Log "Found: $($match.DisplayName) v$($match.DisplayVersion) - $($appInfo.Reason)" "WARNING"
                    }
                }
            }
        }
    }
} catch {
    Write-Log "Error checking registry: $_" "WARNING"
}

# Method 3: Check running processes
Write-Log "Checking running processes..." "INFO"
try {
    $processes = Get-Process | Select-Object ProcessName, Path
    
    foreach ($appInfo in $AppsToRemove) {
        foreach ($pattern in $appInfo.Patterns) {
            $matches = $processes | Where-Object {
                $_.ProcessName -like $pattern -or 
                ($_.Path -and $_.Path -like "*$pattern*")
            }
            foreach ($match in $matches) {
                Write-Log "WARNING: Process running: $($match.ProcessName) from $($match.Path)" "WARNING"
            }
        }
    }
} catch {
    Write-Log "Error checking processes: $_" "WARNING"
}

# Export findings
if ($foundApps.Count -gt 0) {
    $foundApps | Export-Csv -Path "unauthorized-apps-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv" -NoTypeInformation
    Write-Log "Found $($foundApps.Count) unauthorized applications" "WARNING"
    Write-Log "Report exported to CSV" "SUCCESS"
} else {
    Write-Log "No unauthorized applications found" "SUCCESS"
}

if ($ListOnly) {
    Write-Host "`nApplication scan complete. Review the CSV report for details." -ForegroundColor Green
    exit 0
}

# ============================================================================
# Remove Applications
# ============================================================================
if ($Remove) {
    Write-Log "Removing unauthorized applications..." "INFO"
    
    foreach ($app in $foundApps) {
        Write-Log "Attempting to remove: $($app.Name)..." "INFO"
        
        # Try using UninstallString from registry
        if ($app.UninstallString) {
            try {
                # Extract the uninstall command
                $uninstallCmd = $app.UninstallString
                if ($uninstallCmd -match '^"(.+)"') {
                    $exe = $matches[1]
                    $args = $uninstallCmd.Substring($matches[0].Length).Trim()
                    Start-Process -FilePath $exe -ArgumentList "/S", "/quiet" -Wait -ErrorAction Stop
                    Write-Log "Removed: $($app.Name)" "SUCCESS"
                } else {
                    # Try silent uninstall
                    Start-Process -FilePath $uninstallCmd -ArgumentList "/S", "/quiet" -Wait -ErrorAction Stop
                    Write-Log "Removed: $($app.Name)" "SUCCESS"
                }
            } catch {
                Write-Log "Failed to remove $($app.Name) via uninstall string: $_" "WARNING"
                
                # Try using WMI
                try {
                    $product = Get-CimInstance Win32_Product | Where-Object {$_.Name -eq $app.Name}
                    if ($product) {
                        $product | Invoke-CimMethod -MethodName Uninstall | Out-Null
                        Write-Log "Removed: $($app.Name) via WMI" "SUCCESS"
                    }
                } catch {
                    Write-Log "Failed to remove $($app.Name) via WMI: $_" "ERROR"
                    Write-Log "Manual removal may be required for: $($app.Name)" "WARNING"
                }
            }
        } else {
            Write-Log "No uninstall string found for: $($app.Name)" "WARNING"
            Write-Log "Manual removal may be required" "INFO"
        }
    }
    
    Write-Log "Application removal completed!" "SUCCESS"
} else {
    Write-Host "`nApplication scan complete. Run with -Remove to uninstall found applications." -ForegroundColor Yellow
    Write-Host "Review the CSV report for details." -ForegroundColor Green
}


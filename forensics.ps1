# ============================================================================
# Windows Forensics and Log Collection Script
# ============================================================================
# This script collects forensic data including logs, process information,
# hash calculations, file ownership, and suspicious activity detection.
#
# Requirements: Administrator privileges (for some operations)
# Usage: .\forensics.ps1 [-OutputDir <path>]
# ============================================================================

param(
    [string]$OutputDir = "forensics-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    [switch]$CollectLogs,
    [switch]$DetectProcesses,
    [switch]$CalculateHashes,
    [switch]$FileOwnership,
    [switch]$MemoryDump,
    [switch]$All
)

$ErrorActionPreference = "Continue"

# If -All is specified, enable all checks
if ($All) {
    $CollectLogs = $true
    $DetectProcesses = $true
    $CalculateHashes = $true
    $FileOwnership = $true
    $MemoryDump = $true
}

# If no specific option is provided, run all
if (-not ($CollectLogs -or $DetectProcesses -or $CalculateHashes -or $FileOwnership -or $MemoryDump)) {
    $CollectLogs = $true
    $DetectProcesses = $true
    $CalculateHashes = $true
    $FileOwnership = $true
    $MemoryDump = $false  # Memory dump is optional and resource-intensive
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$LogFile = Join-Path $OutputDir "forensics.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogFile -Value $LogMessage
}

Write-Log "Starting Windows Forensics Collection..." "INFO"
Write-Log "Output directory: $OutputDir" "INFO"

# ============================================================================
# 1. Log Collection
# ============================================================================
if ($CollectLogs) {
    Write-Log "Collecting system logs..." "INFO"
    try {
        $logDir = Join-Path $OutputDir "logs"
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        
        # Export Windows Event Logs
        $eventLogs = @("System", "Application", "Security", "Windows PowerShell")
        foreach ($logName in $eventLogs) {
            try {
                $logFile = Join-Path $logDir "$logName.evtx"
                wevtutil epl $logName $logFile
                Write-Log "Exported log: $logName" "SUCCESS"
            } catch {
                Write-Log "Failed to export $logName : $_" "WARNING"
            }
        }
        
        # Export recent security events (last 7 days)
        $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue
        $securityEvents | Export-Csv -Path (Join-Path $logDir "security-events.csv") -NoTypeInformation
        Write-Log "Exported security events (last 7 days)" "SUCCESS"
        
        # Export failed login attempts
        $failedLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 100 -ErrorAction SilentlyContinue
        $failedLogins | Export-Csv -Path (Join-Path $logDir "failed-logins.csv") -NoTypeInformation
        Write-Log "Exported failed login attempts" "SUCCESS"
        
    } catch {
        Write-Log "Error collecting logs: $_" "ERROR"
    }
}

# ============================================================================
# 2. Suspicious Process Detection
# ============================================================================
if ($DetectProcesses) {
    Write-Log "Detecting suspicious processes..." "INFO"
    try {
        $processDir = Join-Path $OutputDir "processes"
        New-Item -ItemType Directory -Path $processDir -Force | Out-Null
        
        # Get all running processes with details
        $processes = Get-Process | Select-Object Id, ProcessName, Path, StartTime, CPU, WorkingSet, 
            @{Name="ParentId";Expression={(Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)").ParentProcessId}},
            @{Name="CommandLine";Expression={(Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine}}
        
        $processes | Export-Csv -Path (Join-Path $processDir "all-processes.csv") -NoTypeInformation
        Write-Log "Exported all running processes" "SUCCESS"
        
        # Detect processes with no path (suspicious)
        $suspiciousProcesses = $processes | Where-Object {$_.Path -eq $null -or $_.Path -eq ""}
        if ($suspiciousProcesses) {
            $suspiciousProcesses | Export-Csv -Path (Join-Path $processDir "suspicious-processes.csv") -NoTypeInformation
            Write-Log "WARNING: Found $($suspiciousProcesses.Count) processes with no path!" "WARNING"
        }
        
        # Detect processes running from temp directories
        $tempProcesses = $processes | Where-Object {
            $_.Path -and (
                $_.Path -like "*\Temp\*" -or 
                $_.Path -like "*\AppData\Local\Temp\*" -or
                $_.Path -like "*\Windows\Temp\*"
            )
        }
        if ($tempProcesses) {
            $tempProcesses | Export-Csv -Path (Join-Path $processDir "temp-processes.csv") -NoTypeInformation
            Write-Log "WARNING: Found $($tempProcesses.Count) processes running from temp directories!" "WARNING"
        }
        
        # Network connections
        $connections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
        $connections | Export-Csv -Path (Join-Path $processDir "network-connections.csv") -NoTypeInformation
        Write-Log "Exported network connections" "SUCCESS"
        
    } catch {
        Write-Log "Error detecting processes: $_" "ERROR"
    }
}

# ============================================================================
# 3. Hash Calculations (MD5, SHA256)
# ============================================================================
if ($CalculateHashes) {
    Write-Log "Calculating file hashes..." "INFO"
    try {
        $hashDir = Join-Path $OutputDir "hashes"
        New-Item -ItemType Directory -Path $hashDir -Force | Out-Null
        
        # Calculate hashes for critical system files
        $criticalPaths = @(
            "$env:SystemRoot\System32\kernel32.dll",
            "$env:SystemRoot\System32\ntdll.dll",
            "$env:SystemRoot\System32\winlogon.exe",
            "$env:SystemRoot\System32\lsass.exe"
        )
        
        $hashResults = @()
        foreach ($filePath in $criticalPaths) {
            if (Test-Path $filePath) {
                try {
                    $fileHash = Get-FileHash -Path $filePath -Algorithm SHA256
                    $md5Hash = Get-FileHash -Path $filePath -Algorithm MD5
                    $hashResults += [PSCustomObject]@{
                        File = $filePath
                        MD5 = $md5Hash.Hash
                        SHA256 = $fileHash.Hash
                        Size = (Get-Item $filePath).Length
                        LastModified = (Get-Item $filePath).LastWriteTime
                    }
                    Write-Log "Calculated hash for: $filePath" "SUCCESS"
                } catch {
                    Write-Log "Failed to calculate hash for $filePath : $_" "WARNING"
                }
            }
        }
        
        $hashResults | Export-Csv -Path (Join-Path $hashDir "system-file-hashes.csv") -NoTypeInformation
        Write-Log "Exported file hashes" "SUCCESS"
        
    } catch {
        Write-Log "Error calculating hashes: $_" "ERROR"
    }
}

# ============================================================================
# 4. File Ownership Lookup
# ============================================================================
if ($FileOwnership) {
    Write-Log "Collecting file ownership information..." "INFO"
    try {
        $ownershipDir = Join-Path $OutputDir "ownership"
        New-Item -ItemType Directory -Path $ownershipDir -Force | Out-Null
        
        # Check ownership of critical directories
        $criticalDirs = @(
            "$env:SystemRoot\System32",
            "$env:SystemRoot\SysWOW64",
            "$env:ProgramFiles",
            "$env:ProgramData"
        )
        
        $ownershipResults = @()
        foreach ($dir in $criticalDirs) {
            if (Test-Path $dir) {
                try {
                    $acl = Get-Acl $dir
                    $ownershipResults += [PSCustomObject]@{
                        Path = $dir
                        Owner = $acl.Owner
                        Group = $acl.Group
                        AccessRules = ($acl.Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join "; "
                    }
                } catch {
                    Write-Log "Failed to get ownership for $dir : $_" "WARNING"
                }
            }
        }
        
        $ownershipResults | Export-Csv -Path (Join-Path $ownershipDir "directory-ownership.csv") -NoTypeInformation
        Write-Log "Exported ownership information" "SUCCESS"
        
    } catch {
        Write-Log "Error collecting ownership: $_" "ERROR"
    }
}

# ============================================================================
# 5. Memory Dump Analysis (Optional - Resource Intensive)
# ============================================================================
if ($MemoryDump) {
    Write-Log "WARNING: Memory dump collection is resource-intensive..." "WARNING"
    Write-Log "This feature requires additional tools (e.g., WinPmem)" "INFO"
    # Memory dump collection typically requires specialized tools
    # This is a placeholder for integration with tools like WinPmem or DumpIt
}

# ============================================================================
# 6. Caesar Cipher Decoding Utility Function
# ============================================================================
function Decode-CaesarCipher {
    param(
        [string]$CipherText,
        [int]$Shift = 0
    )
    
    if ($Shift -eq 0) {
        # Try all shifts (0-25)
        $results = @()
        for ($s = 0; $s -lt 26; $s++) {
            $decoded = ""
            foreach ($char in $CipherText.ToCharArray()) {
                if ($char -match '[a-zA-Z]') {
                    $base = if ($char -cmatch '[a-z]') { [int][char]'a' } else { [int][char]'A' }
                    $decoded += [char]((([int][char]$char - $base - $s + 26) % 26) + $base)
                } else {
                    $decoded += $char
                }
            }
            $results += [PSCustomObject]@{
                Shift = $s
                Decoded = $decoded
            }
        }
        return $results
    } else {
        $decoded = ""
        foreach ($char in $CipherText.ToCharArray()) {
            if ($char -match '[a-zA-Z]') {
                $base = if ($char -cmatch '[a-z]') { [int][char]'a' } else { [int][char]'A' }
                $decoded += [char]((([int][char]$char - $base - $Shift + 26) % 26) + $base)
            } else {
                $decoded += $char
            }
        }
        return $decoded
    }
}

# Export the function for use
Write-Log "Caesar cipher decoder function available" "INFO"
Write-Log "Usage: Decode-CaesarCipher -CipherText 'Khoor' -Shift 3" "INFO"

# ============================================================================
# 7. Additional Forensic Checks
# ============================================================================
Write-Log "Performing additional forensic checks..." "INFO"
try {
    $additionalDir = Join-Path $OutputDir "additional"
    New-Item -ItemType Directory -Path $additionalDir -Force | Out-Null
    
    # Startup programs
    $startup = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
    $startup | Export-Csv -Path (Join-Path $additionalDir "startup-programs.csv") -NoTypeInformation
    Write-Log "Exported startup programs" "SUCCESS"
    
    # Installed software
    $software = Get-CimInstance Win32_Product | Select-Object Name, Version, Vendor, InstallDate
    $software | Export-Csv -Path (Join-Path $additionalDir "installed-software.csv") -NoTypeInformation
    Write-Log "Exported installed software" "SUCCESS"
    
    # Scheduled tasks
    $tasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State, @{Name="LastRunTime";Expression={(Get-ScheduledTaskInfo $_.TaskName).LastRunTime}}
    $tasks | Export-Csv -Path (Join-Path $additionalDir "scheduled-tasks.csv") -NoTypeInformation
    Write-Log "Exported scheduled tasks" "SUCCESS"
    
    # User accounts
    $users = Get-CimInstance Win32_UserAccount | Select-Object Name, SID, Disabled, Lockout, PasswordRequired
    $users | Export-Csv -Path (Join-Path $additionalDir "user-accounts.csv") -NoTypeInformation
    Write-Log "Exported user accounts" "SUCCESS"
    
    # System information
    $systemInfo = Get-CimInstance Win32_ComputerSystem | Select-Object Name, Manufacturer, Model, TotalPhysicalMemory
    $systemInfo | Export-Csv -Path (Join-Path $additionalDir "system-info.csv") -NoTypeInformation
    Write-Log "Exported system information" "SUCCESS"
    
} catch {
    Write-Log "Error in additional checks: $_" "ERROR"
}

Write-Log "Forensics collection completed!" "SUCCESS"
Write-Log "All data saved to: $OutputDir" "INFO"
Write-Host "`nForensics collection completed. Data saved to: $OutputDir" -ForegroundColor Green


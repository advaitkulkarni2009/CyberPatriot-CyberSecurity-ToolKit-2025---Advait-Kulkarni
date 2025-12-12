# ============================================================================
# Windows Firewall Verification and Configuration Script
# ============================================================================
# This script verifies Windows Firewall status, checks rules, and ensures
# proper firewall configuration for security hardening.
#
# Requirements: Administrator privileges
# Usage: .\firewall-check.ps1 [-Enable] [-VerifyOnly]
# ============================================================================

#Requires -RunAsAdministrator

param(
    [switch]$Enable,
    [switch]$VerifyOnly
)

$ErrorActionPreference = "Continue"
$LogFile = "firewall-check-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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

Write-Log "Starting Windows Firewall Verification..." "INFO"

# ============================================================================
# 1. Check Firewall Status
# ============================================================================
Write-Log "Checking Windows Firewall status..." "INFO"

try {
    $firewallProfiles = Get-NetFirewallProfile
    
    foreach ($profile in $firewallProfiles) {
        $profileName = $profile.Name
        $enabled = $profile.Enabled
        $defaultInbound = $profile.DefaultInboundAction
        $defaultOutbound = $profile.DefaultOutboundAction
        
        Write-Log "Profile: $profileName" "INFO"
        Write-Log "  Enabled: $enabled" "INFO"
        Write-Log "  Default Inbound Action: $defaultInbound" "INFO"
        Write-Log "  Default Outbound Action: $defaultOutbound" "INFO"
        
        if (-not $enabled) {
            Write-Log "WARNING: Firewall is DISABLED for $profileName profile!" "WARNING"
            if ($Enable) {
                Set-NetFirewallProfile -Name $profileName -Enabled True
                Write-Log "Enabled firewall for $profileName profile" "SUCCESS"
            }
        } else {
            Write-Log "Firewall is enabled for $profileName profile" "SUCCESS"
        }
        
        # Verify default actions are set to Block for inbound
        if ($defaultInbound -ne "Block") {
            Write-Log "WARNING: Default inbound action is not Block for $profileName!" "WARNING"
            if ($Enable) {
                Set-NetFirewallProfile -Name $profileName -DefaultInboundAction Block
                Write-Log "Set default inbound action to Block for $profileName" "SUCCESS"
            }
        }
    }
} catch {
    Write-Log "Error checking firewall status: $_" "ERROR"
}

# ============================================================================
# 2. Check Firewall Rules
# ============================================================================
Write-Log "Analyzing firewall rules..." "INFO"

try {
    $allRules = Get-NetFirewallRule
    
    Write-Log "Total firewall rules: $($allRules.Count)" "INFO"
    
    # Categorize rules
    $enabledRules = $allRules | Where-Object {$_.Enabled -eq $true}
    $disabledRules = $allRules | Where-Object {$_.Enabled -eq $false}
    
    Write-Log "Enabled rules: $($enabledRules.Count)" "INFO"
    Write-Log "Disabled rules: $($disabledRules.Count)" "INFO"
    
    # Check for potentially dangerous rules (allowing inbound connections)
    $dangerousRules = $enabledRules | Where-Object {
        $_.Direction -eq "Inbound" -and 
        $_.Action -eq "Allow" -and
        $_.Profile -match "Domain|Private|Public"
    }
    
    if ($dangerousRules) {
        Write-Log "WARNING: Found $($dangerousRules.Count) potentially dangerous inbound allow rules" "WARNING"
        
        # List dangerous rules
        foreach ($rule in $dangerousRules | Select-Object -First 10) {
            Write-Log "  Rule: $($rule.DisplayName) - Direction: $($rule.Direction) - Action: $($rule.Action)" "WARNING"
        }
    }
    
    # Export rules to CSV for analysis
    $rulesExport = $allRules | Select-Object DisplayName, Enabled, Direction, Action, Profile, 
        @{Name="LocalPort";Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).LocalPort}},
        @{Name="RemotePort";Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).RemotePort}},
        @{Name="Protocol";Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).Protocol}}
    
    $rulesExport | Export-Csv -Path "firewall-rules-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv" -NoTypeInformation
    Write-Log "Exported firewall rules to CSV" "SUCCESS"
    
} catch {
    Write-Log "Error analyzing firewall rules: $_" "ERROR"
}

# ============================================================================
# 3. Check for Common Vulnerable Ports
# ============================================================================
Write-Log "Checking for common vulnerable ports..." "INFO"

$vulnerablePorts = @{
    21 = "FTP"
    23 = "Telnet"
    135 = "RPC"
    139 = "NetBIOS"
    445 = "SMB"
    3389 = "RDP"
    5985 = "WinRM HTTP"
    5986 = "WinRM HTTPS"
}

try {
    $listeningPorts = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | 
        Select-Object LocalPort -Unique
    
    foreach ($port in $listeningPorts) {
        $portNum = $port.LocalPort
        if ($vulnerablePorts.ContainsKey($portNum)) {
            $service = $vulnerablePorts[$portNum]
            Write-Log "WARNING: Port $portNum ($service) is listening!" "WARNING"
            
            # Check if there's a firewall rule allowing this port
            $portRules = Get-NetFirewallRule | Get-NetFirewallPortFilter | 
                Where-Object {$_.LocalPort -eq $portNum -and $_.Protocol -eq "TCP"}
            
            if ($portRules) {
                Write-Log "  Firewall rules exist for port $portNum" "INFO"
            } else {
                Write-Log "  No firewall rules found for port $portNum" "WARNING"
            }
        }
    }
} catch {
    Write-Log "Error checking vulnerable ports: $_" "ERROR"
}

# ============================================================================
# 4. Verify Firewall Logging
# ============================================================================
Write-Log "Checking firewall logging..." "INFO"

try {
    $profiles = @("Domain", "Private", "Public")
    foreach ($profileName in $profiles) {
        $logging = Get-NetFirewallProfile -Name $profileName | Select-Object LogFileName, LogMaxSizeKilobytes, LogAllowed, LogBlocked
        
        Write-Log "Profile: $profileName" "INFO"
        Write-Log "  Log File: $($logging.LogFileName)" "INFO"
        Write-Log "  Log Max Size: $($logging.LogMaxSizeKilobytes) KB" "INFO"
        Write-Log "  Log Allowed: $($logging.LogAllowed)" "INFO"
        Write-Log "  Log Blocked: $($logging.LogBlocked)" "INFO"
        
        # Recommend enabling logging for blocked connections
        if (-not $logging.LogBlocked) {
            Write-Log "  Recommendation: Enable logging for blocked connections" "INFO"
            if ($Enable) {
                Set-NetFirewallProfile -Name $profileName -LogBlocked True
                Write-Log "  Enabled logging for blocked connections" "SUCCESS"
            }
        }
    }
} catch {
    Write-Log "Error checking firewall logging: $_" "ERROR"
}

# ============================================================================
# 5. Create Recommended Firewall Rules (if enabled)
# ============================================================================
if ($Enable) {
    Write-Log "Creating recommended firewall rules..." "INFO"
    
    try {
        # Block common attack ports (if not already blocked)
        $blockPorts = @(135, 139, 445)  # RPC, NetBIOS, SMB
        
        foreach ($port in $blockPorts) {
            $ruleName = "Block-Port-$port-Inbound"
            $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            
            if (-not $existingRule) {
                New-NetFirewallRule -DisplayName $ruleName `
                    -Direction Inbound `
                    -LocalPort $port `
                    -Protocol TCP `
                    -Action Block `
                    -Profile Any `
                    -ErrorAction SilentlyContinue | Out-Null
                Write-Log "Created firewall rule: $ruleName" "SUCCESS"
            }
        }
    } catch {
        Write-Log "Error creating firewall rules: $_" "WARNING"
    }
}

# ============================================================================
# 6. Summary
# ============================================================================
Write-Log "Firewall verification completed!" "SUCCESS"

if ($VerifyOnly) {
    Write-Host "`nVerification complete. Review the log file for details." -ForegroundColor Green
    Write-Host "Run with -Enable to apply recommended configurations." -ForegroundColor Yellow
} else {
    Write-Host "`nFirewall check completed. Review the log file for details." -ForegroundColor Green
}


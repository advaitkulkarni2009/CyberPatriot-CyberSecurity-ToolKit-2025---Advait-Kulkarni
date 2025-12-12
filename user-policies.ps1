# ============================================================================
# Windows User Policies and Auditing Script
# ============================================================================
# This script configures user account policies, password policies, account
# lockout policies, and enables auditing for security events.
# Note: Some settings require secpol.msc (Local Security Policy) or Group Policy.
#
# Requirements: Administrator privileges
# Usage: .\user-policies.ps1 [-ApplyPolicies] [-EnableAuditing]
# ============================================================================

#Requires -RunAsAdministrator

param(
    [switch]$ApplyPolicies,
    [switch]$EnableAuditing
)

$ErrorActionPreference = "Continue"
$LogFile = "user-policies-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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

Write-Log "Starting User Policies Configuration..." "INFO"

# ============================================================================
# 1. Password Policy Configuration
# ============================================================================
Write-Log "Configuring password policies..." "INFO"

# Password policies are typically set via Local Security Policy (secpol.msc)
# or Group Policy. We'll use secedit.exe to apply policies via INF file.

if ($ApplyPolicies) {
    Write-Log "Applying password policies via secedit..." "INFO"
    
    # Create temporary INF file for password policies
    $infContent = @"
[Version]
Signature=`"`$CHICAGO`$`"
Revision=1

[System Access]
; Minimum password age (days)
MinimumPasswordAge = 1
; Maximum password age (days) - 90 days recommended
MaximumPasswordAge = 90
; Minimum password length - 14 characters recommended
MinimumPasswordLength = 14
; Password complexity requirements (1 = enabled)
PasswordComplexity = 1
; Password history - remember last 24 passwords
PasswordHistorySize = 24
; Clear text passwords (0 = disabled)
ClearTextPassword = 0

[Account Lockout]
; Account lockout duration (minutes) - 30 minutes
LockoutDuration = 30
; Account lockout threshold - 5 failed attempts
LockoutBadCount = 5
; Reset lockout counter after (minutes) - 30 minutes
ResetLockoutCount = 30
"@
    
    $infFile = "$env:TEMP\password-policy.inf"
    Set-Content -Path $infFile -Value $infContent -Force
    
    try {
        # Apply the policy
        secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $infFile /areas SECURITYPOLICY | Out-Null
        Write-Log "Password policies applied successfully" "SUCCESS"
        Remove-Item $infFile -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Failed to apply password policies: $_" "ERROR"
        Write-Log "You may need to configure these manually via secpol.msc" "WARNING"
    }
} else {
    Write-Log "Password policy recommendations:" "INFO"
    Write-Log "  - Minimum password length: 14 characters" "INFO"
    Write-Log "  - Password complexity: Enabled" "INFO"
    Write-Log "  - Password history: 24 passwords" "INFO"
    Write-Log "  - Maximum password age: 90 days" "INFO"
    Write-Log "  - Minimum password age: 1 day" "INFO"
    Write-Log "Run with -ApplyPolicies to apply these settings" "INFO"
}

# ============================================================================
# 2. Account Lockout Policy
# ============================================================================
Write-Log "Configuring account lockout policies..." "INFO"

if ($ApplyPolicies) {
    try {
        # Set account lockout threshold (5 failed attempts)
        $lockoutPolicy = "net accounts /lockoutthreshold:5"
        Invoke-Expression $lockoutPolicy
        Write-Log "Account lockout threshold set to 5 failed attempts" "SUCCESS"
        
        # Set lockout duration (30 minutes)
        $lockoutDuration = "net accounts /lockoutduration:30"
        Invoke-Expression $lockoutDuration
        Write-Log "Account lockout duration set to 30 minutes" "SUCCESS"
        
        # Set lockout observation window (30 minutes)
        $lockoutWindow = "net accounts /lockoutwindow:30"
        Invoke-Expression $lockoutWindow
        Write-Log "Account lockout window set to 30 minutes" "SUCCESS"
    } catch {
        Write-Log "Failed to configure account lockout: $_" "ERROR"
    }
} else {
    Write-Log "Account lockout policy recommendations:" "INFO"
    Write-Log "  - Lockout threshold: 5 failed attempts" "INFO"
    Write-Log "  - Lockout duration: 30 minutes" "INFO"
    Write-Log "  - Lockout window: 30 minutes" "INFO"
}

# ============================================================================
# 3. Enable Auditing
# ============================================================================
Write-Log "Configuring auditing policies..." "INFO"

if ($EnableAuditing) {
    try {
        # Enable audit policy via auditpol.exe
        # Audit account logon events (success and failure)
        auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
        Write-Log "Enabled auditing for logon/logoff events" "SUCCESS"
        
        # Audit account management (success and failure)
        auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
        Write-Log "Enabled auditing for account management" "SUCCESS"
        
        # Audit policy change (success and failure)
        auditpol /set /category:"Policy Change" /success:enable /failure:enable | Out-Null
        Write-Log "Enabled auditing for policy changes" "SUCCESS"
        
        # Audit privilege use (success and failure)
        auditpol /set /category:"Privilege Use" /success:enable /failure:enable | Out-Null
        Write-Log "Enabled auditing for privilege use" "SUCCESS"
        
        # Audit system events (success and failure)
        auditpol /set /category:"System" /success:enable /failure:enable | Out-Null
        Write-Log "Enabled auditing for system events" "SUCCESS"
        
        # Audit object access (optional - can be verbose)
        # auditpol /set /category:"Object Access" /success:enable /failure:enable
        
        Write-Log "Auditing policies configured successfully" "SUCCESS"
    } catch {
        Write-Log "Failed to configure auditing: $_" "ERROR"
        Write-Log "You may need to configure these manually via secpol.msc or gpedit.msc" "WARNING"
    }
} else {
    Write-Log "Auditing policy recommendations:" "INFO"
    Write-Log "  - Audit account logon events: Success and Failure" "INFO"
    Write-Log "  - Audit account management: Success and Failure" "INFO"
    Write-Log "  - Audit policy change: Success and Failure" "INFO"
    Write-Log "  - Audit privilege use: Success and Failure" "INFO"
    Write-Log "  - Audit system events: Success and Failure" "INFO"
    Write-Log "Run with -EnableAuditing to apply these settings" "INFO"
}

# ============================================================================
# 4. User Account Analysis
# ============================================================================
Write-Log "Analyzing user accounts..." "INFO"

try {
    $users = Get-CimInstance Win32_UserAccount | Where-Object {$_.LocalAccount -eq $true}
    
    Write-Log "Found $($users.Count) local user accounts" "INFO"
    
    $userReport = @()
    foreach ($user in $users) {
        $userReport += [PSCustomObject]@{
            Name = $user.Name
            SID = $user.SID
            Disabled = $user.Disabled
            Lockout = $user.Lockout
            PasswordRequired = $user.PasswordRequired
            AccountType = $user.AccountType
        }
        
        if ($user.Disabled -eq $false) {
            Write-Log "Active user: $($user.Name)" "INFO"
        }
        
        if ($user.PasswordRequired -eq $false) {
            Write-Log "WARNING: User $($user.Name) does not require a password!" "WARNING"
        }
    }
    
    $userReport | Export-Csv -Path "user-accounts-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv" -NoTypeInformation
    Write-Log "User account report exported to CSV" "SUCCESS"
    
} catch {
    Write-Log "Error analyzing user accounts: $_" "ERROR"
}

# ============================================================================
# 5. Group Policy Recommendations
# ============================================================================
Write-Log "Group Policy recommendations:" "INFO"
Write-Log "  - Open gpedit.msc (Local Group Policy Editor)" "INFO"
Write-Log "  - Navigate to: Computer Configuration > Windows Settings > Security Settings" "INFO"
Write-Log "  - Configure Account Policies, Local Policies, and Audit Policies" "INFO"
Write-Log "  - For domain environments, use Group Policy Management Console (gpmc.msc)" "INFO"

# ============================================================================
# 6. Summary
# ============================================================================
Write-Log "User Policies Configuration completed!" "SUCCESS"

if (-not $ApplyPolicies -and -not $EnableAuditing) {
    Write-Host "`nPolicy analysis complete. Review the log file for recommendations." -ForegroundColor Green
    Write-Host "Run with -ApplyPolicies to apply password and lockout policies." -ForegroundColor Yellow
    Write-Host "Run with -EnableAuditing to enable auditing policies." -ForegroundColor Yellow
} else {
    Write-Host "`nUser policies configuration completed. Review the log file for details." -ForegroundColor Green
}


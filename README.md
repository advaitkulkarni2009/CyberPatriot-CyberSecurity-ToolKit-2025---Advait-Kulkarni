# Cybersecurity Hardening Toolkit

A comprehensive, modular toolkit for hardening Windows and Linux systems with automated scripts, forensic tools, and security best practices.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Windows Scripts](#windows-scripts)
- [Linux Scripts](#linux-scripts)
- [Usage Guide](#usage-guide)
- [Modular Structure](#modular-structure)
- [Safety & Best Practices](#safety--best-practices)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

This toolkit provides automated security hardening for both Windows and Linux systems. All scripts are modular, well-commented, and designed to be safe to run multiple times (idempotent). Each script can be executed independently, allowing you to apply specific hardening measures as needed.

### Key Principles

- **Modularity**: Each feature is in a separate script
- **Safety**: Scripts check for prerequisites and provide warnings
- **Idempotency**: Safe to run multiple times
- **Comprehensive Logging**: All actions are logged with timestamps
- **Documentation**: Extensive comments explain each command

## ✨ Features

### Windows Features

- ✅ UAC configuration (maximum level)
- ✅ Windows SmartScreen enablement
- ✅ Autoplay disablement
- ✅ Screen saver lock configuration
- ✅ Service management (disable unnecessary services)
- ✅ Scheduled task cleanup
- ✅ Network adapter hardening
- ✅ Shared folder removal
- ✅ SMBv1 disablement
- ✅ Windows Defender verification and configuration
- ✅ System update verification
- ✅ Hosts file reset to default
- ✅ OneDrive removal option
- ✅ Browser hardening (Firefox & Chrome)
- ✅ Firewall verification and configuration
- ✅ User account policies (password, lockout)
- ✅ Account auditing (success/failure)
- ✅ Forensics and log collection
- ✅ Unauthorized application removal

### Linux Features

- ✅ System updates
- ✅ Firewall configuration (UFW, firewalld, iptables)
- ✅ Service management
- ✅ File permission hardening
- ✅ SSH hardening
- ✅ Kernel hardening parameters
- ✅ Network protocol disablement
- ✅ Logging configuration
- ✅ Fail2ban integration
- ✅ Forensics and log collection
- ✅ Hash calculations (MD5, SHA256)
- ✅ Process detection
- ✅ File ownership analysis

## 📦 Requirements

### Windows

- **OS**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: Version 5.1 or later
- **Privileges**: Administrator privileges (required for most scripts)
- **Execution Policy**: May need to set `Set-ExecutionPolicy RemoteSigned`

### Linux

- **OS**: Ubuntu, Debian, CentOS, RHEL, Fedora, or Arch-based distributions
- **Shell**: Bash 4.0+
- **Privileges**: Root privileges (sudo) for most operations
- **Tools**: Standard system utilities (varies by distribution)

## 🚀 Installation

### Clone or Download

```bash
git clone <repository-url>
cd cybersecurity-hardening-toolkit
```

Or download and extract the ZIP file.

### Windows Setup

1. Open PowerShell as Administrator
2. Navigate to the toolkit directory:
   ```powershell
   cd path\to\cybersecurity-hardening-toolkit\windows
   ```
3. Set execution policy (if needed):
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

### Linux Setup

1. Navigate to the toolkit directory:
   ```bash
   cd cybersecurity-hardening-toolkit/linux
   ```
2. Make scripts executable:
   ```bash
   chmod +x *.sh
   ```

## 📖 Windows Scripts

### 1. `hardening.ps1` - Main Hardening Script

Comprehensive system hardening including UAC, SmartScreen, services, and more.

**Usage:**
```powershell
# Run all hardening measures
.\hardening.ps1

# Skip specific sections
.\hardening.ps1 -SkipUAC -SkipServices
```

**Features:**
- UAC to maximum level
- SmartScreen enablement
- Autoplay disablement
- Screen saver lock (5 min timeout)
- Service disablement (Telnet, FTP, Remote Registry, UPnP, etc.)
- Scheduled task cleanup
- Network adapter hardening
- Windows Defender verification
- Hosts file reset
- System update check

### 2. `forensics.ps1` - Forensics and Log Collection

Collects forensic data including logs, processes, hashes, and ownership information.

**Usage:**
```powershell
# Collect all forensic data
.\forensics.ps1 -All

# Collect specific data
.\forensics.ps1 -CollectLogs -DetectProcesses -CalculateHashes

# Specify output directory
.\forensics.ps1 -OutputDir "C:\Forensics\Investigation1"
```

**Features:**
- Event log export (System, Application, Security)
- Process detection and analysis
- Network connection monitoring
- Hash calculations (MD5, SHA256)
- File ownership lookup
- Caesar cipher decoder function
- Startup program analysis
- Installed software inventory

### 3. `browser-hardening.ps1` - Browser Security

Hardens Firefox and Chrome browsers with privacy and security settings.

**Usage:**
```powershell
# Harden both browsers
.\browser-hardening.ps1 -All

# Harden specific browser
.\browser-hardening.ps1 -Firefox
.\browser-hardening.ps1 -Chrome
```

**Features:**
- Tracking protection
- Telemetry disablement
- HTTPS-only mode
- Password saving disablement
- WebRTC disablement
- Privacy settings

### 4. `firewall-check.ps1` - Firewall Verification

Verifies and configures Windows Firewall settings.

**Usage:**
```powershell
# Verify firewall status only
.\firewall-check.ps1 -VerifyOnly

# Enable and configure firewall
.\firewall-check.ps1 -Enable
```

**Features:**
- Firewall status check
- Rule analysis
- Vulnerable port detection
- Firewall logging configuration
- Rule export to CSV

### 5. `service-management.ps1` - Service Management

Manages Windows services, disabling unnecessary ones.

**Usage:**
```powershell
# List services only
.\service-management.ps1 -ListOnly

# Disable unnecessary services
.\service-management.ps1 -Disable
```

**Features:**
- Service analysis
- Automatic disablement of risky services
- Service report export

### 6. `user-policies.ps1` - User Policies and Auditing

Configures password policies, account lockout, and auditing.

**Usage:**
```powershell
# Apply password and lockout policies
.\user-policies.ps1 -ApplyPolicies

# Enable auditing
.\user-policies.ps1 -EnableAuditing

# Apply both
.\user-policies.ps1 -ApplyPolicies -EnableAuditing
```

**Features:**
- Password policy configuration (14+ chars, complexity)
- Account lockout policy (5 attempts, 30 min)
- Audit policy enablement
- User account analysis

### 7. `app-removal.ps1` - Unauthorized Application Removal

Detects and removes potentially dangerous applications.

**Usage:**
```powershell
# List unauthorized apps only
.\app-removal.ps1 -ListOnly

# Remove unauthorized apps
.\app-removal.ps1 -Remove
```

**Target Applications:**
- CCleaner
- TeamViewer
- Wireshark
- Nmap
- Ophcrack
- Hashcat
- Metasploit
- John the Ripper
- Aircrack
- Cain & Abel

## 🐧 Linux Scripts

### 1. `hardening.sh` - Main Hardening Script

Comprehensive Linux system hardening.

**Usage:**
```bash
# Run all hardening measures
sudo ./hardening.sh

# Skip specific sections
sudo ./hardening.sh --skip-firewall --skip-services
```

**Features:**
- System updates
- Firewall configuration (UFW/firewalld/iptables)
- Service disablement
- File permission hardening
- SSH hardening
- Kernel hardening parameters
- Network protocol disablement
- Logging configuration

### 2. `forensics.sh` - Forensics and Log Collection

Collects forensic data from Linux systems.

**Usage:**
```bash
# Collect all forensic data
sudo ./forensics.sh

# Specify output directory
sudo ./forensics.sh --output-dir /tmp/investigation1

# Collect specific data only
sudo ./forensics.sh --no-hashes --no-ownership
```

**Features:**
- System log collection
- Process analysis
- Network connection monitoring
- Hash calculations
- File ownership analysis
- Cron job analysis
- Caesar cipher decoder

### 3. `service-management.sh` - Service Management

Manages Linux services.

**Usage:**
```bash
# List services only
sudo ./service-management.sh --list-only

# Disable unnecessary services
sudo ./service-management.sh --disable
```

### 4. `firewall-config.sh` - Firewall Configuration

Configures and verifies firewall settings.

**Usage:**
```bash
# Verify firewall status
sudo ./firewall-config.sh --verify-only

# Enable and configure firewall
sudo ./firewall-config.sh --enable
```

## 📚 Usage Guide

### Step-by-Step Windows Hardening

1. **Run Main Hardening Script:**
   ```powershell
   cd windows
   .\hardening.ps1
   ```

2. **Configure User Policies:**
   ```powershell
   .\user-policies.ps1 -ApplyPolicies -EnableAuditing
   ```

3. **Harden Browsers:**
   ```powershell
   .\browser-hardening.ps1 -All
   ```

4. **Verify Firewall:**
   ```powershell
   .\firewall-check.ps1 -Enable
   ```

5. **Remove Unauthorized Apps:**
   ```powershell
   .\app-removal.ps1 -Remove
   ```

6. **Collect Forensics Data (if needed):**
   ```powershell
   .\forensics.ps1 -All
   ```

### Step-by-Step Linux Hardening

1. **Run Main Hardening Script:**
   ```bash
   cd linux
   sudo ./hardening.sh
   ```

2. **Configure Firewall:**
   ```bash
   sudo ./firewall-config.sh --enable
   ```

3. **Manage Services:**
   ```bash
   sudo ./service-management.sh --disable
   ```

4. **Collect Forensics Data (if needed):**
   ```bash
   sudo ./forensics.sh
   ```

## 🔧 Modular Structure

Each script is independent and can be run separately:

```
cybersecurity-hardening-toolkit/
├── README.md
├── windows/
│   ├── hardening.ps1          # Main hardening
│   ├── forensics.ps1           # Forensics collection
│   ├── browser-hardening.ps1   # Browser security
│   ├── firewall-check.ps1      # Firewall verification
│   ├── service-management.ps1  # Service management
│   ├── user-policies.ps1       # User policies & auditing
│   └── app-removal.ps1         # App removal
└── linux/
    ├── hardening.sh            # Main hardening
    ├── forensics.sh            # Forensics collection
    ├── service-management.sh   # Service management
    └── firewall-config.sh      # Firewall configuration
```

## ⚠️ Safety & Best Practices

### Before Running Scripts

1. **Backup Your System**: Create a system restore point (Windows) or snapshot (Linux)
2. **Review Scripts**: Read the scripts to understand what they do
3. **Test in Non-Production**: Test scripts in a test environment first
4. **Check Logs**: Review log files after execution

### Safety Features

- ✅ **Privilege Checks**: Scripts verify administrator/root privileges
- ✅ **Idempotency**: Safe to run multiple times
- ✅ **Logging**: All actions are logged with timestamps
- ✅ **Warnings**: Scripts warn before making significant changes
- ✅ **Modularity**: Run only what you need

### Important Notes

- **Windows**: Some settings require Group Policy Editor (gpedit.msc) or Local Security Policy (secpol.msc)
- **Linux**: Some distributions may have different package managers or service names
- **Backup**: Always backup critical data before running hardening scripts
- **Testing**: Test scripts in a non-production environment first

## 🔍 Troubleshooting

### Windows Issues

**Problem**: "Execution policy prevents running scripts"
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Problem**: "Access denied" errors
- Ensure PowerShell is run as Administrator
- Check UAC settings

**Problem**: Some settings not applying
- Some settings require Group Policy (gpedit.msc)
- Some require Local Security Policy (secpol.msc)
- Check log files for specific errors

### Linux Issues

**Problem**: "Permission denied"
```bash
sudo ./script.sh
```

**Problem**: "Command not found"
- Install missing packages (varies by distribution)
- Check if service names match your distribution

**Problem**: Firewall not working
- Ensure UFW, firewalld, or iptables is installed
- Check if firewall service is running

## 📝 Log Files

All scripts generate timestamped log files:

- **Windows**: `script-name-YYYYMMDD-HHMMSS.log`
- **Linux**: `script-name-YYYYMMDD-HHMMSS.log`

Log files contain:
- Timestamped actions
- Success/failure messages
- Warnings and errors
- Detailed operation information

## 🧪 Testing

### Test Checklist

- [ ] Run scripts in test environment first
- [ ] Verify system functionality after hardening
- [ ] Check log files for errors
- [ ] Verify firewall rules are correct
- [ ] Test network connectivity
- [ ] Verify critical services are running
- [ ] Check browser functionality after hardening

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is provided as-is for educational and security hardening purposes. Use at your own risk.

## ⚡ Quick Start

### Windows Quick Start
```powershell
# Run as Administrator
cd windows
.\hardening.ps1
.\user-policies.ps1 -ApplyPolicies -EnableAuditing
.\browser-hardening.ps1 -All
.\firewall-check.ps1 -Enable
```

### Linux Quick Start
```bash
# Run as root
cd linux
sudo ./hardening.sh
sudo ./firewall-config.sh --enable
sudo ./service-management.sh --disable
```

## 📞 Support

For issues, questions, or contributions, please open an issue on the repository.

---

**⚠️ Disclaimer**: This toolkit is provided for security hardening purposes. Always test in a non-production environment first. The authors are not responsible for any damage or issues resulting from the use of these scripts.


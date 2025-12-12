# Quick Start Guide

## Windows Quick Start

### Prerequisites
1. Open PowerShell as **Administrator**
2. Navigate to the `windows` directory
3. Set execution policy (if needed):
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

### Recommended Execution Order

```powershell
# 1. Main system hardening
.\hardening.ps1

# 2. Configure user policies and auditing
.\user-policies.ps1 -ApplyPolicies -EnableAuditing

# 3. Harden browsers
.\browser-hardening.ps1 -All

# 4. Verify and configure firewall
.\firewall-check.ps1 -Enable

# 5. Remove unauthorized applications
.\app-removal.ps1 -Remove

# 6. (Optional) Collect forensic baseline
.\forensics.ps1 -All
```

## Linux Quick Start

### Prerequisites
1. Open terminal
2. Navigate to the `linux` directory
3. Make scripts executable:
   ```bash
   chmod +x *.sh
   ```

### Recommended Execution Order

```bash
# 1. Main system hardening
sudo ./hardening.sh

# 2. Configure firewall
sudo ./firewall-config.sh --enable

# 3. Manage services
sudo ./service-management.sh --disable

# 4. (Optional) Collect forensic baseline
sudo ./forensics.sh
```

## Individual Script Usage

### Windows Scripts

| Script | Purpose | Command |
|--------|---------|---------|
| `hardening.ps1` | Main hardening | `.\hardening.ps1` |
| `forensics.ps1` | Forensics collection | `.\forensics.ps1 -All` |
| `browser-hardening.ps1` | Browser security | `.\browser-hardening.ps1 -All` |
| `firewall-check.ps1` | Firewall verification | `.\firewall-check.ps1 -Enable` |
| `service-management.ps1` | Service management | `.\service-management.ps1 -Disable` |
| `user-policies.ps1` | User policies | `.\user-policies.ps1 -ApplyPolicies -EnableAuditing` |
| `app-removal.ps1` | App removal | `.\app-removal.ps1 -Remove` |

### Linux Scripts

| Script | Purpose | Command |
|--------|---------|---------|
| `hardening.sh` | Main hardening | `sudo ./hardening.sh` |
| `forensics.sh` | Forensics collection | `sudo ./forensics.sh` |
| `firewall-config.sh` | Firewall configuration | `sudo ./firewall-config.sh --enable` |
| `service-management.sh` | Service management | `sudo ./service-management.sh --disable` |

## Important Notes

⚠️ **Always test in a non-production environment first!**

- All scripts generate log files with timestamps
- Review log files after execution
- Some Windows settings may require Group Policy Editor
- Linux scripts detect your distribution automatically
- Scripts are idempotent (safe to run multiple times)

## Getting Help

- Check log files for detailed information
- Review the main README.md for comprehensive documentation
- Ensure you have administrator/root privileges
- Verify system requirements are met


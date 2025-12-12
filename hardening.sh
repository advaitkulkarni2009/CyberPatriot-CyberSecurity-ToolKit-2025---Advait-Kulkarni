#!/bin/bash
# ============================================================================
# Linux System Hardening Script
# ============================================================================
# This script implements comprehensive Linux security hardening measures
# including firewall configuration, service management, file permissions,
# and system updates.
#
# Requirements: Root privileges (sudo)
# Usage: sudo ./hardening.sh [--skip-firewall] [--skip-services] [--skip-updates]
# ============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="hardening-$(date +%Y%m%d-%H%M%S).log"

# Parse command line arguments
SKIP_FIREWALL=false
SKIP_SERVICES=false
SKIP_UPDATES=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-firewall)
            SKIP_FIREWALL=true
            shift
            ;;
        --skip-services)
            SKIP_SERVICES=true
            shift
            ;;
        --skip-updates)
            SKIP_UPDATES=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Function to log messages
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Check for root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: This script must be run as root (use sudo)${NC}" >&2
        exit 1
    fi
}

# Detect Linux distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        log "WARNING" "Cannot detect Linux distribution"
        DISTRO="unknown"
    fi
    log "INFO" "Detected distribution: $DISTRO $VERSION"
}

# Initialize
check_root
detect_distro
log "INFO" "Starting Linux System Hardening..."

# ============================================================================
# 1. System Updates
# ============================================================================
if [[ "$SKIP_UPDATES" == false ]]; then
    log "INFO" "Updating system packages..."
    
    case $DISTRO in
        ubuntu|debian)
            apt-get update -qq
            apt-get upgrade -y -qq
            apt-get autoremove -y -qq
            log "SUCCESS" "System packages updated"
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf update -y -q
                dnf autoremove -y -q
            else
                yum update -y -q
                yum autoremove -y -q
            fi
            log "SUCCESS" "System packages updated"
            ;;
        arch|manjaro)
            pacman -Syu --noconfirm
            log "SUCCESS" "System packages updated"
            ;;
        *)
            log "WARNING" "Unknown distribution, skipping package updates"
            ;;
    esac
else
    log "INFO" "Skipping system updates (--skip-updates specified)"
fi

# ============================================================================
# 2. Firewall Configuration (UFW or firewalld)
# ============================================================================
if [[ "$SKIP_FIREWALL" == false ]]; then
    log "INFO" "Configuring firewall..."
    
    # Try UFW first (Ubuntu/Debian)
    if command -v ufw &> /dev/null; then
        log "INFO" "Using UFW firewall"
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw --force enable
        log "SUCCESS" "UFW firewall enabled with default deny incoming"
    
    # Try firewalld (CentOS/RHEL/Fedora)
    elif command -v firewall-cmd &> /dev/null; then
        log "INFO" "Using firewalld"
        systemctl enable firewalld
        systemctl start firewalld
        firewall-cmd --set-default-zone=public
        firewall-cmd --reload
        log "SUCCESS" "firewalld enabled"
    
    # Try iptables directly
    elif command -v iptables &> /dev/null; then
        log "INFO" "Configuring iptables"
        # Flush existing rules
        iptables -F
        iptables -X
        iptables -t nat -F
        iptables -t nat -X
        
        # Default policies
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT
        
        # Allow loopback
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT
        
        # Allow established connections
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        
        # Save rules (distribution-specific)
        if command -v iptables-save &> /dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
            iptables-save > /etc/iptables.rules 2>/dev/null || \
            log "WARNING" "Could not save iptables rules automatically"
        fi
        log "SUCCESS" "iptables configured"
    else
        log "WARNING" "No firewall tool found (ufw, firewalld, or iptables)"
    fi
else
    log "INFO" "Skipping firewall configuration (--skip-firewall specified)"
fi

# ============================================================================
# 3. Disable Unnecessary Services
# ============================================================================
if [[ "$SKIP_SERVICES" == false ]]; then
    log "INFO" "Disabling unnecessary services..."
    
    # Services to disable (common security risks)
    SERVICES_TO_DISABLE=(
        "telnet"           # Telnet service (insecure)
        "rsh"              # Remote shell (insecure)
        "rlogin"           # Remote login (insecure)
        "rexec"             # Remote execute (insecure)
        "tftp"             # TFTP (insecure)
        "xinetd"            # Extended internet daemon (if not needed)
        "vsftpd"            # FTP server (if not needed)
        "nfs-server"        # NFS server (if not needed)
        "rpcbind"           # RPC bind (if not needed)
    )
    
    # Detect init system
    if systemctl list-units --type=service &> /dev/null; then
        # systemd
        for service in "${SERVICES_TO_DISABLE[@]}"; do
            if systemctl list-unit-files | grep -q "^${service}"; then
                systemctl stop "$service" 2>/dev/null || true
                systemctl disable "$service" 2>/dev/null || true
                log "SUCCESS" "Disabled service: $service"
            fi
        done
    elif command -v service &> /dev/null; then
        # SysV init
        for service in "${SERVICES_TO_DISABLE[@]}"; do
            if service --status-all 2>&1 | grep -q "$service"; then
                service "$service" stop 2>/dev/null || true
                update-rc.d "$service" disable 2>/dev/null || \
                chkconfig "$service" off 2>/dev/null || true
                log "SUCCESS" "Disabled service: $service"
            fi
        done
    fi
else
    log "INFO" "Skipping service management (--skip-services specified)"
fi

# ============================================================================
# 4. Secure File Permissions
# ============================================================================
log "INFO" "Securing file permissions..."

# Secure critical files
CRITICAL_FILES=(
    "/etc/passwd:644"
    "/etc/shadow:600"
    "/etc/group:644"
    "/etc/gshadow:600"
    "/etc/sudoers:440"
    "/etc/ssh/sshd_config:600"
)

for file_perm in "${CRITICAL_FILES[@]}"; do
    IFS=':' read -r file perm <<< "$file_perm"
    if [[ -f "$file" ]]; then
        chmod "$perm" "$file" 2>/dev/null || log "WARNING" "Could not set permissions for $file"
        log "SUCCESS" "Set permissions $perm on $file"
    fi
done

# Secure home directories
log "INFO" "Securing home directories..."
for home_dir in /home/*; do
    if [[ -d "$home_dir" ]]; then
        chmod 700 "$home_dir" 2>/dev/null || true
        log "SUCCESS" "Secured home directory: $home_dir"
    fi
done

# ============================================================================
# 5. SSH Hardening
# ============================================================================
log "INFO" "Hardening SSH configuration..."

SSH_CONFIG="/etc/ssh/sshd_config"
if [[ -f "$SSH_CONFIG" ]]; then
    # Backup original config
    cp "$SSH_CONFIG" "${SSH_CONFIG}.backup.$(date +%Y%m%d-%H%M%S)"
    
    # Apply secure SSH settings
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' "$SSH_CONFIG"
    sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSH_CONFIG"
    sed -i 's/#X11Forwarding.*/X11Forwarding no/' "$SSH_CONFIG"
    
    # Add additional security settings if not present
    if ! grep -q "^Protocol 2" "$SSH_CONFIG"; then
        echo "Protocol 2" >> "$SSH_CONFIG"
    fi
    
    if ! grep -q "^MaxAuthTries" "$SSH_CONFIG"; then
        echo "MaxAuthTries 3" >> "$SSH_CONFIG"
    fi
    
    if ! grep -q "^ClientAliveInterval" "$SSH_CONFIG"; then
        echo "ClientAliveInterval 300" >> "$SSH_CONFIG"
        echo "ClientAliveCountMax 2" >> "$SSH_CONFIG"
    fi
    
    # Restart SSH service
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || service sshd restart 2>/dev/null || true
    log "SUCCESS" "SSH configuration hardened"
else
    log "WARNING" "SSH config file not found"
fi

# ============================================================================
# 6. Kernel Hardening Parameters
# ============================================================================
log "INFO" "Applying kernel hardening parameters..."

SYSCTL_CONFIG="/etc/sysctl.conf"
if [[ -f "$SYSCTL_CONFIG" ]]; then
    # Backup original
    cp "$SYSCTL_CONFIG" "${SYSCTL_CONFIG}.backup.$(date +%Y%m%d-%H%M%S)"
    
    # Add security parameters
    cat >> "$SYSCTL_CONFIG" <<EOF

# Security hardening parameters
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF
    
    # Apply settings
    sysctl -p > /dev/null 2>&1 || true
    log "SUCCESS" "Kernel hardening parameters applied"
fi

# ============================================================================
# 7. Disable Unused Network Protocols
# ============================================================================
log "INFO" "Disabling unused network protocols..."

# Disable IPv6 if not needed (optional - comment out if IPv6 is required)
# echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
# echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf

# Disable DCCP, SCTP, RDS, TIPC (if modules are loaded)
MODULES_TO_DISABLE=("dccp" "sctp" "rds" "tipc")
for module in "${MODULES_TO_DISABLE[@]}"; do
    if lsmod | grep -q "^${module}"; then
        modprobe -r "$module" 2>/dev/null || true
        echo "install $module /bin/true" >> /etc/modprobe.d/blacklist.conf 2>/dev/null || true
        log "SUCCESS" "Disabled module: $module"
    fi
done

# ============================================================================
# 8. Configure Logging
# ============================================================================
log "INFO" "Configuring system logging..."

# Ensure rsyslog or syslog-ng is running
if command -v rsyslogd &> /dev/null; then
    systemctl enable rsyslog 2>/dev/null || true
    systemctl start rsyslog 2>/dev/null || true
    log "SUCCESS" "rsyslog enabled"
elif command -v syslog-ng &> /dev/null; then
    systemctl enable syslog-ng 2>/dev/null || true
    systemctl start syslog-ng 2>/dev/null || true
    log "SUCCESS" "syslog-ng enabled"
fi

# ============================================================================
# 9. Install and Configure Fail2ban (if available)
# ============================================================================
log "INFO" "Checking for fail2ban..."

if command -v fail2ban-client &> /dev/null; then
    systemctl enable fail2ban 2>/dev/null || true
    systemctl start fail2ban 2>/dev/null || true
    log "SUCCESS" "fail2ban is installed and running"
else
    log "INFO" "fail2ban not installed. Consider installing it for brute-force protection."
fi

# ============================================================================
# 10. Remove Unnecessary Packages
# ============================================================================
log "INFO" "Removing unnecessary packages..."

UNNECESSARY_PACKAGES=(
    "telnet"
    "rsh-client"
    "rsh-redone-client"
    "nis"
    "yp-tools"
)

case $DISTRO in
    ubuntu|debian)
        for pkg in "${UNNECESSARY_PACKAGES[@]}"; do
            if dpkg -l | grep -q "^ii.*${pkg}"; then
                apt-get remove -y "$pkg" 2>/dev/null || true
                log "SUCCESS" "Removed package: $pkg"
            fi
        done
        ;;
    centos|rhel|fedora)
        for pkg in "${UNNECESSARY_PACKAGES[@]}"; do
            if rpm -q "$pkg" &> /dev/null; then
                yum remove -y "$pkg" 2>/dev/null || dnf remove -y "$pkg" 2>/dev/null || true
                log "SUCCESS" "Removed package: $pkg"
            fi
        done
        ;;
esac

# ============================================================================
# Summary
# ============================================================================
log "SUCCESS" "Linux System Hardening completed!"
echo -e "${GREEN}Hardening script completed. Review the log file: $LOG_FILE${NC}"


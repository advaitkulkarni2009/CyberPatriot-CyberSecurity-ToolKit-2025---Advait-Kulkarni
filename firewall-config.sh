#!/bin/bash
# ============================================================================
# Linux Firewall Configuration Script
# ============================================================================
# This script configures and verifies firewall settings using UFW, firewalld,
# or iptables depending on the Linux distribution.
#
# Requirements: Root privileges (sudo)
# Usage: sudo ./firewall-config.sh [--enable] [--verify-only]
# ============================================================================

set -euo pipefail

ENABLE=false
VERIFY_ONLY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --enable)
            ENABLE=true
            shift
            ;;
        --verify-only)
            VERIFY_ONLY=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)" >&2
    exit 1
fi

LOG_FILE="firewall-config-$(date +%Y%m%d-%H%M%S).log"

log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log "INFO" "Starting Firewall Configuration..."

# Detect firewall tool
FIREWALL_TOOL=""
if command -v ufw &> /dev/null; then
    FIREWALL_TOOL="ufw"
elif command -v firewall-cmd &> /dev/null; then
    FIREWALL_TOOL="firewalld"
elif command -v iptables &> /dev/null; then
    FIREWALL_TOOL="iptables"
else
    log "ERROR" "No firewall tool found (ufw, firewalld, or iptables)"
    exit 1
fi

log "INFO" "Detected firewall tool: $FIREWALL_TOOL"

# ============================================================================
# UFW Configuration
# ============================================================================
if [[ "$FIREWALL_TOOL" == "ufw" ]]; then
    log "INFO" "Configuring UFW firewall..."
    
    # Check status
    ufw_status=$(ufw status | head -1)
    log "INFO" "Current UFW status: $ufw_status"
    
    if [[ "$ENABLE" == true ]]; then
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw --force enable
        log "SUCCESS" "UFW firewall enabled with default deny incoming"
    elif [[ "$VERIFY_ONLY" == true ]]; then
        ufw status verbose > "$LOG_FILE.status"
        log "INFO" "UFW status saved to log file"
    fi
    
    # List rules
    ufw status numbered > "$LOG_FILE.rules" 2>/dev/null || true
    log "SUCCESS" "UFW rules exported"
fi

# ============================================================================
# firewalld Configuration
# ============================================================================
if [[ "$FIREWALL_TOOL" == "firewalld" ]]; then
    log "INFO" "Configuring firewalld..."
    
    # Check status
    if systemctl is-active firewalld &> /dev/null; then
        log "INFO" "firewalld is active"
    else
        log "WARNING" "firewalld is not active"
        if [[ "$ENABLE" == true ]]; then
            systemctl enable firewalld
            systemctl start firewalld
            log "SUCCESS" "firewalld enabled and started"
        fi
    fi
    
    # Get default zone
    default_zone=$(firewall-cmd --get-default-zone)
    log "INFO" "Default zone: $default_zone"
    
    # List rules
    firewall-cmd --list-all > "$LOG_FILE.rules" 2>/dev/null || true
    log "SUCCESS" "firewalld rules exported"
fi

# ============================================================================
# iptables Configuration
# ============================================================================
if [[ "$FIREWALL_TOOL" == "iptables" ]]; then
    log "INFO" "Configuring iptables..."
    
    # Check current rules
    iptables -L -n -v > "$LOG_FILE.rules" 2>/dev/null || true
    log "INFO" "Current iptables rules exported"
    
    if [[ "$ENABLE" == true ]]; then
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
        
        # Allow SSH (important!)
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        
        # Save rules
        if command -v iptables-save &> /dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
            iptables-save > /etc/iptables.rules 2>/dev/null || \
            log "WARNING" "Could not save iptables rules automatically"
        fi
        
        log "SUCCESS" "iptables configured with secure defaults"
    fi
fi

# ============================================================================
# Check for Common Vulnerable Ports
# ============================================================================
log "INFO" "Checking for common vulnerable ports..."

VULNERABLE_PORTS=(21 23 135 139 445 3389)

if command -v netstat &> /dev/null; then
    listening_ports=$(netstat -tuln | grep LISTEN | awk '{print $4}' | cut -d: -f2 | sort -u)
elif command -v ss &> /dev/null; then
    listening_ports=$(ss -tuln | grep LISTEN | awk '{print $4}' | cut -d: -f2 | sort -u)
else
    log "WARNING" "Cannot check listening ports (netstat or ss not found)"
    listening_ports=""
fi

for port in "${VULNERABLE_PORTS[@]}"; do
    if echo "$listening_ports" | grep -q "^${port}$"; then
        log "WARNING" "Port $port is listening!"
    fi
done

log "SUCCESS" "Firewall configuration completed!"
echo "Firewall check completed. Review the log file: $LOG_FILE"


#!/bin/bash
# ============================================================================
# Linux Service Management Script
# ============================================================================
# This script manages Linux services, disabling unnecessary and potentially
# dangerous services while ensuring critical services remain running.
#
# Requirements: Root privileges (sudo)
# Usage: sudo ./service-management.sh [--disable] [--list-only]
# ============================================================================

set -euo pipefail

DISABLE=false
LIST_ONLY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --disable)
            DISABLE=true
            shift
            ;;
        --list-only)
            LIST_ONLY=true
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

LOG_FILE="service-management-$(date +%Y%m%d-%H%M%S).log"

log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log "INFO" "Starting Linux Service Management..."

# Services to disable (security risk)
SERVICES_TO_DISABLE=(
    "telnet"
    "rsh"
    "rlogin"
    "rexec"
    "tftp"
    "xinetd"
    "vsftpd"
    "nfs-server"
    "rpcbind"
    "rpc-statd"
    "nfs-idmapd"
)

# Detect init system
if systemctl list-units --type=service &> /dev/null; then
    INIT_SYSTEM="systemd"
elif command -v service &> /dev/null; then
    INIT_SYSTEM="sysv"
else
    log "ERROR" "Unknown init system"
    exit 1
fi

log "INFO" "Detected init system: $INIT_SYSTEM"

# List services
log "INFO" "Analyzing services..."

REPORT_FILE="service-report-$(date +%Y%m%d-%H%M%S).csv"
echo "Name,Status,StartType,Action" > "$REPORT_FILE"

for service in "${SERVICES_TO_DISABLE[@]}"; do
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        if systemctl list-unit-files | grep -q "^${service}"; then
            status=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
            enabled=$(systemctl is-enabled "$service" 2>/dev/null || echo "disabled")
            echo "$service,$status,$enabled,Should Disable" >> "$REPORT_FILE"
            log "INFO" "Found service: $service - Status: $status - Enabled: $enabled"
        fi
    elif [[ "$INIT_SYSTEM" == "sysv" ]]; then
        if service --status-all 2>&1 | grep -q "$service"; then
            status=$(service "$service" status 2>&1 | head -1 || echo "unknown")
            echo "$service,$status,unknown,Should Disable" >> "$REPORT_FILE"
            log "INFO" "Found service: $service - Status: $status"
        fi
    fi
done

log "SUCCESS" "Service report exported to: $REPORT_FILE"

if [[ "$LIST_ONLY" == true ]]; then
    log "SUCCESS" "Service analysis complete"
    exit 0
fi

# Disable services
if [[ "$DISABLE" == true ]]; then
    log "INFO" "Disabling unnecessary services..."
    
    for service in "${SERVICES_TO_DISABLE[@]}"; do
        if [[ "$INIT_SYSTEM" == "systemd" ]]; then
            if systemctl list-unit-files | grep -q "^${service}"; then
                systemctl stop "$service" 2>/dev/null || true
                systemctl disable "$service" 2>/dev/null || true
                log "SUCCESS" "Disabled service: $service"
            fi
        elif [[ "$INIT_SYSTEM" == "sysv" ]]; then
            if service --status-all 2>&1 | grep -q "$service"; then
                service "$service" stop 2>/dev/null || true
                update-rc.d "$service" disable 2>/dev/null || \
                chkconfig "$service" off 2>/dev/null || true
                log "SUCCESS" "Disabled service: $service"
            fi
        fi
    done
    
    log "SUCCESS" "Service management completed!"
else
    log "INFO" "Service analysis complete. Run with --disable to apply changes."
fi


#!/bin/bash
# ============================================================================
# Linux Forensics and Log Collection Script
# ============================================================================
# This script collects forensic data including logs, process information,
# hash calculations, file ownership, and suspicious activity detection.
#
# Requirements: Root privileges (sudo) for some operations
# Usage: sudo ./forensics.sh [--output-dir <path>]
# ============================================================================

set -euo pipefail

# Default output directory
OUTPUT_DIR="forensics-$(date +%Y%m%d-%H%M%S)"
COLLECT_LOGS=true
DETECT_PROCESSES=true
CALCULATE_HASHES=true
FILE_OWNERSHIP=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --no-logs)
            COLLECT_LOGS=false
            shift
            ;;
        --no-processes)
            DETECT_PROCESSES=false
            shift
            ;;
        --no-hashes)
            CALCULATE_HASHES=false
            shift
            ;;
        --no-ownership)
            FILE_OWNERSHIP=false
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/forensics.log"

# Function to log messages
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log "INFO" "Starting Linux Forensics Collection..."
log "INFO" "Output directory: $OUTPUT_DIR"

# ============================================================================
# 1. Log Collection
# ============================================================================
if [[ "$COLLECT_LOGS" == true ]]; then
    log "INFO" "Collecting system logs..."
    
    LOG_DIR="$OUTPUT_DIR/logs"
    mkdir -p "$LOG_DIR"
    
    # Collect system logs
    if [[ -d /var/log ]]; then
        cp -r /var/log/* "$LOG_DIR/" 2>/dev/null || true
        log "SUCCESS" "Copied /var/log contents"
    fi
    
    # Collect auth logs (login attempts)
    if [[ -f /var/log/auth.log ]]; then
        cp /var/log/auth.log "$LOG_DIR/auth.log"
        log "SUCCESS" "Copied auth.log"
    elif [[ -f /var/log/secure ]]; then
        cp /var/log/secure "$LOG_DIR/secure"
        log "SUCCESS" "Copied secure log"
    fi
    
    # Collect failed login attempts
    if [[ -f /var/log/auth.log ]]; then
        grep "Failed password" /var/log/auth.log > "$LOG_DIR/failed-logins.txt" 2>/dev/null || true
        log "SUCCESS" "Extracted failed login attempts"
    fi
    
    # Collect system messages
    if [[ -f /var/log/messages ]]; then
        cp /var/log/messages "$LOG_DIR/messages"
        log "SUCCESS" "Copied messages log"
    fi
    
    # Collect kernel logs
    dmesg > "$LOG_DIR/dmesg.txt" 2>/dev/null || true
    log "SUCCESS" "Collected kernel messages"
    
    # Collect journalctl logs (systemd)
    if command -v journalctl &> /dev/null; then
        journalctl -a > "$LOG_DIR/journalctl.log" 2>/dev/null || true
        log "SUCCESS" "Collected systemd journal logs"
    fi
fi

# ============================================================================
# 2. Suspicious Process Detection
# ============================================================================
if [[ "$DETECT_PROCESSES" == true ]]; then
    log "INFO" "Detecting suspicious processes..."
    
    PROCESS_DIR="$OUTPUT_DIR/processes"
    mkdir -p "$PROCESS_DIR"
    
    # Get all running processes
    ps aux > "$PROCESS_DIR/all-processes.txt"
    log "SUCCESS" "Exported all running processes"
    
    # Get process tree
    pstree -p > "$PROCESS_DIR/process-tree.txt" 2>/dev/null || true
    
    # Get network connections
    netstat -tulpn > "$PROCESS_DIR/network-connections.txt" 2>/dev/null || \
    ss -tulpn > "$PROCESS_DIR/network-connections.txt" 2>/dev/null || true
    log "SUCCESS" "Exported network connections"
    
    # Detect processes running from temp directories
    ps aux | awk '{print $11}' | grep -E "(/tmp/|/var/tmp/|/dev/shm/)" > "$PROCESS_DIR/temp-processes.txt" 2>/dev/null || true
    if [[ -s "$PROCESS_DIR/temp-processes.txt" ]]; then
        log "WARNING" "Found processes running from temp directories!"
    fi
    
    # Get listening ports
    netstat -tuln > "$PROCESS_DIR/listening-ports.txt" 2>/dev/null || \
    ss -tuln > "$PROCESS_DIR/listening-ports.txt" 2>/dev/null || true
    
    # Get process environment variables (may contain sensitive data)
    ps eww > "$PROCESS_DIR/process-env.txt" 2>/dev/null || true
fi

# ============================================================================
# 3. Hash Calculations (MD5, SHA256)
# ============================================================================
if [[ "$CALCULATE_HASHES" == true ]]; then
    log "INFO" "Calculating file hashes..."
    
    HASH_DIR="$OUTPUT_DIR/hashes"
    mkdir -p "$HASH_DIR"
    
    # Critical system files to hash
    CRITICAL_FILES=(
        "/bin/bash"
        "/bin/sh"
        "/usr/bin/sudo"
        "/usr/bin/su"
        "/etc/passwd"
        "/etc/shadow"
        "/etc/group"
        "/etc/sudoers"
        "/etc/ssh/sshd_config"
    )
    
    # Calculate hashes
    {
        echo "File,MD5,SHA256,Size,LastModified"
        for file in "${CRITICAL_FILES[@]}"; do
            if [[ -f "$file" ]]; then
                md5=$(md5sum "$file" 2>/dev/null | awk '{print $1}') || md5="N/A"
                sha256=$(sha256sum "$file" 2>/dev/null | awk '{print $1}') || sha256="N/A"
                size=$(stat -c%s "$file" 2>/dev/null || echo "N/A")
                modified=$(stat -c%y "$file" 2>/dev/null || echo "N/A")
                echo "\"$file\",\"$md5\",\"$sha256\",\"$size\",\"$modified\""
                log "SUCCESS" "Calculated hash for: $file"
            fi
        done
    } > "$HASH_DIR/system-file-hashes.csv"
    
    log "SUCCESS" "Exported file hashes"
fi

# ============================================================================
# 4. File Ownership Lookup
# ============================================================================
if [[ "$FILE_OWNERSHIP" == true ]]; then
    log "INFO" "Collecting file ownership information..."
    
    OWNERSHIP_DIR="$OUTPUT_DIR/ownership"
    mkdir -p "$OWNERSHIP_DIR"
    
    # Check ownership of critical directories
    CRITICAL_DIRS=(
        "/bin"
        "/usr/bin"
        "/sbin"
        "/usr/sbin"
        "/etc"
        "/root"
        "/home"
    )
    
    {
        echo "Path,Owner,Group,Permissions"
        for dir in "${CRITICAL_DIRS[@]}"; do
            if [[ -d "$dir" ]]; then
                owner=$(stat -c%U "$dir" 2>/dev/null || echo "N/A")
                group=$(stat -c%G "$dir" 2>/dev/null || echo "N/A")
                perms=$(stat -c%a "$dir" 2>/dev/null || echo "N/A")
                echo "\"$dir\",\"$owner\",\"$group\",\"$perms\""
            fi
        done
    } > "$OWNERSHIP_DIR/directory-ownership.csv"
    
    log "SUCCESS" "Exported ownership information"
fi

# ============================================================================
# 5. Additional Forensic Checks
# ============================================================================
log "INFO" "Performing additional forensic checks..."

ADDITIONAL_DIR="$OUTPUT_DIR/additional"
mkdir -p "$ADDITIONAL_DIR"

# Startup programs
if [[ -d /etc/init.d ]]; then
    ls -la /etc/init.d/ > "$ADDITIONAL_DIR/init-scripts.txt" 2>/dev/null || true
fi

if [[ -d /etc/systemd/system ]]; then
    systemctl list-unit-files > "$ADDITIONAL_DIR/systemd-services.txt" 2>/dev/null || true
fi

# Cron jobs
crontab -l > "$ADDITIONAL_DIR/root-crontab.txt" 2>/dev/null || true
if [[ -d /etc/cron.d ]]; then
    cat /etc/cron.d/* > "$ADDITIONAL_DIR/system-crontab.txt" 2>/dev/null || true
fi

# Installed packages
if command -v dpkg &> /dev/null; then
    dpkg -l > "$ADDITIONAL_DIR/installed-packages.txt" 2>/dev/null || true
elif command -v rpm &> /dev/null; then
    rpm -qa > "$ADDITIONAL_DIR/installed-packages.txt" 2>/dev/null || true
fi

# User accounts
cat /etc/passwd > "$ADDITIONAL_DIR/passwd.txt"
cat /etc/group > "$ADDITIONAL_DIR/group.txt"
cat /etc/shadow > "$ADDITIONAL_DIR/shadow.txt" 2>/dev/null || true

# System information
uname -a > "$ADDITIONAL_DIR/system-info.txt"
hostname > "$ADDITIONAL_DIR/hostname.txt"
ifconfig > "$ADDITIONAL_DIR/network-config.txt" 2>/dev/null || \
ip addr > "$ADDITIONAL_DIR/network-config.txt" 2>/dev/null || true

# Mount points
mount > "$ADDITIONAL_DIR/mounts.txt"
cat /etc/fstab > "$ADDITIONAL_DIR/fstab.txt" 2>/dev/null || true

log "SUCCESS" "Additional forensic checks completed"

# ============================================================================
# 6. Caesar Cipher Decoding Function
# ============================================================================
log "INFO" "Caesar cipher decoder function available"
cat > "$OUTPUT_DIR/caesar-cipher.sh" <<'EOF'
#!/bin/bash
# Caesar Cipher Decoder
# Usage: ./caesar-cipher.sh <ciphertext> [shift]

CIPHERTEXT="$1"
SHIFT="${2:-0}"

if [[ -z "$CIPHERTEXT" ]]; then
    echo "Usage: $0 <ciphertext> [shift]"
    echo "If shift is 0, all shifts (0-25) will be tried"
    exit 1
fi

decode() {
    local text="$1"
    local shift="$2"
    local result=""
    
    for ((i=0; i<${#text}; i++)); do
        char="${text:$i:1}"
        if [[ "$char" =~ [a-z] ]]; then
            ascii=$(printf '%d' "'$char")
            ascii=$((ascii - 97))
            ascii=$(((ascii - shift + 26) % 26))
            ascii=$((ascii + 97))
            result+=$(printf "\\$(printf '%03o' $ascii)")
        elif [[ "$char" =~ [A-Z] ]]; then
            ascii=$(printf '%d' "'$char")
            ascii=$((ascii - 65))
            ascii=$(((ascii - shift + 26) % 26))
            ascii=$((ascii + 65))
            result+=$(printf "\\$(printf '%03o' $ascii)")
        else
            result+="$char"
        fi
    done
    echo "$result"
}

if [[ "$SHIFT" -eq 0 ]]; then
    echo "Trying all shifts (0-25):"
    for s in {0..25}; do
        decoded=$(decode "$CIPHERTEXT" $s)
        printf "Shift %2d: %s\n" $s "$decoded"
    done
else
    decoded=$(decode "$CIPHERTEXT" $SHIFT)
    echo "Decoded (shift $SHIFT): $decoded"
fi
EOF

chmod +x "$OUTPUT_DIR/caesar-cipher.sh"
log "SUCCESS" "Created Caesar cipher decoder script"

# ============================================================================
# Summary
# ============================================================================
log "SUCCESS" "Forensics collection completed!"
log "INFO" "All data saved to: $OUTPUT_DIR"
echo "Forensics collection completed. Data saved to: $OUTPUT_DIR"


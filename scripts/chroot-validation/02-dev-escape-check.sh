#!/usr/bin/env bash
# =============================================================================
# VALIDATION SCRIPT 02: /dev Filesystem Escape Vector
# =============================================================================
#
# FINDING: CVE-CLASS-001 - Chroot is Not a Security Boundary
# SEVERITY: CRITICAL
#
# TECHNICAL DETAILS:
# ------------------
# When /dev is bind-mounted from the host, all device nodes are accessible.
# This creates multiple escape vectors:
#
# 1. /dev/sda* - Direct disk access bypasses filesystem permissions
# 2. /dev/mem, /dev/kmem - Direct memory access (usually restricted)
# 3. /dev/pts/* - PTY access could allow terminal hijacking
# 4. Device node creation - mknod could create new devices
#
# The classic chroot escape using devices:
#   mknod /tmp/sda b 8 0  # Create block device for first disk
#   mount /tmp/sda /mnt   # Mount it
#   chroot /mnt           # Escape to real root
#
# RISK LEVEL: READ-ONLY TEST
# This script only checks what's accessible. It does NOT:
# - Create device nodes
# - Read from block devices
# - Modify anything
#
# EXPECTED RESULT IF VULNERABLE:
# - Block devices visible and potentially readable
# - Can create device nodes (would require root)
#
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=============================================="
echo "VALIDATION 02: /dev Filesystem Escape Vector"
echo "=============================================="
echo ""

VULNERABLE=false

# Test 1: Is /dev mounted with host devices?
echo "[TEST 1] Checking for block devices in /dev..."
BLOCK_DEVS=$(ls /dev/sd* /dev/nvme* /dev/vd* 2>/dev/null | head -5 || echo "")
if [[ -n "$BLOCK_DEVS" ]]; then
    echo -e "${RED}  Block devices found:${NC}"
    echo "$BLOCK_DEVS" | while read dev; do
        echo "    $dev"
    done
    VULNERABLE=true
else
    echo -e "${GREEN}  No block devices visible${NC}"
fi

# Test 2: Check for dangerous device nodes
echo ""
echo "[TEST 2] Checking for dangerous device nodes..."

DANGEROUS_DEVS=("/dev/mem" "/dev/kmem" "/dev/port")
for dev in "${DANGEROUS_DEVS[@]}"; do
    if [[ -e "$dev" ]]; then
        PERMS=$(ls -la "$dev" 2>/dev/null | awk '{print $1}')
        echo -e "${YELLOW}  $dev exists (perms: $PERMS)${NC}"
        if [[ -r "$dev" ]]; then
            echo -e "${RED}    READABLE - direct memory access possible${NC}"
            VULNERABLE=true
        fi
    else
        echo -e "${GREEN}  $dev not present${NC}"
    fi
done

# Test 3: Check if we can see PTYs (terminal hijacking vector)
echo ""
echo "[TEST 3] Checking /dev/pts access..."
if [[ -d /dev/pts ]]; then
    PTY_COUNT=$(ls /dev/pts 2>/dev/null | wc -l)
    echo -e "${YELLOW}  /dev/pts accessible with $PTY_COUNT entries${NC}"
    echo "  (Could potentially be used for terminal hijacking)"
else
    echo -e "${GREEN}  /dev/pts not accessible${NC}"
fi

# Test 4: Check mknod capability (requires root, just test if binary exists)
echo ""
echo "[TEST 4] Checking mknod availability..."
if command -v mknod &>/dev/null; then
    echo -e "${YELLOW}  mknod binary available${NC}"
    echo "  (If running as root, could create arbitrary device nodes)"

    # Check if /tmp is writable (where we'd create nodes)
    if [[ -w /tmp ]]; then
        echo -e "${YELLOW}  /tmp is writable - device node creation possible if root${NC}"
    fi
else
    echo -e "${GREEN}  mknod not available${NC}"
fi

# Test 5: Check current user capabilities
echo ""
echo "[TEST 5] Checking current user context..."
echo "  User: $(id -un) (UID: $(id -u))"
echo "  Groups: $(id -Gn)"

if [[ $(id -u) -eq 0 ]]; then
    echo -e "${RED}  Running as root - full device access possible${NC}"
    VULNERABLE=true
elif groups | grep -qE '\b(disk|kmem)\b'; then
    echo -e "${RED}  Member of disk/kmem group - device access possible${NC}"
    VULNERABLE=true
else
    echo -e "${GREEN}  Not in privileged groups${NC}"
fi

# Test 6: List all accessible device types
echo ""
echo "[TEST 6] Device node summary..."
if [[ -d /dev ]]; then
    echo "  Character devices: $(find /dev -type c 2>/dev/null | wc -l)"
    echo "  Block devices: $(find /dev -type b 2>/dev/null | wc -l)"
fi

echo ""
echo "=============================================="
if $VULNERABLE; then
    echo -e "${RED}RESULT: VULNERABLE${NC}"
    echo ""
    echo "Host /dev is mounted with accessible devices."
    echo "Escape possible via device node manipulation."
    echo ""
    echo "REMEDIATION:"
    echo "  1. Use devtmpfs with minimal device set"
    echo "  2. Only mount required devices (null, zero, urandom)"
    echo "  3. Use device cgroup to restrict access"
    echo "  4. Run in separate mount namespace"
else
    echo -e "${GREEN}RESULT: NOT VULNERABLE${NC}"
    echo ""
    echo "Device access appears restricted."
fi
echo "=============================================="

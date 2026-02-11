#!/usr/bin/env bash
# =============================================================================
# VALIDATION SCRIPT 07: /sys Filesystem Information Disclosure
# =============================================================================
#
# FINDING: CVE-CLASS-001 - Chroot is Not a Security Boundary
# SEVERITY: MEDIUM (Info Disclosure) / HIGH (with write access)
#
# TECHNICAL DETAILS:
# ------------------
# /sys (sysfs) exposes kernel and hardware information:
#
# READ vectors (information disclosure):
#   /sys/class/net/*/address - MAC addresses
#   /sys/devices/*/uevent - Hardware info
#   /sys/kernel/debug/* - Kernel debugging info
#   /sys/fs/cgroup/* - Process cgroup membership
#
# WRITE vectors (if writable - rare but dangerous):
#   /sys/class/leds/*/brightness - LED control
#   /sys/devices/system/cpu/*/online - CPU hotplug
#   /sys/kernel/mm/* - Memory management
#
# RISK LEVEL: READ-ONLY TEST
# This script only reads information, does not modify anything.
#
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=============================================="
echo "VALIDATION 07: /sys Filesystem Exposure"
echo "=============================================="
echo ""

VULNERABLE=false

# Test 1: Is /sys mounted?
echo "[TEST 1] Checking if /sys is accessible..."
if [[ -d /sys/class ]]; then
    echo -e "${YELLOW}  /sys is mounted and accessible${NC}"
    VULNERABLE=true
else
    echo -e "${GREEN}  /sys not accessible${NC}"
    echo ""
    echo "RESULT: NOT VULNERABLE"
    exit 0
fi

# Test 2: Network interface information disclosure
echo ""
echo "[TEST 2] Network interface information..."
if [[ -d /sys/class/net ]]; then
    for iface in /sys/class/net/*; do
        if [[ -d "$iface" ]]; then
            IFNAME=$(basename "$iface")
            if [[ "$IFNAME" != "lo" ]]; then
                MAC=$(cat "$iface/address" 2>/dev/null || echo "unreadable")
                echo -e "${YELLOW}  $IFNAME: MAC=$MAC${NC}"
            fi
        fi
    done
fi

# Test 3: Block device information
echo ""
echo "[TEST 3] Block device information..."
if [[ -d /sys/block ]]; then
    for dev in /sys/block/*; do
        if [[ -d "$dev" ]]; then
            DEVNAME=$(basename "$dev")
            SIZE=$(cat "$dev/size" 2>/dev/null || echo "?")
            # Size is in 512-byte sectors
            SIZE_GB=$((SIZE * 512 / 1024 / 1024 / 1024))
            echo -e "${YELLOW}  $DEVNAME: ${SIZE_GB}GB${NC}"
        fi
    done | head -5
fi

# Test 4: CPU information
echo ""
echo "[TEST 4] CPU information disclosure..."
if [[ -d /sys/devices/system/cpu ]]; then
    CPU_COUNT=$(ls -d /sys/devices/system/cpu/cpu[0-9]* 2>/dev/null | wc -l)
    echo -e "${YELLOW}  CPUs visible: $CPU_COUNT${NC}"

    # Check for vulnerabilities info
    if [[ -d /sys/devices/system/cpu/vulnerabilities ]]; then
        echo "  CPU vulnerabilities:"
        for vuln in /sys/devices/system/cpu/vulnerabilities/*; do
            VULNNAME=$(basename "$vuln")
            STATUS=$(cat "$vuln" 2>/dev/null | head -c 50)
            echo "    $VULNNAME: $STATUS"
        done | head -5
    fi
fi

# Test 5: Memory information
echo ""
echo "[TEST 5] Memory subsystem information..."
if [[ -d /sys/kernel/mm ]]; then
    echo -e "${YELLOW}  /sys/kernel/mm accessible${NC}"
    if [[ -d /sys/kernel/mm/transparent_hugepage ]]; then
        THP=$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || echo "?")
        echo "    THP: $THP"
    fi
fi

# Test 6: DMI/BIOS information
echo ""
echo "[TEST 6] Hardware identification..."
DMI_PATHS=("/sys/class/dmi/id" "/sys/devices/virtual/dmi/id")
for dmi in "${DMI_PATHS[@]}"; do
    if [[ -d "$dmi" ]]; then
        echo "  DMI information:"
        for field in product_name sys_vendor bios_version; do
            if [[ -r "$dmi/$field" ]]; then
                VALUE=$(cat "$dmi/$field" 2>/dev/null || echo "?")
                echo -e "${YELLOW}    $field: $VALUE${NC}"
            fi
        done
        break
    fi
done

# Test 7: Check for writable sysfs entries (rare but dangerous)
echo ""
echo "[TEST 7] Checking for writable sysfs entries..."
WRITABLE_COUNT=0
# Sample check - don't traverse entire /sys
for check_path in "/sys/kernel/mm" "/sys/devices/system/cpu"; do
    if [[ -d "$check_path" ]]; then
        FOUND=$(find "$check_path" -maxdepth 2 -type f -writable 2>/dev/null | head -5 | wc -l)
        WRITABLE_COUNT=$((WRITABLE_COUNT + FOUND))
    fi
done

if [[ $WRITABLE_COUNT -gt 0 ]]; then
    echo -e "${RED}  Found writable sysfs entries!${NC}"
else
    echo -e "${GREEN}  No writable sysfs entries found in sample${NC}"
fi

# Test 8: Kernel debug filesystem
echo ""
echo "[TEST 8] Checking debugfs access..."
if [[ -d /sys/kernel/debug ]] && [[ -r /sys/kernel/debug ]]; then
    echo -e "${RED}  /sys/kernel/debug accessible - sensitive kernel info exposed${NC}"
    VULNERABLE=true
else
    echo -e "${GREEN}  /sys/kernel/debug not accessible${NC}"
fi

echo ""
echo "=============================================="
if $VULNERABLE; then
    echo -e "${YELLOW}RESULT: INFORMATION DISCLOSURE${NC}"
    echo ""
    echo "Host hardware/kernel info exposed via /sys."
    echo ""
    echo "Disclosed information:"
    echo "  - Network interface MAC addresses"
    echo "  - Disk device names and sizes"
    echo "  - CPU count and vulnerability status"
    echo "  - Hardware vendor/model (DMI)"
    echo ""
    echo "REMEDIATION:"
    echo "  1. Don't mount host /sys into chroot"
    echo "  2. Use mount namespace with minimal /sys"
    echo "  3. Use sysfs filtering (cgroupns, etc.)"
else
    echo -e "${GREEN}RESULT: NOT VULNERABLE${NC}"
fi
echo "=============================================="

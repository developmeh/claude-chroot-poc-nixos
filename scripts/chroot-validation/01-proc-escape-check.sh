#!/usr/bin/env bash
# =============================================================================
# VALIDATION SCRIPT 01: /proc Filesystem Escape Vector
# =============================================================================
#
# FINDING: CVE-CLASS-001 - Chroot is Not a Security Boundary
# SEVERITY: CRITICAL
#
# TECHNICAL DETAILS:
# ------------------
# When /proc is bind-mounted into a chroot, it exposes the host's process
# information. Critically, /proc/1/root is a symlink to the real root
# filesystem (not the chroot root). Any process that can read this symlink
# can potentially access files outside the chroot.
#
# The attack works because:
# 1. /proc is the host's procfs, not a chroot-local one
# 2. /proc/1/root points to "/" of PID 1 (init/systemd), which is the real root
# 3. /proc/*/cwd, /proc/*/exe also leak host filesystem paths
#
# RISK LEVEL: READ-ONLY TEST
# This script only reads and displays information. It does not modify anything.
#
# EXPECTED RESULT IF VULNERABLE:
# - Can see /proc/1/root pointing to real "/"
# - Can potentially read host files via /proc/1/root/etc/passwd
#
# EXPECTED RESULT IF SECURE:
# - /proc is not mounted, OR
# - /proc/1/root is not accessible, OR
# - PID namespace isolation prevents seeing host PIDs
#
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=============================================="
echo "VALIDATION 01: /proc Filesystem Escape Vector"
echo "=============================================="
echo ""

VULNERABLE=false

# Test 1: Is /proc mounted?
echo "[TEST 1] Checking if /proc is mounted..."
if [[ -d /proc/1 ]]; then
    echo -e "${YELLOW}  /proc/1 exists - procfs is mounted${NC}"
else
    echo -e "${GREEN}  /proc/1 not accessible - may be isolated${NC}"
    echo ""
    echo "RESULT: INCONCLUSIVE (run inside chroot to validate)"
    exit 0
fi

# Test 2: Can we see /proc/1/root?
echo ""
echo "[TEST 2] Checking /proc/1/root symlink..."
if [[ -L /proc/1/root ]]; then
    ROOT_TARGET=$(readlink /proc/1/root 2>/dev/null || echo "unreadable")
    echo -e "${YELLOW}  /proc/1/root -> $ROOT_TARGET${NC}"

    if [[ "$ROOT_TARGET" == "/" ]]; then
        echo -e "${RED}  VULNERABLE: /proc/1/root points to real root filesystem${NC}"
        VULNERABLE=true
    fi
else
    echo -e "${GREEN}  /proc/1/root not accessible${NC}"
fi

# Test 3: Can we read host files via /proc/1/root?
echo ""
echo "[TEST 3] Attempting to read /proc/1/root/etc/hostname..."
if [[ -r /proc/1/root/etc/hostname ]]; then
    HOSTNAME_CONTENT=$(cat /proc/1/root/etc/hostname 2>/dev/null || echo "")
    if [[ -n "$HOSTNAME_CONTENT" ]]; then
        echo -e "${RED}  VULNERABLE: Can read host /etc/hostname: $HOSTNAME_CONTENT${NC}"
        VULNERABLE=true
    fi
else
    echo -e "${GREEN}  Cannot read /proc/1/root/etc/hostname${NC}"
fi

# Test 4: Check for PID namespace isolation
echo ""
echo "[TEST 4] Checking PID namespace isolation..."
PID_COUNT=$(ls /proc | grep -E '^[0-9]+$' | wc -l)
echo "  Visible PIDs in /proc: $PID_COUNT"
if [[ $PID_COUNT -gt 10 ]]; then
    echo -e "${YELLOW}  Many PIDs visible - likely NOT in isolated PID namespace${NC}"
else
    echo -e "${GREEN}  Few PIDs visible - may be in isolated PID namespace${NC}"
fi

# Test 5: Check /proc/*/exe for host binary paths
echo ""
echo "[TEST 5] Sampling /proc/*/exe paths (first 5 non-self)..."
for pid in $(ls /proc | grep -E '^[0-9]+$' | head -10); do
    if [[ "$pid" != "$$" ]] && [[ -L "/proc/$pid/exe" ]]; then
        EXE_PATH=$(readlink "/proc/$pid/exe" 2>/dev/null || echo "unreadable")
        if [[ "$EXE_PATH" != "unreadable" ]]; then
            echo "  PID $pid -> $EXE_PATH"
            # Check if path is outside expected chroot paths
            if [[ "$EXE_PATH" == /nix/* ]] || [[ "$EXE_PATH" == /run/* ]]; then
                : # Expected paths
            elif [[ "$EXE_PATH" == /usr/* ]] || [[ "$EXE_PATH" == /bin/* ]]; then
                echo -e "${YELLOW}    (host system binary visible)${NC}"
            fi
        fi
    fi
done

echo ""
echo "=============================================="
if $VULNERABLE; then
    echo -e "${RED}RESULT: VULNERABLE${NC}"
    echo ""
    echo "The /proc mount exposes host filesystem access vectors."
    echo "An attacker could use /proc/1/root to escape the chroot."
    echo ""
    echo "REMEDIATION:"
    echo "  1. Use PID namespace: unshare --pid --fork"
    echo "  2. Use mount namespace with private /proc"
    echo "  3. Don't mount /proc, or mount a new procfs instance"
else
    echo -e "${GREEN}RESULT: NOT VULNERABLE (or not in chroot)${NC}"
fi
echo "=============================================="

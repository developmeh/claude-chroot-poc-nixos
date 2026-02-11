#!/usr/bin/env bash
# =============================================================================
# FULL VALIDATION SUITE: Run All Chroot Security Checks
# =============================================================================
#
# This script runs all validation scripts and produces a summary report.
#
# USAGE:
#   # From outside chroot (validates host perspective):
#   bash scripts/chroot-validation/10-full-validation-suite.sh
#
#   # From inside chroot (validates chroot perspective):
#   bash /workspace/scripts/chroot-validation/10-full-validation-suite.sh
#
# OUTPUT:
#   - Individual test results displayed
#   - Summary at the end
#   - Exit code 0 if all pass, 1 if any fail
#
# =============================================================================

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
RESULTS=()

run_test() {
    local script="$1"
    local name=$(basename "$script" .sh)

    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Running: $name${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if bash "$script" 2>&1; then
        # Check output for VULNERABLE/EXPOSED
        if bash "$script" 2>&1 | grep -qE 'RESULT: (VULNERABLE|CREDENTIALS EXPOSED|BYPASSABLE|RESOURCE LIMITS MISSING|INFORMATION DISCLOSURE)'; then
            FAILED_TESTS=$((FAILED_TESTS + 1))
            RESULTS+=("${RED}FAIL${NC} $name")
        else
            PASSED_TESTS=$((PASSED_TESTS + 1))
            RESULTS+=("${GREEN}PASS${NC} $name")
        fi
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        RESULTS+=("${RED}ERROR${NC} $name")
    fi
}

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║               CLAUDE CHROOT SECURITY VALIDATION SUITE                        ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Running from: $SCRIPT_DIR"
echo "Date: $(date)"
echo ""

# Run each validation script (except this one)
for script in "$SCRIPT_DIR"/0[1-9]-*.sh; do
    if [[ -f "$script" ]] && [[ -x "$script" || -r "$script" ]]; then
        run_test "$script"
    fi
done

# Summary
echo ""
echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                              VALIDATION SUMMARY                               ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

for result in "${RESULTS[@]}"; do
    echo -e "  $result"
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Total tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"
echo ""

if [[ $FAILED_TESTS -gt 0 ]]; then
    echo -e "${RED}OVERALL: VULNERABILITIES DETECTED${NC}"
    echo ""
    echo "The chroot implementation has security weaknesses."
    echo "Review individual test outputs for remediation guidance."
    exit 1
else
    echo -e "${GREEN}OVERALL: ALL CHECKS PASSED${NC}"
    echo ""
    echo "No obvious vulnerabilities detected in tested areas."
    echo "Note: This does not guarantee complete security."
    exit 0
fi

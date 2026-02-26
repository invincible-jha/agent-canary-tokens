#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
#
# fire-line-audit.sh
#
# Automated FIRE LINE compliance checker for agent-canary-tokens.
# Exits 0 if all checks pass; exits 1 on any violation.
#
# Usage:
#   bash scripts/fire-line-audit.sh
#   bash scripts/fire-line-audit.sh --verbose
#
# Run this script from the repository root.

set -euo pipefail

VERBOSE=0
if [[ "${1:-}" == "--verbose" ]]; then
    VERBOSE=1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/src"
EXAMPLES_DIR="${REPO_ROOT}/examples"

ERRORS=0

# Colour helpers (only when connected to a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' NC=''
fi

log_ok()   { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $*"; ERRORS=$((ERRORS + 1)); }
log_info() { [[ $VERBOSE -eq 1 ]] && echo -e "${YELLOW}[INFO]${NC} $*" || true; }

echo "=== FIRE LINE AUDIT: agent-canary-tokens ==="
echo "Repo root : ${REPO_ROOT}"
echo ""

# ---------------------------------------------------------------------------
# Check 1: No AumOS imports
# ---------------------------------------------------------------------------
AUMOS_PATTERNS=(
    "import aumos_governance"
    "import aumos_types"
    "from aumos_core"
    "from aumos_sdks"
    "from aumos_integrations"
    "from aumos_research"
)

echo "--- Check 1: No AumOS imports ---"
for pattern in "${AUMOS_PATTERNS[@]}"; do
    matches=$(grep -rn --include="*.py" "$pattern" "$SRC_DIR" "$EXAMPLES_DIR" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
        log_fail "Found AumOS import '$pattern':"
        echo "$matches"
    else
        log_ok "No occurrences of '$pattern'"
    fi
done

# ---------------------------------------------------------------------------
# Check 2: No forbidden identifiers
# ---------------------------------------------------------------------------
FORBIDDEN_IDENTIFIERS=(
    "progressLevel"
    "promoteLevel"
    "computeTrustScore"
    "behavioralScore"
    "adaptiveBudget"
    "optimizeBudget"
    "predictSpending"
    "detectAnomaly"
    "generateCounterfactual"
    "PersonalWorldModel"
    "MissionAlignment"
    "SocialTrust"
    "CognitiveLoop"
    "AttentionFilter"
    "GOVERNANCE_PIPELINE"
)

echo ""
echo "--- Check 2: No forbidden identifiers ---"
for identifier in "${FORBIDDEN_IDENTIFIERS[@]}"; do
    matches=$(grep -rn --include="*.py" "$identifier" "$SRC_DIR" "$EXAMPLES_DIR" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
        log_fail "Found forbidden identifier '$identifier':"
        echo "$matches"
    else
        log_ok "No occurrences of '$identifier'"
    fi
done

# ---------------------------------------------------------------------------
# Check 3: SPDX header present in all Python source files
# ---------------------------------------------------------------------------
echo ""
echo "--- Check 3: SPDX license headers ---"
MISSING_SPDX=()
while IFS= read -r -d '' pyfile; do
    if ! head -1 "$pyfile" | grep -q "SPDX-License-Identifier: Apache-2.0"; then
        MISSING_SPDX+=("$pyfile")
    fi
done < <(find "$SRC_DIR" "$EXAMPLES_DIR" -name "*.py" -print0 2>/dev/null)

if [[ ${#MISSING_SPDX[@]} -gt 0 ]]; then
    log_fail "Missing SPDX header in:"
    for f in "${MISSING_SPDX[@]}"; do
        echo "  $f"
    done
else
    log_ok "All Python files have SPDX header"
fi

# ---------------------------------------------------------------------------
# Check 4: No hardcoded latency targets
# ---------------------------------------------------------------------------
LATENCY_PATTERNS=(
    "<[0-9]\+ms"
    "[0-9]\+ms budget"
    "latency.*target"
)

echo ""
echo "--- Check 4: No hardcoded latency targets ---"
for pattern in "${LATENCY_PATTERNS[@]}"; do
    matches=$(grep -rn --include="*.py" "$pattern" "$SRC_DIR" "$EXAMPLES_DIR" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
        log_fail "Found latency target pattern '$pattern':"
        echo "$matches"
    else
        log_ok "No occurrences of '$pattern'"
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== AUDIT COMPLETE ==="
if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}All checks passed. FIRE LINE intact.${NC}"
    exit 0
else
    echo -e "${RED}${ERRORS} violation(s) found. FIRE LINE breached. Fix before merging.${NC}"
    exit 1
fi

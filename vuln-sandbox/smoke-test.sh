#!/usr/bin/env bash
# Smoke test: verify vuln-sandbox produces exactly 1 finding per TP file
# (matching the expected rule ID) and 0 findings per TN file (for the
# corresponding rule ID).
#
# Usage:
#   bash vuln-sandbox/smoke-test.sh [--quick]
#
#   --quick  Skip per-file assertions; only check total finding count >= 115.
#            Useful for fast CI pre-checks before the full validation.
#
# Exit codes:
#   0  All assertions passed
#   1  One or more assertions failed (details printed to stdout)
#   2  Prerequisite missing (sicario or jq not in PATH)
#
# Run from the repo root: bash vuln-sandbox/smoke-test.sh
set -euo pipefail

# --- Argument parsing --------------------------------------------------------
QUICK=0
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# --- Resolve paths -----------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SANDBOX_DIR="$SCRIPT_DIR"
MANIFEST="$SANDBOX_DIR/MANIFEST.md"

# --- Prerequisite checks -----------------------------------------------------
if ! command -v sicario &>/dev/null; then
  echo "x Smoke test FAILED: 'sicario' not found in PATH"
  echo "  Build and install the CLI first: cargo install --path sicario-cli"
  exit 2
fi

if ! command -v jq &>/dev/null; then
  echo "x Smoke test FAILED: 'jq' not found in PATH"
  echo "  Install jq: https://stedolan.github.io/jq/download/"
  exit 2
fi

if [ ! -f "$MANIFEST" ]; then
  echo "x Smoke test FAILED: MANIFEST.md not found at $MANIFEST"
  exit 2
fi

# --- Run the scan ------------------------------------------------------------
echo "Running: sicario scan vuln-sandbox/ --format json"
# Use || true so set -e does not abort when sicario exits 1 (findings found)
SCAN_OUTPUT=$(sicario scan "$SANDBOX_DIR/" --format json 2>/dev/null || true)

# Validate output is parseable JSON array
ACTUAL=$(echo "$SCAN_OUTPUT" | jq 'length' 2>/dev/null || echo "parse_error")

if [ "$ACTUAL" = "parse_error" ]; then
  echo "x Smoke test FAILED: could not parse JSON output from sicario"
  echo "--- Raw output (first 2000 chars) ---"
  echo "$SCAN_OUTPUT" | head -c 2000
  exit 1
fi

echo "Total findings: $ACTUAL"
echo ""

# --- Quick mode: just check total count --------------------------------------
if [ "$QUICK" = "1" ]; then
  MIN_EXPECTED=115
  if [ "$ACTUAL" -lt "$MIN_EXPECTED" ]; then
    echo "x Quick smoke test FAILED: $ACTUAL findings (expected at least $MIN_EXPECTED)"
    exit 1
  fi
  echo "OK Quick smoke test passed: $ACTUAL findings (minimum $MIN_EXPECTED)"
  exit 0
fi

# --- Full mode: per-file/per-rule assertions from MANIFEST.md ----------------
#
# Parse MANIFEST.md table rows. Each row looks like:
#   | `path/to/file.js` | CWE-XX | rule-id | TruePositive | SEVERITY |
#   | `path/to/file-safe.js` | CWE-XX | rule-id | TrueNegative | -- |
#
# We extract: file_path, rule_id, expected_outcome (TruePositive|TrueNegative)

PASS_COUNT=0
FAIL_COUNT=0
FAILURES=""

# Parse MANIFEST.md line by line
while IFS= read -r line; do
  # Match table rows that contain TruePositive or TrueNegative
  if [[ "$line" != *"TruePositive"* && "$line" != *"TrueNegative"* ]]; then
    continue
  fi

  # Extract columns from the markdown table row
  # Format: | `file` | CWE | rule_id | Outcome | Severity |
  # Column indices (1-based after splitting on |):
  #   1: empty (leading pipe)
  #   2: file path (backtick-quoted)
  #   3: CWE
  #   4: rule_id
  #   5: outcome
  #   6: severity

  FILE_COL=$(echo "$line" | awk -F'|' '{print $2}' | tr -d '`[:space:]')
  RULE_COL=$(echo "$line" | awk -F'|' '{print $4}' | tr -d '[:space:]')
  OUTCOME_COL=$(echo "$line" | awk -F'|' '{print $5}' | tr -d '[:space:]')

  # Skip if we could not parse the columns
  if [ -z "$FILE_COL" ] || [ -z "$RULE_COL" ] || [ -z "$OUTCOME_COL" ]; then
    continue
  fi

  # Skip header rows and separator rows
  if [[ "$FILE_COL" == "File" ]] || [[ "$FILE_COL" == "---"* ]]; then
    continue
  fi

  # Count findings for this (file, rule_id) pair.
  # The file path in MANIFEST is relative to vuln-sandbox/ (e.g. "node/cwe-89/sql-injection.js").
  # The scan output file_path may be relative to the scanned dir or absolute.
  # We match on the suffix of the file path.
  MATCH_COUNT=$(echo "$SCAN_OUTPUT" | jq --arg file "$FILE_COL" --arg rule "$RULE_COL" '
    [.[] | select(
      (.file_path | endswith($file)) and
      (.rule_id == $rule)
    )] | length
  ')

  if [ "$OUTCOME_COL" = "TruePositive" ]; then
    # Expect exactly 1 finding
    if [ "$MATCH_COUNT" -eq 1 ]; then
      PASS_COUNT=$((PASS_COUNT + 1))
    else
      FAIL_COUNT=$((FAIL_COUNT + 1))
      FAILURES="${FAILURES}
  x TP FAIL: $FILE_COL (rule: $RULE_COL) -- expected 1 finding, got $MATCH_COUNT"
    fi
  elif [ "$OUTCOME_COL" = "TrueNegative" ]; then
    # Expect exactly 0 findings for this rule_id in this file
    if [ "$MATCH_COUNT" -eq 0 ]; then
      PASS_COUNT=$((PASS_COUNT + 1))
    else
      FAIL_COUNT=$((FAIL_COUNT + 1))
      FAILURES="${FAILURES}
  x TN FAIL: $FILE_COL (rule: $RULE_COL) -- expected 0 findings, got $MATCH_COUNT"
    fi
  fi

done < "$MANIFEST"

TOTAL_CHECKED=$((PASS_COUNT + FAIL_COUNT))

echo "Assertions checked: $TOTAL_CHECKED"
echo "  Passed: $PASS_COUNT"
echo "  Failed: $FAIL_COUNT"
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "x Smoke test FAILED: $FAIL_COUNT assertion(s) did not pass:"
  echo "$FAILURES"
  echo ""
  echo "Breakdown by severity:"
  echo "$SCAN_OUTPUT" | jq 'group_by(.severity) | map({severity: .[0].severity, count: length}) | sort_by(.severity)'
  exit 1
fi

if [ "$TOTAL_CHECKED" -eq 0 ]; then
  echo "x Smoke test FAILED: no TP/TN entries found in MANIFEST.md -- check the manifest format"
  exit 1
fi

echo "OK Smoke test passed: $PASS_COUNT/$TOTAL_CHECKED assertions passed"
echo ""
echo "Breakdown by severity:"
echo "$SCAN_OUTPUT" | jq 'group_by(.severity) | map({severity: .[0].severity, count: length}) | sort_by(.severity)'
exit 0

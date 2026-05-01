#!/usr/bin/env bash
# Smoke test: verify vuln-sandbox produces at least 79 findings (one per file)
# Run from the repo root: bash vuln-sandbox/smoke-test.sh
set -euo pipefail

# Resolve the repo root (one level up from this script's directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

if ! command -v sicario &>/dev/null; then
  echo "✗ Smoke test FAILED: 'sicario' not found in PATH"
  echo "  Build and install the CLI first: cargo install --path sicario-cli"
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo "✗ Smoke test FAILED: 'jq' not found in PATH"
  echo "  Install jq: https://stedolan.github.io/jq/download/"
  exit 1
fi

echo "Running: sicario scan vuln-sandbox/ --format json"
SCAN_OUTPUT=$(sicario scan "$REPO_ROOT/vuln-sandbox/" --format json 2>&1)

ACTUAL=$(echo "$SCAN_OUTPUT" | jq 'length' 2>/dev/null || echo "parse_error")

if [ "$ACTUAL" = "parse_error" ]; then
  echo "✗ Smoke test FAILED: could not parse JSON output from sicario"
  echo "--- Raw output ---"
  echo "$SCAN_OUTPUT"
  exit 1
fi

# Must find at least one finding per vuln-sandbox file (79 files)
MIN_EXPECTED=79

if [ "$ACTUAL" -lt "$MIN_EXPECTED" ]; then
  echo "✗ Smoke test FAILED: $ACTUAL findings (expected at least $MIN_EXPECTED)"
  echo ""
  echo "Breakdown by severity:"
  echo "$SCAN_OUTPUT" | jq 'group_by(.severity) | map({severity: .[0].severity, count: length}) | sort_by(.severity)'
  exit 1
fi

echo "✓ Smoke test passed: $ACTUAL findings (minimum $MIN_EXPECTED)"
echo ""
echo "Breakdown by severity:"
echo "$SCAN_OUTPUT" | jq 'group_by(.severity) | map({severity: .[0].severity, count: length}) | sort_by(.severity)'
exit 0

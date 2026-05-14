#!/usr/bin/env bash
# MANIFEST.md validation script
# Verifies that MANIFEST.md is complete and accurate:
#   1. Every file listed in MANIFEST.md exists on disk
#   2. Every source file in vuln-sandbox/ is listed in MANIFEST.md
#   3. Every MANIFEST entry has required fields (CWE, rule ID, expected outcome)
#
# Usage:
#   bash vuln-sandbox/validate-manifest.sh
#
# Exit codes:
#   0  Validation passed
#   1  Validation failed (details printed to stdout)
#   2  Prerequisite missing
#
# Run from the repo root: bash vuln-sandbox/validate-manifest.sh
set -euo pipefail

# --- Resolve paths -----------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SANDBOX_DIR="$SCRIPT_DIR"
MANIFEST="$SANDBOX_DIR/MANIFEST.md"

# --- Prerequisite checks -----------------------------------------------------
if [ ! -f "$MANIFEST" ]; then
  echo "x MANIFEST validation FAILED: MANIFEST.md not found at $MANIFEST"
  exit 2
fi

# --- Parse MANIFEST.md and collect file paths --------------------------------
echo "Validating MANIFEST.md..."
echo ""

MANIFEST_FILES=()
MISSING_FILES=()
INVALID_ENTRIES=()
LINE_NUM=0

while IFS= read -r line; do
  LINE_NUM=$((LINE_NUM + 1))
  
  # Match table rows that contain TruePositive or TrueNegative
  if [[ "$line" != *"TruePositive"* && "$line" != *"TrueNegative"* ]]; then
    continue
  fi

  # Extract columns from the markdown table row
  # Format: | `file` | CWE | rule_id | Outcome | Severity |
  FILE_COL=$(echo "$line" | awk -F'|' '{print $2}' | tr -d '`[:space:]')
  CWE_COL=$(echo "$line" | awk -F'|' '{print $3}' | tr -d '[:space:]')
  RULE_COL=$(echo "$line" | awk -F'|' '{print $4}' | tr -d '[:space:]')
  OUTCOME_COL=$(echo "$line" | awk -F'|' '{print $5}' | tr -d '[:space:]')

  # Skip header rows and separator rows
  if [[ "$FILE_COL" == "File" ]] || [[ "$FILE_COL" == "---"* ]]; then
    continue
  fi

  # Skip if we could not parse the columns
  if [ -z "$FILE_COL" ]; then
    continue
  fi

  # Validate required fields are present
  if [ -z "$CWE_COL" ] || [ -z "$RULE_COL" ] || [ -z "$OUTCOME_COL" ]; then
    INVALID_ENTRIES+=("Line $LINE_NUM: Missing required field(s) for file: $FILE_COL")
    continue
  fi

  # Validate outcome is TruePositive or TrueNegative
  if [[ "$OUTCOME_COL" != "TruePositive" && "$OUTCOME_COL" != "TrueNegative" ]]; then
    INVALID_ENTRIES+=("Line $LINE_NUM: Invalid outcome '$OUTCOME_COL' for file: $FILE_COL (must be TruePositive or TrueNegative)")
    continue
  fi

  # Validate CWE format
  if [[ ! "$CWE_COL" =~ ^CWE-[0-9]+$ ]]; then
    INVALID_ENTRIES+=("Line $LINE_NUM: Invalid CWE format '$CWE_COL' for file: $FILE_COL (must be CWE-XXX)")
    continue
  fi

  # Add to manifest files list
  MANIFEST_FILES+=("$FILE_COL")

  # Check if file exists on disk
  FULL_PATH="$SANDBOX_DIR/$FILE_COL"
  if [ ! -f "$FULL_PATH" ]; then
    MISSING_FILES+=("$FILE_COL")
  fi

done < "$MANIFEST"

# --- Check for files on disk not in MANIFEST --------------------------------
ORPHANED_FILES=()

# Find all source files in vuln-sandbox subdirectories
# Exclude: MANIFEST.md, README.md, AUDIT.md, smoke-test.sh, validate-manifest.sh, .sicario/
while IFS= read -r file; do
  # Get relative path from vuln-sandbox/
  REL_PATH="${file#$SANDBOX_DIR/}"
  
  # Skip if it's a known non-source file
  if [[ "$REL_PATH" == "MANIFEST.md" ]] || \
     [[ "$REL_PATH" == "README.md" ]] || \
     [[ "$REL_PATH" == "AUDIT.md" ]] || \
     [[ "$REL_PATH" == "smoke-test.sh" ]] || \
     [[ "$REL_PATH" == "validate-manifest.sh" ]] || \
     [[ "$REL_PATH" == ".sicario/"* ]]; then
    continue
  fi
  
  # Check if this file is in MANIFEST_FILES
  FOUND=0
  for manifest_file in "${MANIFEST_FILES[@]}"; do
    if [ "$REL_PATH" = "$manifest_file" ]; then
      FOUND=1
      break
    fi
  done
  
  if [ "$FOUND" -eq 0 ]; then
    ORPHANED_FILES+=("$REL_PATH")
  fi
  
done < <(find "$SANDBOX_DIR" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.tsx" -o -name "*.py" -o -name "*.go" -o -name "*.java" -o -name "*.rs" \))

# --- Report results ----------------------------------------------------------
TOTAL_MANIFEST_ENTRIES=${#MANIFEST_FILES[@]}
TOTAL_MISSING=${#MISSING_FILES[@]}
TOTAL_ORPHANED=${#ORPHANED_FILES[@]}
TOTAL_INVALID=${#INVALID_ENTRIES[@]}

echo "MANIFEST.md entries: $TOTAL_MANIFEST_ENTRIES"
echo "Missing files: $TOTAL_MISSING"
echo "Orphaned files: $TOTAL_ORPHANED"
echo "Invalid entries: $TOTAL_INVALID"
echo ""

FAILED=0

if [ "$TOTAL_INVALID" -gt 0 ]; then
  echo "x VALIDATION FAILED: $TOTAL_INVALID invalid MANIFEST entries:"
  for entry in "${INVALID_ENTRIES[@]}"; do
    echo "  - $entry"
  done
  echo ""
  FAILED=1
fi

if [ "$TOTAL_MISSING" -gt 0 ]; then
  echo "x VALIDATION FAILED: $TOTAL_MISSING files listed in MANIFEST.md do not exist on disk:"
  for file in "${MISSING_FILES[@]}"; do
    echo "  - $file"
  done
  echo ""
  FAILED=1
fi

if [ "$TOTAL_ORPHANED" -gt 0 ]; then
  echo "x VALIDATION FAILED: $TOTAL_ORPHANED source files exist but are not listed in MANIFEST.md:"
  for file in "${ORPHANED_FILES[@]}"; do
    echo "  - $file"
  done
  echo ""
  echo "Add these files to MANIFEST.md with their CWE, rule ID, and expected outcome."
  FAILED=1
fi

if [ "$FAILED" -eq 1 ]; then
  exit 1
fi

if [ "$TOTAL_MANIFEST_ENTRIES" -eq 0 ]; then
  echo "x VALIDATION FAILED: no entries found in MANIFEST.md -- check the manifest format"
  exit 1
fi

echo "OK MANIFEST validation passed: $TOTAL_MANIFEST_ENTRIES entries validated"
exit 0

> **Integration**

# Baseline Management

Baselines allow you to capture the current state of security findings and use that snapshot as a reference point for future scans. This is essential for established codebases that have existing (known) vulnerabilities — instead of being blocked on every scan, you can suppress known issues and focus strictly on **new** vulnerabilities introduced by new code.

---

## What Is a Baseline?

A baseline is a snapshot of finding fingerprints captured at a specific point in time. Each baseline contains:

- **Finding fingerprints**: SHA-256 hashes of `(file_path + rule_id + matched_code + match_index)` used for stable identification across scans
- **Tag metadata**: An optional human-readable tag (e.g., `v1.0`, `sprint-12`)
- **Timestamp**: When the baseline was created
- **Scan summary**: Total findings count, breakdown by severity

Baselines are stored locally in the project's `.sicario/baselines/` directory:

```
.sicario/baselines/
  v1.0.json
  v1.1.json
  v2.0.json
  latest.json        # Symlink or copy of the most recent baseline
```

### Why Use a Baseline?

| Scenario | Without Baseline | With Baseline |
|----------|-----------------|---------------|
| **Existing codebase** | Hundreds of pre-existing findings block every PR | Known issues are suppressed; only new findings are reported |
| **Release gating** | No objective measure of "is this release more secure?" | Compare current scan against release tag baseline |
| **Security debt tracking** | No way to measure progress | Trend analysis shows finding counts over time |
| **CI/CD enforcement** | Must pass the entire scan, including legacy issues | Fail only on **new** findings above threshold |

---

## `sicario baseline save`

Capture the current state of findings as a baseline snapshot.

### Usage

```bash
# Save with a tag
sicario baseline save --tag v1.0

# Save with a tag (explicit format)
sicario baseline save --tag sprint-45 --format json
```

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `--tag` | string | A human-readable tag for this baseline. Recommended format: `v<major>.<minor>` or `<project>-<date>`. |
| `--format` | string | Output format: `json` (default) or `text`. |

### How Baselines Work

When you run `sicario baseline save`, the CLI:

1. Runs a full scan of the current directory (equivalent to `sicario scan .`)
2. Computes a **fingerprint** for each finding using SHA-256 of `(file_path + rule_id + pattern_with_values)`
3. Stores the fingerprints along with severity, file path, and rule ID in the baseline file
4. Writes the baseline to `.sicario/baselines/<tag>.json`

The fingerprint includes an `_<index>` suffix for disambiguation when multiple matches of the same rule appear in the same file.

### Examples

```bash
# Tag a baseline for a release
sicario baseline save --tag v2.3.0

# Tag for a sprint review
sicario baseline save --tag sprint-12

# Tag with a date-based naming scheme
sicario baseline save --tag $(date +%Y-%m-%d)

# Use a descriptive label for a major refactor
sicario baseline save --tag pre-refactor-auth-module
```

> **Best Practice**: Save a baseline at every release tag. This gives you clear checkpoints for tracking security debt.

---

## `sicario baseline compare`

Compare the current scan results against a saved baseline. This shows what findings are **new** (not in the baseline) versus **pre-existing** (already in the baseline).

### Usage

```bash
# Compare against a specific tag
sicario baseline compare v1.0

# Compare against the most recent baseline (no argument)
sicario baseline compare

# Output in text format
sicario baseline compare v1.0 --format text
```

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `reference` | string (positional) | Tag or timestamp of the baseline to compare against. If omitted, uses the most recent baseline. |
| `--format` | string | Output format: `json` (default) or `text`. |

### Output

```json
{
  "baseline": "v1.0",
  "baseline_timestamp": "2025-11-15T10:30:00Z",
  "total_previous": 47,
  "total_current": 52,
  "new_findings": [
    {
      "rule_id": "js/sql-injection",
      "file": "src/api/users.ts",
      "line": 142,
      "severity": "High"
    },
    {
      "rule_id": "py/insecure-deserialization",
      "file": "src/worker/tasks.py",
      "line": 67,
      "severity": "Critical"
    }
  ],
  "resolved_findings": [
    {
      "rule_id": "js/console-log",
      "file": "src/debug.ts",
      "line": 10,
      "severity": "Low"
    }
  ],
  "new_count": 5,
  "resolved_count": 3,
  "net_change": 2
}
```

The comparison algorithm:

1. **Fingerprint matching**: Each current finding's fingerprint is compared against all baseline fingerprints
2. **Not found in baseline** → classified as `new_finding`
3. **Found in baseline but not in current scan** → classified as `resolved_finding`
4. **Found in both** → pre-existing, not reported in the diff output

### Using in CI/CD

Compare against the baseline and fail the build on new findings:

```bash
# With the diff subcommand (CI-friendly)
sicario baseline diff --ci --threshold high --tag v1.0

# Manual approach in a script
sicario baseline compare v1.0 --format json > comparison.json
NEW_COUNT=$(jq '.new_count' comparison.json)
if [ "$NEW_COUNT" -gt 0 ]; then
  echo "FAIL: $NEW_COUNT new vulnerabilities introduced"
  exit 1
fi
```

The `baseline diff` subcommand is specifically designed for CI/CD:

| Argument | Type | Description |
|----------|------|-------------|
| `reference` | string (positional, optional) | Tag or timestamp to compare against. Uses most recent if omitted. |
| `--ci` | flag | Exit with code 1 on new findings above the threshold |
| `--threshold` | string | Minimum severity for CI blocking: `low`, `medium`, `high`, `critical`. Default: `high`. |
| `--tag` | string | Tag of a named baseline to compare against |

```bash
# CI-friendly: exit 1 if new High+ findings exist
sicario baseline diff --ci --threshold high --tag v1.0

# CI-friendly: exit 1 if any new findings exist (strict)
sicario baseline diff --ci --threshold low --tag v1.0
```

---

## `sicario baseline trend`

View finding count trends across all saved baselines. This gives you a historical view of security debt over time.

### Usage

```bash
# Show trend data
sicario baseline trend

# Output as JSON for programmatic consumption
sicario baseline trend --format json
```

### Output (Text)

```
Baseline Trend Report
══════════════════════

Tag           Date                  Total    Critical    High    Medium    Low
─────         ──────────            ─────    ────────    ────    ──────    ───
v1.0          2025-01-15T10:30Z     47       3           12      18        14
v1.1          2025-02-01T14:00Z     45       2           11      18        14
v2.0          2025-03-10T09:00Z     38       1            8      16        13
v2.1          2025-04-05T16:30Z     35       1            7      14        13

Net change:  -12 findings (-25.5%)
Critical:    -2 (-66.7%)
High:        -5 (-41.7%)
```

### Output (JSON)

```json
{
  "baselines": [
    { "tag": "v1.0", "timestamp": "2025-01-15T10:30:00Z", "total": 47, "critical": 3, "high": 12, "medium": 18, "low": 14 },
    { "tag": "v1.1", "timestamp": "2025-02-01T14:00:00Z", "total": 45, "critical": 2, "high": 11, "medium": 18, "low": 14 },
    { "tag": "v2.0", "timestamp": "2025-03-10T09:00:00Z", "total": 38, "critical": 1, "high": 8, "medium": 16, "low": 13 },
    { "tag": "v2.1", "timestamp": "2025-04-05T16:30:00Z", "total": 35, "critical": 1, "high": 7, "medium": 14, "low": 13 }
  ],
  "net_change": -12,
  "net_change_pct": -25.5
}
```

> **Tip**: Use the trend output in team dashboards or security review meetings to demonstrate remediation progress.

---

## Baseline Workflow Best Practices

### 1. Save a Baseline Before Major Refactors

Before refactoring a module, save a baseline to capture its current security state:

```bash
# Before refactoring the auth module
sicario baseline save --tag pre-refactor-auth

# ... perform the refactor ...

# After refactoring, compare to see if you introduced new issues
sicario baseline compare pre-refactor-auth
```

### 2. Save Baselines at Release Tags

Integrate baseline saving into your release process:

```bash
# In your release script
VERSION=$(git describe --tags --abbrev=0)
sicario baseline save --tag "$VERSION"
```

### 3. CI/CD: Compare Against Baseline, Fail on New Findings

In your CI/CD pipeline, use `baseline diff` to enforce that no new High+ vulnerabilities are introduced:

```yaml
# GitHub Actions
- name: Save baseline for main branch
  if: github.ref == 'refs/heads/main'
  run: sicario baseline save --tag main-latest

- name: Check for new findings on PR
  if: github.event_name == 'pull_request'
  run: sicario baseline diff --ci --threshold high --tag main-latest
```

### 4. Track Trends in Security Reviews

Use `sicario baseline trend` in your quarterly security review to demonstrate progress.

---

## Managing Multiple Baselines

Baselines are stored per-project in `.sicario/baselines/`. Multiple projects maintain their own independent baseline sets.

### Baseline Storage Format

Each baseline is a JSON file at `.sicario/baselines/<tag>.json`:

```json
{
  "tag": "v2.1",
  "timestamp": "2025-04-05T16:30:00Z",
  "findings": [
    {
      "fingerprint": "sha256:abc123def456..._0",
      "rule_id": "js/sql-injection",
      "file": "src/api/users.ts",
      "line": 142,
      "severity": "High"
    }
  ],
  "summary": {
    "total": 35,
    "critical": 1,
    "high": 7,
    "medium": 14,
    "low": 13
  }
}
```

### Listing All Baselines

```bash
ls -la .sicario/baselines/
```

### Removing a Baseline

```bash
rm .sicario/baselines/v0.9.json
```

---

## Troubleshooting

### Baseline Comparison Shows No New Findings (When There Should Be)

**Problem**: You know there are new vulnerabilities, but `baseline compare` reports zero new findings.

**Solutions**:

1. **Check the baseline reference**: Ensure you're comparing against the correct baseline tag
   ```bash
   sicario baseline compare v1.0  # Explicit tag
   ```

2. **Check the baseline is fresh enough**: If the baseline was saved after the new vulnerabilities were introduced, those findings are already in the baseline.
   ```bash
   # Save a fresh baseline first
   sicario baseline save --tag fresh-baseline
   ```

3. **Fingerprint collisions**: Very rarely, different findings can produce the same fingerprint. This is a SHA-256 collision risk that is astronomically unlikely in practice.

### Stale Baselines Over Time

**Problem**: After months of development, the baseline contains findings from files that no longer exist.

**Baselines do not auto-expire**. Stale entries (findings for deleted files) are simply ignored during comparison — they won't match any current finding, so they're not reported as "new."

To refresh a baseline periodically:

```bash
# Save a new baseline at each major release
sicario baseline save --tag v$(date +%Y.%m)
```

### Baseline "Conflicts" Across Branches

**Problem**: Two branches have different baseline states, causing inconsistent CI results.

**The baseline file is not a lock — it's a snapshot**. Each branch should save its own baseline. The recommended approach:

1. **Main branch**: Save baselines on every merge
2. **Feature branches**: Compare against the main branch baseline
3. **Release branches**: Save baselines at release tags only

### Cannot Find Baseline File

**Problem**: `Error: baseline not found` when running `baseline compare`.

**Solutions**:

- Verify the baseline exists:
  ```bash
  ls .sicario/baselines/
  ```

- Check the exact tag name:
  ```bash
  sicario baseline compare  # Omits tag, uses most recent baseline
  ```

- If no baselines exist, create one:
  ```bash
  sicario baseline save --tag initial
  ```

---

## Cloud Dashboard Integration

When logged into Sicario Cloud (`sicario login`), baseline data is synchronized to the cloud dashboard for visual trending:

```bash
# Scan, compare against baseline, and publish
sicario scan . --publish
sicario baseline compare v1.0 --format json
```

The cloud dashboard provides:

- **Finding trend charts** — visualize total, new, and resolved findings over time
- **Severity breakdowns** — see how Critical/High/Medium/Low counts change across baselines
- **Team metrics** — track remediation velocity per developer or team

---

## Related

- [Suppressions](./suppressions) — Inline suppression directives for individual findings
- [CI/CD Integration](./ci-cd) — Using baselines in pipeline gates
- [Configuration](./configuration) — Project and global configuration
- [Reporting](./reporting) — OWASP compliance and SARIF reporting

---

## Next Steps

1. Save your [first baseline](./sicario-baseline-save) for the current codebase state
2. Integrate [baseline comparison](./sicario-baseline-compare) into your CI/CD pipeline
3. Establish a [release tagging strategy](./#save-baselines-at-release-tags) for baselines
4. Review [trend data](./sicario-baseline-trend) monthly to track security debt
5. Share trend reports with your team during security reviews

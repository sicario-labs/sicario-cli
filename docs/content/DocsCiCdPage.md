> **Integration**

# CI/CD Integration

Sicario is designed from the ground up to run natively in any CI/CD pipeline. It produces standard exit codes, supports SARIF output for GitHub Code Scanning and other platforms, and integrates with GitHub Actions, GitLab CI/CD, Bitbucket Pipelines, and pre-commit hooks. This page covers everything you need to embed Sicario into your delivery pipeline and enforce security gates automatically.

---

## Why CI/CD Integration Matters

Running security scanners only on a developer's workstation creates a gap: vulnerabilities can be introduced via merged PRs, dependency updates, or misconfigured infrastructure. Embedding Sicario into your CI/CD pipeline ensures that **every commit, every PR, and every release is scanned before it reaches production**.

Key benefits:

- **Shift left without relying on developer discipline** — the pipeline enforces scans
- **Block PRs automatically** when High or Critical vulnerabilities are introduced
- **Track findings over time** with baseline comparisons and trend analysis
- **Generate compliance artifacts** (SARIF, OWASP reports) as build outputs
- **Publish to the Sicario Cloud dashboard** for team-wide visibility

---

## Exit Codes

Sicario uses standard Unix exit codes to communicate scan results to the CI runner. Every subcommand (`scan`, `ci`, `fix`, etc.) returns one of three codes:

| Exit Code | Meaning | Description |
|-----------|---------|-------------|
| `0` | **Clean** | Scan completed successfully. No findings at or above the severity/confidence threshold. |
| `1` | **Findings Detected** | Scan completed successfully. One or more findings at or above the severity/confidence threshold were detected and not suppressed. |
| `2` | **Internal Error** | The CLI encountered an error before or during scanning (e.g., malformed config, missing directory, invalid flags). |

### Exit Code Computation Logic

The exit code is computed in `cli::exit_code::ExitCode::from_findings()`:

```rust
pub fn from_findings(
    findings: &[FindingSummary],
    severity_threshold: Severity,
    confidence_threshold: f64,
) -> ExitCode {
    let actionable = findings.iter().any(|f| {
        !f.suppressed
            && f.severity >= severity_threshold
            && f.confidence_score >= confidence_threshold
    });
    if actionable { ExitCode::FindingsDetected } else { ExitCode::Clean }
}
```

A finding must satisfy **all three** criteria to trigger exit code 1:

1. **`!suppressed`** — The finding is not suppressed by an inline `// sicario-ignore` directive
2. **`severity >= severity_threshold`** — The finding's severity meets or exceeds the threshold
3. **`confidence_score >= confidence_threshold`** — The finding's confidence score meets or exceeds the confidence threshold

This means suppressed findings never cause a pipeline failure, even if they are Critical severity.

### Using Exit Codes

In any shell-based CI system, you can check the exit code directly:

```bash
sicario scan .
if [ $? -eq 0 ]; then
  echo "Clean scan — no vulnerabilities above threshold"
elif [ $? -eq 1 ]; then
  echo "Vulnerabilities detected — failing build"
  exit 1
fi
```

However, most CI systems automatically fail the step when a command returns a non-zero exit code, so the explicit check is usually unnecessary.

---

## Severity Threshold & `--fail-on`

The `--fail-on` flag controls the minimum severity level that triggers a non-zero exit code. By default, if not specified, Sicario will fall back to the `SICARIO_FAIL_ON` environment variable, and if neither is set, the default is **High**.

### Available Levels

| Level | Behavior |
|-------|----------|
| `Critical` | Exit 1 only on Critical findings. Low/Medium/High findings are reported but do not fail the build. |
| `High` | Exit 1 on High or Critical findings (default). |
| `Medium` | Exit 1 on Medium, High, or Critical findings. |
| `Low` | Exit 1 on any finding (Low and above). |

### Usage

```bash
# Fail only on Critical findings
sicario scan . --fail-on Critical

# Fail on Medium and above (stricter)
sicario scan . --fail-on Medium

# Fail on any finding (strictest)
sicario scan . --fail-on Low
```

### Priority Resolution

The priority chain for resolving `--fail-on` is:

1. **`--fail-on` CLI flag** (highest priority)
2. **`SICARIO_FAIL_ON` environment variable**
3. **Policy file** (`.sicario/policy.yaml` — `fail_on` field overrides CLI)
4. **Default**: `High`

```rust
pub fn resolve_fail_on(&self) -> Result<Severity, String> {
    if let Some(level) = self.fail_on {
        return Ok(level.into());
    }
    if let Ok(val) = std::env::var("SICARIO_FAIL_ON") {
        return parse_fail_on_str(&val);
    }
    // Policy file override is checked separately in cmd_scan
    Ok(Severity::High) // default
}
```

### Additional Fail-On Flags

Sicario supports two specialized fail-on flags beyond severity:

- **`--fail-on-license <LEVEL>`** — Exit code 1 when dependencies with High or Medium license risk are detected. Useful for enforcing license compliance in CI. Accepts `HIGH` or `MEDIUM` (case-insensitive).

  ```bash
  sicario scan . --fail-on-license HIGH
  ```

- **`--fail-on-reachable`** — Exit code 1 only for SCA vulnerabilities that are reachable through data-flow analysis. This filters out dependency vulnerabilities in unused packages, reducing false-positive-driven build failures.

  ```bash
  sicario scan . --fail-on-reachable
  ```

### Using `--severity-threshold`

The `--severity-threshold` flag is distinct from `--fail-on`. It controls the **minimum severity to report in output**, while `--fail-on` controls the minimum severity to fail the build:

```bash
# Report all findings (including Low) but only fail on High+
sicario scan . --severity-threshold low --fail-on High
```

If `--severity-threshold` is not specified, it defaults to `Low`.

---

## GitHub Actions Integration

GitHub Actions is the recommended CI platform for Sicario. The integration supports SARIF upload for GitHub Code Scanning alerts, PR annotations, and conditional pass/fail gating.

### Complete Workflow

```yaml
# .github/workflows/sicario-scan.yml
name: Sicario Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  sicario-scan:
    runs-on: ubuntu-latest

    # Permissions required for SARIF upload and code scanning
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      # ── Step 1: Checkout code ────────────────────────────────────────
      - name: Checkout repository
        uses: actions/checkout@v4

      # ── Step 2: Install Sicario CLI ─────────────────────────────────
      - name: Install Sicario
        run: |
          curl -fsSL https://usesicario.xyz/install.sh | sh
          echo "$HOME/.sicario/bin" >> $GITHUB_PATH

      # ── Step 3: Run the scan ─────────────────────────────────────────
      - name: Run Sicario Scan
        id: scan
        continue-on-error: true
        run: |
          sicario scan . \
            --format sarif \
            --sarif-output results.sarif \
            --fail-on High

      # ── Step 4: Upload SARIF to GitHub Code Scanning ────────────────
      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
          category: sicario

      # ── Step 5: Conditional failure based on Sicario exit code ─────
      - name: Fail on critical findings
        if: steps.scan.outcome == 'failure'
        run: |
          echo "::error::Sicario detected vulnerabilities at or above the threshold."
          exit 1
```

> **Important**: The `security-events: write` permission is required for the SARIF upload step. Without it, GitHub Code Scanning alerts will not appear.

### Step-by-Step Breakdown

#### Step 1: Checkout

Uses the standard `actions/checkout@v4` action. For pull request scans, this automatically checks out the merge commit between the PR branch and the target branch.

#### Step 2: Install

The installation script downloads the latest Sicario binary for the runner architecture:

```bash
curl -fsSL https://usesicario.xyz/install.sh | sh
```

The script installs Sicario to `~/.sicario/bin/sicario`. Add this to `$GITHUB_PATH` so subsequent steps can find the binary.

> **Windows runners** — Use the PowerShell installer:
> ```powershell
> irm https://usesicario.xyz/install.ps1 | iex
> ```

#### Step 3: Run the Scan

Key flags used:

| Flag | Purpose |
|------|---------|
| `--format sarif` | Output findings in SARIF JSON format on stdout |
| `--sarif-output results.sarif` | Write SARIF to a file (required for upload-sarif action) |
| `--fail-on High` | Exit 1 when any High or Critical finding is detected |

The `continue-on-error: true` prevents the workflow from failing immediately, allowing the SARIF upload step to run regardless of scan results.

> **Tip**: Add `--secrets` and `--sca` to scan for secrets and dependency vulnerabilities in addition to SAST:
> ```bash
> sicario scan . --format sarif --sarif-output results.sarif --fail-on High --secrets --sca
> ```

#### Step 4: Upload SARIF

The `github/codeql-action/upload-sarif@v3` action uploads the SARIF file to GitHub Code Scanning. Findings appear under the **Security > Code scanning** tab in your repository.

- `if: always()` ensures upload happens even if the scan step failed (exit code 1)
- `category: sicario` distinguishes Sicario findings from CodeQL or other scanners

#### Step 5: Conditional Failure

After SARIF upload, the workflow explicitly fails if Sicario returned a non-zero exit code:

```yaml
if: steps.scan.outcome == 'failure'
```

This ensures the PR is blocked while still providing Code Scanning alerts.

### PR Annotations

When SARIF is uploaded for a pull request, GitHub automatically creates:
- **PR Check Run annotations** — inline code annotations on the diff for each finding
- **Code Scanning alerts** — visible under the Security tab
- **PR comment summaries** — a summary of new findings introduced by the PR

No additional configuration is needed.

---

## GitLab CI/CD Integration

GitLab CI/CD supports Sicario through custom job definitions. SARIF artifacts can be uploaded manually (GitLab does not have native SARIF ingestion like GitHub, but GitLab 16+ supports it).

### Complete `.gitlab-ci.yml`

```yaml
# .gitlab-ci.yml
sicario-scan:
  stage: test
  image: alpine:3.19
  variables:
    SICARIO_FAIL_ON: "High"
    SICARIO_SEVERITY_THRESHOLD: "Low"

  before_script:
    - apk add --no-cache curl bash
    - curl -fsSL https://usesicario.xyz/install.sh | sh
    - export PATH="$HOME/.sicario/bin:$PATH"

  script:
    - sicario scan . --format sarif --sarif-output sicario-results.sarif --fail-on High

  artifacts:
    paths:
      - sicario-results.sarif
    reports:
      sast: sicario-results.sarif
    expire_in: 30 days

  only:
    - main
    - merge_requests
```

> **GitLab Ultimate** users can configure the `reports: sast` field to display Sicario findings in the **Security** tab natively.

### GitLab 16+ Native SARIF Support

GitLab 16 supports native SARIF ingestion under the **Security & Compliance > Vulnerability Report**:

```yaml
sicario-scan:
  stage: test
  script:
    - curl -fsSL https://usesicario.xyz/install.sh | sh
    - export PATH="$HOME/.sicario/bin:$PATH"
    - sicario scan . --format sarif --sarif-output gl-sast-report.sarif --fail-on High
  artifacts:
    reports:
      sast: gl-sast-report.sarif
```

The file must be named `gl-sast-report.sarif` for GitLab's auto-detection.

### Merge Request Comments

To add a comment with finding summaries on merge requests, combine with a custom script:

```yaml
sicario-scan:
  script:
    - curl -fsSL https://usesicario.xyz/install.sh | sh
    - export PATH="$HOME/.sicario/bin:$PATH"
    - sicario scan . --format json --output sicario-results.json --fail-on High 2>&1 | tee scan-output.txt
  after_script:
    - |
      if grep -q "High" scan-output.txt || grep -q "Critical" scan-output.txt; then
        curl --request POST \
          --header "PRIVATE-TOKEN: $CI_JOB_TOKEN" \
          --header "Content-Type: application/json" \
          --data "{ \"body\": \"⚠️ Sicario found High/Critical vulnerabilities in this MR. See pipeline artifacts for full report.\" }" \
          "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes"
      fi
```

---

## Pre-Commit Hooks

Sicario provides two pre-commit hook modes: a standard scan hook and an auto-fix ("Ghost Fix") hook.

### Installing the Standard Hook

```bash
sicario hook install
```

This installs a pre-commit hook at `.git/hooks/pre-commit` that runs:

```bash
sicario scan --staged --secrets --fail-on medium
```

Only staged files are scanned (`--staged`), and the commit is blocked if any Medium+ finding is detected.

### Installing the Auto-Fix Hook (Ghost Fix Mode)

```bash
sicario hook install --hook-mode
```

The `--hook-mode` flag (aliased as `sicario hook auto-fix`) installs a more sophisticated hook that:

1. **Attempts automatic remediation** — runs `sicario fix --staged` on all staged files
2. **On success** — auto-stages the fixed files via `git add` and allows the commit to proceed
3. **On failure** — blocks the commit with a prompt to apply or abort

The hook behavior when High/Critical findings remain unfixed:

```
🛑 Sicario Intercept: 3 Critical Vulnerabilities found (e.g., SQL Injection in src/db.js)
Our local engine has generated a secure, verified patch.
Apply fix and continue commit? [Y/n]
```

- Typing `Y` or pressing Enter: applies the template-based fix, re-stages the file, and continues the commit
- Typing `n`: blocks the commit (exit code 1)

### Skipping the Hook

To bypass the Sicario hook for a specific commit:

```bash
SICARIO_SKIP_HOOK=1 git commit -m "WIP: temporary skip"
```

The hook script checks for this environment variable at the very beginning and exits 0 (success) immediately without scanning.

### Verification

Check whether the Sicario pre-commit hook is installed:

```bash
sicario hook status
```

Output:

```
Sicario pre-commit hook: installed
  Command: sicario scan --staged --secrets --fail-on medium
```

### Uninstalling

```bash
sicario hook uninstall
```

This removes only the Sicario marker block from `.git/hooks/pre-commit`, preserving any other hook content that existed before installation.

---

## Bitbucket Pipelines

Bitbucket Pipelines can run Sicario with minimal configuration:

```yaml
# bitbucket-pipelines.yml
pipelines:
  default:
    - step:
        name: Security Scan
        script:
          - curl -fsSL https://usesicario.xyz/install.sh | sh
          - export PATH="$HOME/.sicario/bin:$PATH"
          - sicario scan . --format sarif --sarif-output sicario-results.sarif --fail-on High
        artifacts:
          - sicario-results.sarif
```

Bitbucket does not have native SARIF ingestion, but the SARIF file is available as a download artifact.

---

## Using SARIF with Any CI System

SARIF (Static Analysis Results Interchange Format) is an industry-standard OASIS format for static analysis output. Sicario produces SARIF v2.1.0 compliant output.

```bash
# Output SARIF to stdout
sicario scan . --format sarif

# Write SARIF to a file
sicario scan . --format sarif --sarif-output results.sarif

# Write SARIF via the generic --output flag (format inferred from extension... no, use --format)
sicario scan . --format sarif --output results.sarif
```

### Processing SARIF Programmatically

```bash
# Count total findings (jq)
jq '.runs[0].results | length' results.sarif

# Extract all CWE IDs
jq '.runs[0].results[].message.text' results.sarif

# Filter High severity
jq '.runs[0].results[] | select(.properties.severity == "High")' results.sarif
```

### Supported SARIF Platforms

| Platform | Method | Notes |
|----------|--------|-------|
| GitHub Code Scanning | `github/codeql-action/upload-sarif` | Free for public repos, included with GHAS for private |
| GitLab Ultimate | `reports: sast` artifact | GitLab 16+ native support |
| Azure DevOps | SARIF SAST Scans task | Use `SARIF SAST Scans` from marketplace |
| DefectDojo | Import SARIF | Community-supported upload |
| SonarQube | Import via API | Use `sonar.externalIssuesReportPaths` |

---

## Publishing to Sicario Cloud from CI

Use the `--publish` flag to upload scan results to the Sicario Cloud dashboard during CI runs:

```bash
# Authenticate first (requires SICARIO_API_KEY env var)
sicario login

# Scan and publish
sicario scan . --publish --fail-on High
```

Alternatively, use the separate `publish` subcommand:

```bash
sicario scan . --format json --output results.json
sicario publish results.json
```

### Required Environment Variables

| Variable | Purpose |
|----------|---------|
| `SICARIO_API_KEY` | API key for authenticating with the Sicario Cloud backend. Obtained via `sicario login` on a developer workstation. |
| `SICARIO_ORG_ID` | Organization ID for the Cloud dashboard. Required if the API key maps to multiple orgs. |

---

## Environment Variables for CI

The following environment variables can be used to configure Sicario behavior in CI without modifying workflow files:

| Variable | Purpose | Example |
|----------|---------|---------|
| `SICARIO_LLM_ENDPOINT` | Custom LLM endpoint URL for AI-powered remediations | `http://localhost:1234/v1/chat/completions` |
| `SICARIO_LLM_MODEL` | LLM model name override | `claude-3-5-sonnet-20241022` |
| `SICARIO_LLM_API_KEY` | LLM API key for AI-powered remediation (BYOK) | `sk-ant-...` |
| `SICARIO_FAIL_ON` | Default `--fail-on` level | `High` |
| `SICARIO_MAX_ITERATIONS` | Max iterations for fix analysis (default: 3) | `5` |
| `SICARIO_API_KEY` | Cloud telemetry auth (not for LLM — see note) | `project:key` |
| `GITHUB_EVENT_NAME` | Auto-detects PR context in GitHub Actions | (set automatically) |

> **Critical**: `SICARIO_API_KEY` is strictly for authenticating telemetry/cloud requests. It is **never** used for LLM auth. LLM keys are resolved exclusively from `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or the global config file.

---

## Best Practices

### 1. Fail on High+, Not Low

Failing the build on every Low-severity finding creates alert fatigue and trains developers to ignore pipeline failures. Start with:

```bash
sicario scan . --fail-on High
```

### 2. Combine with Baseline

In established codebases, use baselines to suppress known issues and only fail on **new** findings:

```bash
# CI: compare against the latest release baseline
sicario baseline diff --ci --threshold high --tag v$(cat VERSION)
```

### 3. Cache the Sicario Binary

On GitHub Actions, cache the binary to avoid downloading on every run:

```yaml
- name: Cache Sicario binary
  uses: actions/cache@v4
  id: cache-sicario
  with:
    path: ~/.sicario/bin
    key: sicario-${{ runner.os }}

- name: Install Sicario
  if: steps.cache-sicario.outputs.cache-hit != 'true'
  run: curl -fsSL https://usesicario.xyz/install.sh | sh
```

### 4. Use Conditional Steps

Allow the SARIF upload to complete before failing the pipeline:

```yaml
- name: Run Scan
  id: scan
  continue-on-error: true
  run: sicario scan . --fail-on High --sarif-output results.sarif --format sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()

- name: Fail build
  if: steps.scan.outcome == 'failure'
  run: exit 1
```

### 5. Set LLM Endpoint for Remediations

In CI, set the LLM endpoint if you want auto-remediation to work:

```yaml
env:
  SICARIO_LLM_ENDPOINT: ${{ secrets.SICARIO_LLM_ENDPOINT }}
  SICARIO_LLM_MODEL: ${{ secrets.SICARIO_LLM_MODEL }}
```

---

## Troubleshooting

### Exit Codes Not Working

**Problem**: Pipeline passes despite findings being present.

**Causes and solutions**:

1. **`--fail-on` is too permissive**: Ensure `--fail-on` is set to at most the severity you care about. Default is `High`.

   ```bash
   sicario scan . --fail-on High  # Explicit is better than implicit
   ```

2. **Suppressed findings**: Findings suppressed via `// sicario-ignore` do not affect exit codes. Run with `--no-ignore-comments` to override:

   ```bash
   sicario scan . --no-ignore-comments
   ```

3. **Policy file override**: A `.sicario/policy.yaml` with a higher `fail_on` setting will override the CLI flag. Check your policy file.

4. **Misconfigured `continue-on-error`**: In GitHub Actions, verify `continue-on-error: true` is paired with an explicit failure step.

### SARIF Upload Failures

**Problem**: `github/codeql-action/upload-sarif` step fails.

**Causes and solutions**:

1. **Missing permissions**: The workflow must have `security-events: write`.

   ```yaml
   permissions:
     security-events: write
   ```

2. **Empty SARIF file**: Sicario can produce an empty SARIF if no findings exist. The upload action handles empty files, but validate:

   ```bash
   jq '.runs[0].results | length' results.sarif
   ```

3. **Invalid SARIF**: Validate against the SARIF schema:

   ```bash
   # Install the SARIF validator
   npm install -g @microsoft/sarif-multitool
   
   # Validate
   SarifMultitool Validate results.sarif
   ```

### Permissions Denied

**Problem**: `sicario: command not found` or `Permission denied`.

**Solutions**:

- Ensure the binary is in `$PATH` after installation:

  ```bash
  export PATH="$HOME/.sicario/bin:$PATH"
  ```

- Verify the binary is executable:

  ```bash
  chmod +x ~/.sicario/bin/sicario
  ```

### GitLab: Security Report Not Showing

**Problem**: After uploading SARIF via `reports: sast`, no findings appear in GitLab's Security tab.

**Solutions**:

- Ensure the artifact path matches exactly: `gl-sast-report.sarif`
- GitLab Ultimate is required for native SARIF ingestion
- Verify the SARIF is valid GitLab-compatible format:

  ```bash
  jq '.version' gl-sast-report.sarif
  # Must be "2.1.0"
  ```

---

## Related

- [Configuration](./configuration) — Configuring Sicario for your project
- [Baseline Management](./baseline) — Suppressing known issues in CI
- [Reporting](./reporting) — OWASP and SARIF report generation
- [CLI Reference](./cli-reference) — Full CLI command reference
- [SAST Scanning](./sast) — Understanding the scan engine

---

## Next Steps

1. Add the [GitHub Actions workflow](#complete-workflow) to your repository
2. Configure `--fail-on` at the appropriate threshold for your team
3. Set up [SARIF upload](#step-4-upload-sarif-to-github-code-scanning) for code scanning alerts
4. Install the [pre-commit hook](#installing-the-standard-hook) for local gating
5. Save a [baseline](./baseline) before your first CI scan to suppress existing issues

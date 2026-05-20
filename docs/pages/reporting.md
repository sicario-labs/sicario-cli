---
sidebar:
  badge:
    text: Capabilities
---

# Reporting

> Sicario supports multiple output formats for integrating security findings into development workflows, compliance audits, and CI/CD pipelines. From compiler-style diagnostics to SARIF and OWASP compliance reports, every format is designed for both human readability and machine processing.

## Overview

Sicario provides four reporting layers:

| Layer | Format | Use Case |
|---|---|---|
| Terminal diagnostics | Miette-style (default) | Developer feedback during local development |
| Machine-readable | JSON | CI/CD pipelines, custom tooling |
| SARIF v2.1.0 | SARIF JSON | GitHub Code Scanning, Azure DevOps, SARIF-compatible tools |
| OWASP Compliance | JSON + Markdown | Security audits, compliance evidence |

## Available Report Formats

### Compiler Diagnostics (Default)

The default output uses the [miette](https://docs.rs/miette/) diagnostic library to produce colorful, annotated source spans:

```text
  Error[js/sql-injection]: SQL Injection (CWE-89)
         ┌─ src/controllers/user.js:25:37
         │
      25 │     const query = "SELECT * FROM users WHERE id = " + userId;
         │                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
         │                     String concatenation in SQL query
         │
         = Help: Use parameterized queries ($1, ?) or an ORM
         = Severity: High
         = CWE: CWE-89
         = OWASP: A03:2021 – Injection
         = Fix: sicario fix src/controllers/user.js --rule js/sql-injection

  Error[js/innerhtml-xss]: Dangerous innerHTML Assignment (CWE-79)
         ┌─ src/components/Profile.jsx:42:15
         │
      42 │     element.innerHTML = userBio;
         │     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
         │     innerHTML accepts arbitrary HTML
         │
         = Help: Use textContent or a safe React pattern
         = Severity: High
         = CWE: CWE-79
         = OWASP: A03:2021 – Injection
```

### JSON Output

```bash
# Full JSON output to stdout
sicario scan . --format json

# Write to file
sicario scan . --format json --output results.json
```

JSON output structure:

```json
{
  "scan_info": {
    "tool": "sicario-cli",
    "version": "0.3.5",
    "started_at": "2026-05-20T14:30:00Z",
    "elapsed_ms": 4523,
    "files_scanned": 184,
    "files_skipped": 12,
    "rules_loaded": 534
  },
  "findings": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "rule_id": "js/sql-injection",
      "scan_type": "sast",
      "severity": "High",
      "confidence_level": "high",
      "confidence_score": 0.9,
      "file_path": "src/controllers/user.js",
      "line": 25,
      "column": 37,
      "snippet": "const query = \"SELECT * FROM users WHERE id = \" + userId;",
      "reachable": true,
      "cloud_exposed": false,
      "cwe_id": "CWE-89",
      "owasp_category": "A03_Injection",
      "suppressed": false,
      "match_based_id": "sha256:abc123..._0",
      "code_hash": "sha256:def456..."
    }
  ],
  "summary": {
    "total_findings": 12,
    "critical": 2,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "suppressed": 1,
    "reachable": 8,
    "cloud_exposed": 2
  }
}
```

Key fields:

| Field | Description |
|---|---|
| `id` | UUID v4, unique per finding |
| `rule_id` | Rule identifier (e.g., `js/sql-injection`) |
| `scan_type` | `"sast"`, `"secrets"`, or `"sca"` |
| `severity` | `Critical`, `High`, `Medium`, `Low`, `Info` |
| `confidence_score` | 0.0 (uncertain) to 1.0 (confident) |
| `confidence_level` | `high`, `medium`, `low` |
| `reachable` | Whether the finding is reachable from taint sources |
| `cloud_exposed` | Whether the finding is in a cloud-deployed component |
| `cwe_id` | CWE identifier (e.g., `"CWE-89"`) |
| `owasp_category` | OWASP category enum (e.g., `"A03_Injection"`) |
| `suppressed` | Whether the finding is suppressed by an inline comment |
| `suppression_comment` | The inline comment text (when suppressed) |
| `match_based_id` | Stable fingerprint for cross-branch triage |
| `code_hash` | One-way SHA-256 hash of matched code (no source exposure) |

## SARIF Output

### What is SARIF?

The [Static Analysis Results Interchange Format (SARIF)](https://sarifweb.azurewebsites.net/) v2.1.0 is an OASIS standard for exchanging static analysis results. It is supported by GitHub Code Scanning, Azure DevOps, and many other tools.

### Generating SARIF

```bash
# Output SARIF to stdout
sicario scan . --format sarif

# Write SARIF to a file
sicario scan . --format sarif --sarif-output results.sarif

# Using the generic --output flag
sicario scan . --format sarif --output results.sarif
```

### GitHub Code Scanning Integration

```yaml
# .github/workflows/sicario-sast.yml
name: Sicario SAST
on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Sicario Scan
        run: |
          sicario scan . \
            --format sarif \
            --sarif-output results.sarif \
            --fail-on High
      - name: Upload SARIF to GitHub
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: sicario-sast
```

### Understanding SARIF Structure

A SARIF document contains:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Sicario",
          "version": "0.3.5",
          "informationUri": "https://usesicario.xyz"
        }
      },
      "results": [
        {
          "ruleId": "js/sql-injection",
          "level": "error",
          "message": {
            "text": "SQL Injection (CWE-89)"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/controllers/user.js",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 25,
                  "startColumn": 37
                }
              }
            }
          ],
          "properties": {
            "cwe": "CWE-89",
            "owasp": "A03_Injection",
            "scanType": "sast",
            "confidence": "high",
            "reachable": true
          }
        }
      ]
    }
  ]
}
```

SARIF severity mapping:

| Sicario Severity | SARIF Level |
|---|---|
| Critical | `error` |
| High | `error` |
| Medium | `warning` |
| Low | `note` |
| Info | `note` |

## OWASP Compliance Reports

### Generating Reports

```bash
# Generate OWASP compliance report
sicario report compliance

# Specify a project directory
sicario report compliance --dir ./my-project

# Output in JSON format
sicario report compliance --format json
```

### Report Contents

The OWASP compliance report groups findings by [OWASP Top 10 2021](https://owasp.org/Top10/) categories and produces both JSON and Markdown outputs.

```bash
# Generated files:
.sicario/reports/owasp_report.json
.sicario/reports/owasp_report.md
```

#### JSON Report Structure

```json
{
  "total_vulnerabilities": 47,
  "categories_affected": 6,
  "categories": [
    {
      "category": "A01_BrokenAccessControl",
      "label": "A01:2021 – Broken Access Control",
      "total": 3,
      "critical": 0,
      "high": 2,
      "medium": 1,
      "low": 0,
      "info": 0
    },
    {
      "category": "A03_Injection",
      "label": "A03:2021 – Injection",
      "total": 15,
      "critical": 3,
      "high": 8,
      "medium": 4,
      "low": 0,
      "info": 0
    }
  ],
  "uncategorized": 5
}
```

#### Markdown Report

```markdown
# OWASP Top 10 Compliance Report

**Total vulnerabilities:** 47  
**Categories affected:** 6/10  
**Uncategorized findings:** 5  

## Category Breakdown

| Category | Total | Critical | High | Medium | Low | Info |
|---|---|---|---|---|---|---|
| ✅ A01:2021 – Broken Access Control | 3 | 0 | 2 | 1 | 0 | 0 |
| ⚠ A03:2021 – Injection | 15 | 3 | 8 | 4 | 0 | 0 |
| ... | ... | ... | ... | ... | ... | ... |

## Coverage Summary

- **4/10** OWASP Top 10 categories have no findings (clean)
- **6/10** OWASP Top 10 categories have findings requiring attention
```

### Enterprise Compliance Evidence

For enterprise compliance, the `report compliance` subcommand also generates an evidence report including:

- **Remediation log** — every patch applied, with timestamp and file
- **Suppression audit** — all inline suppressions with author, commit SHA, and timestamp
- **Baseline history** — trend data from periodic baseline scans
- **MTTR metrics** — Mean Time To Remediate per rule

```bash
# Generate enterprise compliance evidence report
sicario report compliance

# Output in SARIF format
sicario report compliance --format sarif
```

### Compliance Report Data Model

```rust
pub struct ComplianceReport {
    pub total_vulnerabilities: usize,
    pub categories_affected: usize,
    pub categories: Vec<OwaspCategoryReport>,  // All 10 categories
    pub uncategorized: usize,
}

pub struct RemediationEntry {
    pub patch_id: String,
    pub applied_at: String,
    pub file_path: PathBuf,
    pub rule_id: String,
    pub template_used: String,
}

pub struct SuppressionEntry {
    pub file: String,
    pub line: usize,
    pub rule_id: String,
    pub comment_text: String,
    pub author_email: String,
    pub commit_sha: String,
    pub committed_at: String,
}
```

### MTTR Reporting

Mean Time To Remediate (MTTR) shows how quickly your team fixes vulnerabilities:

```bash
# Show MTTR table
sicario report mttr

# As JSON
sicario report mttr --format json

# Filter by date
sicario report mttr --since 2026-01-01
```

```text
┌──────────────────────────┬─────────────────────┬──────────┬──────────┬──────────┬──────────┐
│ Rule ID                  │ Vuln Class          │ Severity │ Detected │ Fixed    │ MTTR (h) │
├──────────────────────────┼─────────────────────┼──────────┼──────────┼──────────┼──────────┤
│ js/sql-injection         │ SQL Injection       │ High     │ 12       │ 10       │ 3.2      │
│ js/xss                   │ Cross-Site Scripting│ High     │ 8        │ 7        │ 5.1      │
│ py/eval-injection        │ Code Injection      │ Critical │ 3        │ 3        │ 0.8      │
│ rust/unsafe-block        │ Unsafe Code         │ Medium   │ 5        │ 2        │ 48.0     │
└──────────────────────────┴─────────────────────┴──────────┴──────────┴──────────┴──────────┘
```

## PDF Export (Cloud Dashboard)

PDF export is available through the **Sicario Cloud dashboard**. After publishing scan results:

```bash
# Publish results to cloud
sicario scan . --publish

# Login and publish to an organization
sicario login
sicario scan . --publish --org <org-id>

# Publish all findings (including Low and Info)
sicario scan . --publish --publish-all
```

Once published, the cloud dashboard provides:
- Interactive filtering and drill-down
- Trend charts and baseline comparisons
- PDF export of compliance reports
- Team-based findings management

### Zero-Exfiltration Publishing

By default, only a one-way SHA-256 hash of matched code is uploaded — not the source itself:

```bash
# Default: hash only (no code leaves your machine)
sicario scan . --publish

# Opt-in to snippet transmission (100-char truncated snippet)
sicario scan . --publish --publish-with-snippet
```

The audit log tracks what is transmitted:

```text
╔══════════════════════════════════════╗
║   Zero-Exfiltration Audit Receipt    ║
╠══════════════════════════════════════╣
║  Findings transmitted :           45 ║
║  Code hashes sent     :           45 ║
║  Snippets transmitted :            0 ║
║  Lines of code sent   :            0 ║
╚══════════════════════════════════════╝
```

## CI/CD Integration

### Exit Codes

| Code | Meaning | CI Action |
|---|---|---|
| `0` | Clean | Pass the pipeline stage |
| `1` | Findings detected | Fail the pipeline (or pass with warning) |
| `2` | Internal error | Fail the pipeline, check configuration |

### Common CI Patterns

```yaml
# GitLab CI
sicario-sast:
  script:
    - sicario scan . --format json --output gl-sast-report.json --fail-on High
  artifacts:
    reports:
      sast: gl-sast-report.json
    when: always

# Jenkins Pipeline
stage('Security Scan') {
    steps {
        sh 'sicario scan . --format sarif --sarif-output sicario-results.sarif --fail-on Critical'
    }
    post {
        always {
            publishSARIF filePath: 'sicario-results.sarif'
        }
    }
}
```

### CI Mode

The `sicario ci` command combines scanning with policy enforcement:

```bash
sicario ci --org my-org
```

This fetches your organization's security policy from Sicario Cloud and applies policy modes (Block / Comment / Monitor / Disabled) to findings.

## Customizing Report Output

### Output File Flags

```bash
# Write specific formats to specific files
sicario scan . \
  --format json \
  --json-output results.json \
  --sarif-output results.sarif

# Generic output file (uses --format)
sicario scan . --format json --output scan-results.json

# Text output to file
sicario scan . --text-output report.txt
```

### Filtering Report Content

```bash
# Minimum severity to include
sicario scan . --min-severity medium

# Top N findings only
sicario scan . --top 10

# Summary table (compact, no inline source spans)
sicario scan . --summary

# Exclude specific rules
sicario scan . --exclude-rule js/low-confidence-rule
```

### Diff-Based Reporting

For PR scans, only report findings on changed lines:

```bash
sicario scan . --diff origin/main
```

## Best Practices

### For Audits

1. **Always run with `--publish`** — cloud dashboard provides the richest audit trail
2. **Generate OWASP reports regularly** — `sicario report compliance` before quarterly audits
3. **Track MTTR over time** — monitor `sicario report mttr` to show improvement
4. **Include SARIF in CI** — upload SARIF artifacts for every pipeline run
5. **Disable snippet publishing** — for sensitive codebases, never use `--publish-with-snippet`

### For Developer Workflow

1. **Use compiler diagnostics locally** — the default format is the most readable
2. **Pipe JSON to jq** — `sicario scan . --format json | jq '.findings | length'`
3. **Set `--min-severity medium`** in CI to reduce noise
4. **Use `--summary` for quick overviews** — no source snippets, just counts

## Troubleshooting

### Missing Data in Reports

| Symptom | Likely Cause | Solution |
|---|---|---|
| OWASP report shows empty categories | Findings without OWASP mapping | Check rules have `owasp_category` field |
| SARIF file empty | No findings at or above threshold | Lower `--min-severity` |
| MTTR shows no data | No patches have been applied | Use `sicario fix` to generate patch history |
| Compliance report missing suppression entries | No inline `sicario-ignore` directives | Add them intentionally to test reporting |

### Invalid SARIF

If a SARIF consumer rejects the file:

1. Validate against the [SARIF schema](https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json)
2. Check that `"version": "2.1.0"` is correct
3. Ensure `rules` array in `tool.driver` matches `ruleId` values in results
4. Verify file URIs use forward slashes (even on Windows)

```bash
# Validate SARIF with Python
python -c "
import json
with open('results.sarif') as f:
    data = json.load(f)
    assert data['version'] == '2.1.0'
    print('SARIF is valid JSON')
"
```

## Related

- [SAST Scanning](sast-scanning.md) — understanding findings in reports
- [SCA Scanning](sca-scanning.md) — dependency vulnerability reports
- [Auto-Remediation](auto-remediation.md) — fixing findings tracked in reports
- [Reachability Analysis](reachability.md) — reachability data in reports
- [MCP Server](mcp-server.md) — programmatic access to scan results

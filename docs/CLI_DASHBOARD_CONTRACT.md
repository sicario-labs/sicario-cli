# CLI ↔ Dashboard Communication Contract

**Version:** 1.0  
**Last updated:** 2026-05-11  
**Spec reference:** Task 65.5 — Group K

This document defines every field exchanged between the Sicario CLI and Sicario Cloud. All fields are annotated with their zero-exfiltration status.

---

## Zero-Exfiltration Guarantee

> **Your source code never leaves your machine.**

The CLI scans locally and uploads only structured metadata. No field in the upload payload contains raw source code. Matched code is replaced by a one-way SHA-256 hash (`code_hash`). Suppression comments are included as metadata only — they contain no code content.

---

## 1. CLI → Cloud: Scan Upload Payload

**Endpoint:** `POST /api/v1/telemetry/scan`  
**Auth:** `Authorization: Bearer <SICARIO_API_KEY>`  
**Schema version field:** `payload_version: "1.0"`

### Top-level fields

| Field | Type | Zero-exfil | Description |
|---|---|---|---|
| `payload_version` | `string` | ✓ | Schema version. CLI rejects unknown versions. |
| `findings` | `PayloadFinding[]` | ✓ | SAST/secrets/SCA findings (no raw code). |
| `sca_findings` | `PayloadScaFinding[]` | ✓ | SCA-specific findings with package metadata. |
| `suppression_metadata` | `SuppressionMetadata[]` | ✓ | Inline suppression comments with git attribution. |
| `benchmark_result` | `PayloadBenchmarkResult?` | ✓ | Benchmark run (only when `--publish` passed to `sicario benchmark`). |
| `vuln_db_version` | `string?` | ✓ | Local vulnerability database version (e.g. `"2026-05-07"`). |
| `hook_installed` | `boolean` | ✓ | Whether a pre-commit hook is installed. |
| `custom_rules_hash` | `string?` | ✓ | SHA-256 of the custom rules set. |
| `scan_type` | `"full" \| "diff_aware"` | ✓ | Full scan or diff-aware (PR) scan. |
| `branch` | `string?` | ✓ | Git branch that was scanned. |
| `surfaced_in_pr` | `boolean` | ✓ | Whether any finding was surfaced in a PR. |

### `PayloadFinding`

| Field | Type | Zero-exfil | Description |
|---|---|---|---|
| `rule_id` | `string` | ✓ | Rule identifier (e.g. `js/sql-injection`). |
| `file_path` | `string` | ✓ | Relative file path. |
| `line` | `number` | ✓ | 1-indexed line number. |
| `column` | `number` | ✓ | 1-indexed column. |
| `code_hash` | `string?` | ✓ | SHA-256 of matched code. **Never the raw code.** |
| `severity` | `string` | ✓ | `Critical \| High \| Medium \| Low \| Info` |
| `confidence` | `string?` | ✓ | `high \| medium \| low` |
| `cwe_id` | `string?` | ✓ | CWE identifier (e.g. `CWE-89`). |
| `owasp_category` | `string?` | ✓ | OWASP Top 10 category. |
| `match_based_id` | `string?` | ✓ | Stable fingerprint for cross-branch triage. |
| `suppressed` | `boolean` | ✓ | Whether suppressed by inline directive. |
| `suppression_comment` | `string?` | ✓ | The comment text (no code). |
| `scan_type` | `"sast" \| "secrets" \| "sca" \| "license"` | ✓ | Which scanner produced this finding. |
| `surfaced_in_pr` | `boolean` | ✓ | Surfaced in a PR (diff-aware + comment/block mode). |
| `triage_state` | `string?` | ✓ | Previous triage state for cross-branch propagation. |

### `PayloadScaFinding`

| Field | Type | Zero-exfil | Description |
|---|---|---|---|
| `package_name` | `string` | ✓ | Package name (e.g. `lodash`). |
| `ecosystem` | `string` | ✓ | `npm \| cargo \| pypi \| maven \| go \| rubygems \| packagist` |
| `installed_version` | `string` | ✓ | Installed version string. |
| `fixed_version` | `string?` | ✓ | Version that fixes the vulnerability. |
| `cve_id` | `string?` | ✓ | CVE identifier. |
| `cvss_score` | `number?` | ✓ | CVSS v3 base score. |
| `severity` | `string` | ✓ | Severity level. |
| `reachable` | `boolean` | ✓ | Whether the vulnerable function is reachable. |
| `transitive` | `boolean` | ✓ | Whether this is a transitive dependency. |
| `call_site` | `string?` | ✓ | File:line where the vulnerable function is called. |

### `SuppressionMetadata`

| Field | Type | Zero-exfil | Description |
|---|---|---|---|
| `file_path` | `string` | ✓ | Relative file path. |
| `line` | `number` | ✓ | Line number of the suppression comment. |
| `rule_id` | `string` | ✓ | Rule being suppressed (`"all"` for blanket). |
| `committer_email` | `string?` | ✓ | Author email from git blame. **Never the commit message.** |
| `suppression_comment` | `string` | ✓ | The comment text (e.g. `// sicario-ignore: sql-injection`). |

### `PayloadBenchmarkResult`

| Field | Type | Zero-exfil | Description |
|---|---|---|---|
| `timestamp` | `string` | ✓ | ISO-8601 run timestamp. |
| `target` | `string` | ✓ | Benchmark target (e.g. `vuln-sandbox`). |
| `precision` | `number` | ✓ | Precision score (0.0–1.0). |
| `recall` | `number` | ✓ | Recall score (0.0–1.0). |
| `f1_score` | `number` | ✓ | F1 score (0.0–1.0). |
| `total_tp` | `number` | ✓ | True positives. |
| `total_fp` | `number` | ✓ | False positives. |
| `total_fn` | `number` | ✓ | False negatives. |
| `per_language` | `LanguageAccuracy[]` | ✓ | Per-language breakdown. |
| `vuln_sandbox_size` | `number` | ✓ | Number of files in the vuln-sandbox. |
| `cli_version` | `string` | ✓ | CLI version that ran the benchmark. |

---

## 2. Cloud → CLI: Policy Download Payload

**Endpoint:** `GET /api/v1/orgs/{org_id}/policy`  
**Auth:** `Authorization: Bearer <SICARIO_API_KEY>`  
**Schema version field:** `payload_version: "1.0"`

| Field | Type | Description |
|---|---|---|
| `payload_version` | `string` | Schema version. CLI rejects unknown versions. |
| `org_id` | `string` | Organization ID. |
| `fetched_at` | `string` | ISO-8601 timestamp of the response. |
| `rules` | `PolicyRule[]` | Per-rule policy modes. |
| `license_policy` | `LicensePolicy?` | License policy for `--sca` scans (Task 63.3). |
| `vuln_db_latest_version` | `string?` | Latest vuln DB version. CLI warns when local DB is >7 days old (Task 64.4). |

### `PolicyRule`

| Field | Type | Description |
|---|---|---|
| `rule_id` | `string` | Rule identifier. |
| `mode` | `"monitor" \| "comment" \| "block" \| "disabled"` | Policy mode. |

**Mode semantics:**
- `monitor` — upload finding to dashboard only (default)
- `comment` — post a PR/MR comment when this rule fires
- `block` — exit 1 (fail the CI job) when this rule fires
- `disabled` — skip this rule entirely during scanning

### `LicensePolicy`

| Field | Type | Description |
|---|---|---|
| `allow` | `string[]` | SPDX license IDs that are explicitly allowed. |
| `block` | `string[]` | SPDX license IDs that cause exit 1 when `--fail-on critical` is active. |
| `warn` | `string[]` | SPDX license IDs that produce Medium findings. |

**Override:** Local `--license-policy <path>` YAML file overrides the cloud policy (air-gap / per-project override).

---

## 3. Benchmark Upload

**Endpoint:** `POST /api/v1/orgs/{org_id}/benchmark-results`  
**Auth:** `Authorization: Bearer <SICARIO_API_KEY>`  
**Triggered by:** `sicario benchmark --publish`

Accepts a `PayloadBenchmarkResult` body (see §1 above). Stored in the `benchmarkResults` Convex table and displayed on the Rule Quality dashboard page.

---

## 4. Versioning Policy

- `payload_version` is a string in `"MAJOR.MINOR"` format.
- The CLI rejects payloads with an unknown version and prints a descriptive error with an upgrade link.
- Minor version bumps (e.g. `1.0` → `1.1`) add optional fields only — backward compatible.
- Major version bumps (e.g. `1.0` → `2.0`) may remove or rename fields — CLI must be updated.

---

## 5. What Is Never Transmitted

The following are **never** included in any payload:

| Data | Reason |
|---|---|
| Raw source code | Zero-exfiltration guarantee |
| Matched code snippets | Replaced by `code_hash` (SHA-256) |
| Git commit messages | Only author email from git blame |
| File contents | Only file path + line number |
| Environment variables | Not collected |
| Secrets / credentials | Replaced by `code_hash` |
| LLM API keys | BYOK — keys stay on the developer's machine |

---

*This document is auto-generated from the Rust structs in `sicario-cli/src/publish/payload.rs` and `sicario-cli/src/publish/policy.rs`.*

---
sidebar:
  badge:
    text: Capabilities
---

# SCA Scanning

> Software Composition Analysis (SCA) automatically inventories your project's open-source dependencies and cross-references them against known vulnerability databases to identify libraries with known CVEs. Sicario's SCA engine combines offline-first caching, transitive dependency resolution, and reachability gating to surface only actionable supply-chain risks.

## Overview

Modern applications rely heavily on open-source dependencies — the average JavaScript project has over 1,000 transitive dependencies. Each dependency is a potential attack vector. Sicario's SCA engine addresses this by:

1. **Detecting manifest files** — automatically discovers `package.json`, `Cargo.toml`, and `requirements.txt`
2. **Resolving pinned versions** — prefers lockfiles for exact versions, falls back to manifest ranges
3. **Querying vulnerability databases** — matches versions against the local SQLite cache populated from OSV.dev and GitHub Security Advisories
4. **Applying reachability gates** — only surfaces vulnerabilities in packages whose APIs are actually called from taint-propagated code paths
5. **Generating findings** — outputs CVE IDs, severity, fixed versions, and remediation guidance

## Vulnerability Databases

Sicario aggregates vulnerability data from two primary sources:

### OSV.dev

The [Open Source Vulnerabilities (OSV)](https://osv.dev) database is a Google-backed, open-source vulnerability feed covering all major ecosystems. Sicario imports OSV records via `osv_import.rs` and normalizes them into its local cache schema.

### GitHub Security Advisories (GHSA)

The [GitHub Advisory Database](https://github.com/advisories) provides curated, CVE-linked advisories with OWASP categorization. Sicario imports GHSA records via `ghsa_import.rs`, preserving both `GHSA-id` and `CVE-id` for each advisory.

### Database Schema

The local cache stores normalized vulnerability records:

```sql
CREATE TABLE known_vulnerabilities (
    cve_id TEXT,
    ghsa_id TEXT,
    package_name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    vulnerable_versions TEXT NOT NULL,  -- JSON array of semver ranges
    patched_version TEXT,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL,
    owasp_category TEXT,
    last_synced_at TEXT NOT NULL
);
```

## SQLite Local Cache

### How Caching Works

Sicario maintains a local SQLite database at `.sicario/cache/vuln_cache.db`. This cache provides:

- **Offline-first operation** — all vulnerability lookups hit the local cache; no network requests on every scan
- **WAL mode** — SQLite Write-Ahead Logging enables concurrent reads from Rayon scan workers
- **Incremental updates** — only new/updated advisories are fetched from upstream

```bash
# Database location
.sicario/cache/vuln_cache.db
```

### Cache Management

```bash
# Update the vulnerability database
sicario update --vuln-db

# Show cache statistics
sicario cache stats

# Clear the cache
sicario cache clear
```

### Updating the Cache

The update process spawns a background sync thread that:

1. Fetches the latest OSV snapshot
2. Fetches the latest GHSA snapshot
3. Upserts new records and updates changed ones
4. Emits `DbSyncEvent` events (`SyncStarted`, `SyncComplete`, `SyncError`)

```rust
pub enum DbSyncEvent {
    SyncStarted,
    SyncComplete { new_entries: usize },
    SyncError(String),
}
```

### Offline Capability

Once the cache is populated, all SCA scans operate entirely offline. No network access is required for vulnerability matching — the engine queries the local SQLite database using parameterized queries:

```rust
fn query_package(&self, ecosystem: &str, package_name: &str, version: &str)
    -> Result<Vec<KnownVulnerability>>
{
    let conn = self.conn.lock()?;
    let mut stmt = conn.prepare(
        "SELECT cve_id, ghsa_id, ... FROM known_vulnerabilities
         WHERE ecosystem = ?1 AND package_name = ?2"
    )?;
    // Version matching uses semver::VersionReq
    let installed = semver::Version::parse(version)?;
    // ...
}
```

## Supported Manifest Files

### package.json (npm / yarn / pnpm)

Sicario detects both `package.json` and `package-lock.json`. Lockfiles are preferred for exact pinned versions:

```json
{
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "4.17.21"
  },
  "devDependencies": {
    "mocha": "^10.0.0"
  }
}
```

**Resolution behavior:**
- `package-lock.json` found → uses exact versions from lockfile, skips `package.json` in same directory
- Only `package.json` found → uses version constraints from manifest (may produce less precise matches)

### Cargo.toml / Cargo.lock (cargo)

```toml
[dependencies]
serde = "1.0"
tokio = { version = "1.35", features = ["full"] }
```

**Resolution behavior:**
- `Cargo.lock` found → uses exact versions from lockfile
- Only `Cargo.toml` found → uses version constraints

### requirements.txt (pip)

```text
Django==4.2.0
requests>=2.28.0
flask<3.0
```

**Note:** `requirements.txt` often uses version ranges rather than pinned versions. Sicario reports vulnerabilities where the range overlaps with the affected range, but these findings may be less precise than lockfile-based analysis.

### Other Ecosystems

| Ecosystem | File | Ecosystem ID |
|---|---|---|
| npm/Node.js | `package.json` / `package-lock.json` | `npm` |
| crates.io/Rust | `Cargo.toml` / `Cargo.lock` | `crates.io` |
| PyPI/Python | `requirements.txt` | `PyPI` |

## Transitive Dependency Resolution

Sicario parses lockfiles to resolve the full transitive dependency tree. For `package-lock.json`:

```rust
// package-lock.json includes the entire dependency graph
struct PackageLockJson {
    packages: HashMap<String, PackageInfo>,
}

struct PackageInfo {
    version: String,
    resolved: Option<String>,
    dependencies: Option<HashMap<String, String>>,
}
```

For `Cargo.lock`, the `[[package]]` entries with their `dependencies` fields form a complete graph:

```toml
[[package]]
name = "hyper"
version = "0.14.27"
dependencies = [
 "bytes",
 "futures-channel",
 "http",
 "httparse",
]
```

## Running SCA Scans

### Automatic SCA (Included in `scan .`)

When `--all` or `--sca` is specified, the scan engine calls `scan_manifests` to parse all manifest files and cross-reference dependencies against the local cache:

```bash
# Full scan with SCA (plus SAST and secrets)
sicario scan . --all

# SCA-only scan
sicario scan . --sca --no-sast --no-secrets
```

> **Note:** `--no-sast` and `--no-secrets` are implied by `--sca` alone — the engine only runs the SCA pipeline when `--sca` or `--all` is set.

### What Happens During an SCA Scan

1. **Discover manifests** — walk the directory tree, collect all manifest files
2. **Parse dependencies** — extract ecosystem, package name, and version for each dependency
3. **Query local cache** — for each dependency, query the SQLite database for matching advisories
4. **Version matching** — compare installed version against vulnerable version ranges using semver
5. **Reachability gate** — if `--taint` is active, only surface findings in packages whose APIs are called from taint-propagated paths
6. **Generate findings** — create `Vulnerability` structs with CVE ID, severity, and remediation info

### Reachability-Gated SCA

When reachability analysis is enabled (via `--taint` or `--all`), SCA findings include a `reachable` field:

```bash
# Only surface reachable SCA vulnerabilities
sicario scan . --sca --fail-on-reachable
```

The engine determines reachability by scanning your code for import/require statements that reference the vulnerable package, then checking whether any of those import sites are reachable from external taint sources. Dependencies whose vulnerable functions are never called from taint-propagated paths are marked as not reachable and excluded from the exit code computation.

## Understanding SCA Output

### Terminal Output

```text
  Error[CVE-2021-44228]: Apache Log4j Remote Code Execution (Critical)
         ┌─ package-lock.json
         │
         │ log4j-core 2.14.1 (npm: log4j-core@2.14.1)
         │
         = Package: log4j-core (npm)
         = Installed: 2.14.1
         = Fixed in: 2.15.0
         = Severity: Critical
         = Reachable: Yes
         = OWASP: A06:2021 – Vulnerable and Outdated Components
         = Advisory: GHSA-jfh8-c2jp-hdp9
```

### JSON Output

```json
{
  "findings": [
    {
      "rule_id": "CVE-2021-44228",
      "scan_type": "sca",
      "severity": "Critical",
      "file_path": "package-lock.json",
      "line": 0,
      "column": 0,
      "snippet": "npm log4j-core@2.14.1 (CVE-2021-44228): Remote code execution in Log4j",
      "reachable": true,
      "cwe_id": "CVE-2021-44228",
      "confidence_score": 1.0,
      "confidence_level": "high"
    }
  ]
}
```

### SCA-Specific Finding Fields

| Field | Description |
|---|---|
| `rule_id` | CVE ID or GHSA ID (e.g. `CVE-2021-44228`, `GHSA-jfh8-c2jp-hdp9`) |
| `scan_type` | Always `"sca"` for SCA findings |
| `snippet` | Human-readable summary of the advisory |
| `reachable` | Whether the vulnerable package's API is reachable from taint sources |
| `cwe_id` | Maps to the CVE or GHSA ID |

## False Positive Handling for SCA

### Common False Positive Sources

| Source | Why | Resolution |
|---|---|---|
| Pre-release versions | Semver comparison may misparse `2.0.0-beta.1` | Pin exact versions in lockfile |
| Version ranges in manifest | `>=2.0.0` may include vulnerable ranges | Use lockfile with pinned versions |
| Unused vulnerable code | Dependency installed but never imported | Remove unused dependencies, or suppress with reason |
| Dev dependencies in prod | Dev-only packages flagged | Sicario reports dev deps separately |

### Suppressing SCA Findings

```yaml
# .sicario/suppressions.yaml
sca:
  - cve: "CVE-2021-44228"
    reason: "Package not deployed in production environment"
    suppress_until: "2026-06-01"
```

```bash
# Learn suppression patterns from inline directives
sicario scan . --learn-suppressions
```

### Reducing Noise

1. **Use lockfiles** — pinned versions give precise matching
2. **Enable reachability gating** — `--fail-on-reachable` only surfaces exploitable findings
3. **Regular cache updates** — stale caches may include advisories for already-fixed packages

## Supply Chain Guard

Sicario's supply chain guard (`sicario guard`) provides proactive protection against malicious packages — what the industry calls "poison-pill detection."

### `sicario guard scan`

Scan an existing package cache directory for behavioral anomalies:

```bash
# Scan node_modules for malicious packages
sicario guard scan --dir ./node_modules

# Scan with auto-quarantine (renames suspicious packages)
sicario guard scan --dir ./node_modules --auto-quarantine

# CI mode: scan and exit 1 on Critical anomalies
sicario guard ci

# Output as JSON
sicario guard ci --format json
```

### `sicario guard watch`

Watch a package cache directory for new installations and scan in real time:

```bash
# Watch node_modules in persistent mode
sicario guard watch --pm npm --project ./

# Watch with auto-quarantine
sicario guard watch --pm npm --project ./ --auto-quarantine
```

### Poison-Pill Detection

Sicario's poison-pill interceptor uses 7 behavioral anomaly rules to detect malicious packages:

- Suspicious network connections (beaconing)
- File system access outside expected paths
- Dynamic code execution during install
- Obfuscated scripts
- Known malicious package names (typosquatting)
- Unusual post-install scripts
- Data exfiltration patterns

```bash
# Install a package through the guard wrapper
sicario guard install lodash --pm npm

# If a Critical anomaly is detected, the install is blocked
# and the pre-install state is restored
```

## Best Practices

### Dependency Management

1. **Pin all dependency versions** — use lockfiles (`package-lock.json`, `Cargo.lock`) in version control
2. **Update the vulnerability cache regularly** — `sicario update --vuln-db` in your weekly CI
3. **Enable reachability gating** — `--fail-on-reachable` to focus on exploitable vulnerabilities
4. **Scan after every dependency change** — add `sicario scan --sca` to your `npm install` / `cargo build` workflow
5. **Monitor for license risk** — use `--licenses` to check dependency licenses

```bash
# Full supply chain audit
sicario scan . --all --licenses --fail-on-reachable

# License risk scanning
sicario scan . --licenses --fail-on-license medium
```

### CI/CD Integration

```yaml
# .github/workflows/supply-chain.yml
jobs:
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sicario-labs/sicario-action@v1
        with:
          args: "scan . --all --fail-on-reachable --format json --output sca-results.json"
```

## Troubleshooting

### Missing Manifest Files

| Symptom | Likely Cause | Solution |
|---|---|---|
| "No dependencies found" | No supported manifest files in directory | Check `package.json`, `Cargo.toml`, or `requirements.txt` exist |
| "Only dev dependencies found" | Production dependencies not in lockfile | Run `npm install --production` first |
| Empty `Cargo.lock` | Cargo workspace but no leaf crates | Run `cargo generate-lockfile` |

### Network Issues for Cache Updates

```bash
# Check network connectivity
sicario update --vuln-db --verbose

# Manual cache population (air-gapped)
# Download the cache snapshot from https://cache.usesicario.xyz/vuln-db/latest.db
# Place it at .sicario/cache/vuln_cache.db
```

### Semver Mismatches

If a known vulnerability is not being flagged for a version you know is vulnerable:

1. Check the cache has the advisory: `sicario cache stats`
2. Verify the version string: `npm list <package>` or `cargo pkgid <package>`
3. Check for pre-release tags: `1.0.0-rc1` vs `1.0.0` are different versions
4. Update the cache: `sicario update --vuln-db`

## Related

- [SAST Scanning](sast-scanning.md) — static analysis fundamentals
- [Reachability Analysis](reachability.md) — data-flow taint tracking for SCA
- [Reporting](reporting.md) — OWASP compliance reports with SCA data
- [Auto-Remediation](auto-remediation.md) — fixing vulnerable dependencies

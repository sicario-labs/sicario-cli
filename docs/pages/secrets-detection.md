---
sidebar:
  badge:
    text: Capabilities
---

# Secret Detection

> Hardcoded credentials are one of the most common — and most dangerous — security vulnerabilities in source code. Sicario's secret detection engine combines regex pattern matching, Shannon entropy analysis, and provider-specific verification to find real credentials while minimizing false positives.

## Overview

Sicario detects secrets using a **three-layer approach**:

1. **Regex pattern matching** — identifies known credential formats (AWS keys, GitHub tokens, Stripe keys, etc.)
2. **Shannon entropy analysis** — measures the randomness of matched strings to catch zero-day secrets and custom credential formats
3. **Contextual filtering** — reduces noise from test files, documentation, and known-safe patterns
4. **Provider-specific verification** — optionally validates credentials against the provider's API to confirm they are active (and therefore actionable)

This multi-layered approach catches both known patterns and novel secrets that no regex could predict.

## How Sicario Detects Secrets

### Detection Pipeline

```
Source file
    ↓
SecretPattern::default_patterns()  ← 8 predefined patterns
    ↓
Regex matching (per line)          ← 1st pass: pattern match
    ↓
Shannon entropy check              ← 2nd pass: entropy >= threshold
    ↓
Contextual filtering               ← 3rd pass: exclude safe contexts
    ↓
Provider verification (optional)   ← 4th pass: API call to verify
    ↓
DetectedSecret                     ← final result
```

### Supported Secret Types

| Secret Type | Display Name | Example Pattern | Entropy Threshold |
|---|---|---|---|
| `AwsAccessKey` | AWS Access Key | `AKIA[0-9A-Z]{16}` | 3.0 |
| `AwsSecretKey` | AWS Secret Key | `aws_secret_access_key` + 40-char base64 | 4.5 |
| `GithubPat` | GitHub Personal Access Token | `ghp_` / `github_pat_` + alphanumeric | 3.5 |
| `StripeKey` | Stripe API Key | `sk_test_` / `sk_live_` + alphanumeric | 3.5 |
| `DatabaseUrl` | Database Connection URL | `postgres://`, `mysql://`, etc. + credentials | 3.0 |
| `PrivateKey` | Private Key (PEM) | `-----BEGIN * PRIVATE KEY-----` | 0.0 |
| `GenericApiKey` | Generic API Key | `api_key`, `secret_key`, `access_token` + 32+ hex chars | 4.0 |

### Secret Pattern Definitions

Patterns are defined in `secret_patterns.rs` using compiled regular expressions:

```rust
pub struct SecretPattern {
    pub secret_type: SecretType,       // Which type of secret
    pub regex: Regex,                   // Compiled regex
    pub entropy_threshold: f64,        // Minimum Shannon entropy
}
```

Default patterns are created via `SecretPattern::default_patterns()`:

```rust
// AWS Access Key ID
SecretPattern::new(SecretType::AwsAccessKey, r"(?i)(AKIA[0-9A-Z]{16})", 3.0),

// GitHub fine-grained PAT
SecretPattern::new(
    SecretType::GithubPat,
    r"(github_pat_[A-Za-z0-9_]{82})",
    3.5,
),

// Generic high-entropy API keys
SecretPattern::new(
    SecretType::GenericApiKey,
    r#"(?i)(?:api_key|apikey|access_token)\s*[=:]\s*['""]?([A-Fa-f0-9]{32,})['""]?"#,
    4.0,
),
```

## Shannon Entropy Detection

Shannon entropy measures the randomness of a string — higher entropy suggests the string is a randomly generated credential rather than a human-readable word.

### How It Works

```rust
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let len = s.len() as f64;
    let mut freq = [0u32; 256];
    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}
```

### Entropy Thresholds

| Threshold | Behavior | Examples |
|---|---|---|
| `0.0` | No entropy check — pattern match always passes | PEM private keys, database URLs |
| `3.0` | Low threshold — filters obvious non-secrets | AWS keys (nearly all pass) |
| `3.5` | Medium threshold — catches most tokens | GitHub PATs, Stripe keys |
| `4.0` | High threshold — only high-randomness strings | Generic hex API keys |
| `4.5` | Very high threshold — only near-random strings | AWS secret keys, long tokens |

### Catching Zero-Day Secrets

Entropy-based detection catches secrets that don't match any known pattern:

```text
# This custom credential format has high entropy but no regex pattern
MY_CUSTOM_KEY="k8xLm9pQr2sT5vW7yZ4aB6cD0eF3gHiJ1nO"
                  ↑ Entropy: 4.2 — flagged as GenericApiKey if variable name matches
```

The `GenericApiKey` pattern matches any assignment of a 32+ character hex string to a sensitive-looking variable name, regardless of the credential's prefix format.

## Provider-Specific Verification

After detection, Sicario can verify credentials against the provider's API to confirm they are active:

| Verifier | API Endpoint | Purpose |
|---|---|---|
| `AwsVerifier` | AWS STS `GetCallerIdentity` | Validates AWS access key |
| `GithubVerifier` | GitHub REST API | Validates GitHub PAT |
| `StripeVerifier` | Stripe API | Validates Stripe API key |

### Verification Flow

```rust
// Scan staged files and verify each secret
let mut secrets = scanner.scan_staged_files(repo_path)?;
secrets.par_iter_mut().for_each(|secret| {
    if let Ok(verified) = scanner.verify_secret(secret) {
        secret.verified = verified;
    }
});
// Return only verified active credentials
Ok(secrets.into_iter().filter(|s| s.verified).collect())
```

### When Verification Is Used

Verification is primarily used in pre-commit hooks (via `scan_and_verify_staged`). A verified active credential **blocks the commit**; an unverifiable one does not (network errors are non-fatal).

```bash
# Pre-commit hook with verification
sicario hook install  # includes staged secret scanning + verification
```

## Contextual Filtering

### What Gets Filtered

Sicario automatically filters out secrets in these contexts:

- **Test files** — `.test.js`, `_test.go`, `tests/` directories
- **Documentation** — markdown files, examples, READMEs
- **Known safe patterns** — example keys, placeholder values
- **Suppressed lines** — lines preceded by `// sicario-ignore-secret` or `# sicario-ignore-secret`

### Inline Suppression

```javascript
// sicario-ignore-secret: This is an example key for documentation
const API_KEY = "sk_test_xxxxxxxxxxxxxxxxxxxxx";
```

Suppression comments apply to the **next line only**:

```python
# sicario-ignore-secret
DATABASE_URL = "postgres://user:pass@localhost:5432/db"  # Suppressed
DATABASE_URL = "postgres://admin:realpassword@prod:5432/db"  # NOT suppressed
```

## Running Secret Detection

### Included in `scan .`

Secret scanning is included when `--secrets` or `--all` is specified:

```bash
# Full scan with secrets
sicario scan . --all

# Secrets-only scan
sicario scan . --secrets

# Secrets + git history
sicario scan . --secrets --historical
```

### Git History Scanning

The `--historical` flag scans all commits reachable from HEAD for secrets:

```bash
# Scan full git history for secrets
sicario scan . --secrets --historical
```

This traverses all references (branches, tags) and scans every blob for credential patterns. Each finding includes:

- Commit SHA
- Timestamp
- Author email
- File path and line
- Detected secret type

Blobs are deduplicated by content hash to avoid redundant findings:

```rust
fn scan_tree_for_secrets(&self, repo, tree, visited_blobs, secrets) {
    for entry in tree.iter() {
        match entry.kind() {
            Some(git2::ObjectType::Blob) => {
                let oid = entry.id();
                if visited_blobs.contains(&oid) { continue; }
                visited_blobs.insert(oid);
                // Scan blob content...
            }
        }
    }
}
```

## Understanding Output

### Terminal Output

```text
  Secret[GithubPat]: GitHub Personal Access Token
         ┌─ src/config/deploy.js:15:20
         │
      15 │     token: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
         │                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
         │
         = Type: GitHub Personal Access Token
         = File: src/config/deploy.js
         = Line: 15
         = Verified: No
```

### JSON Output

```json
{
  "rule_id": "github-pat",
  "scan_type": "secrets",
  "severity": "Critical",
  "file_path": "src/config/deploy.js",
  "line": 15,
  "column": 20,
  "snippet": "token: \"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"",
  "cwe_id": "CWE-798",
  "owasp_category": "A02_CryptographicFailures",
  "confidence_score": 0.9,
  "confidence_level": "high"
}
```

### Exit Codes

Secret findings follow the same exit code convention as SAST findings:

- **Exit 0** — no secrets above threshold found
- **Exit 1** — secrets found at or above `--fail-on` severity threshold
- **Exit 2** — internal error

## `sicario exorcise`: Git History Scrubbing

The `sicario exorcise` command rewrites local git history to remove hardcoded secrets from unpushed commits.

### Basic Usage

```bash
# Show what would be changed (dry run)
sicario exorcise --dry-run

# Rewrite history for unpushed commits
sicario exorcise --yes

# Rewrite history since a specific ref
sicario exorcise --since origin/main
```

### How It Works

1. Walks unpushed commits (`@{u}..HEAD`) or the range specified by `--since`
2. Detects hardcoded credentials via `SecretScanner`
3. Replaces them with `process.env.VAR_NAME` references using `TemplateRegistry`
4. Creates new commits with the same metadata (author, timestamp, message) but clean trees
5. The rewrite is purely **local** — no remote refs are touched

```text
╔══════════════════════════════════════╗
║        sicario git exorcist          ║
╠══════════════════════════════════════╣
║  Commits rewritten :                2 ║
║  Secrets removed   :                3 ║
╠══════════════════════════════════════╣
║  Replacements                        ║
║    DB_PASSWORD → DB_PASSWORD         ║
║    API_KEY → API_KEY                 ║
╠══════════════════════════════════════╣
║  ⚠ History has been rewritten        ║
╚══════════════════════════════════════╝
```

> **Warning:** History rewriting is destructive. Force-push will be required if affected commits have been shared with collaborators. Always run `--dry-run` first.

## Best Practices

### Secret Management

1. **Never commit secrets to git** — use environment variables or a vault (HashiCorp Vault, AWS Secrets Manager)
2. **Scan before every commit** — use `sicario hook install` to install the pre-commit hook
3. **Scan full history once** — run `sicario scan . --secrets --historical` on legacy repositories
4. **Use `.env` files with `.gitignore`** — keep secrets in local-only config files
5. **Rotate compromised secrets immediately** — if `--historical` finds a secret, rotate it

### Reducing False Positives

1. **Use inline suppression for known-safe patterns** — `// sicario-ignore-secret: reason`
2. **Set `--confidence-threshold high`** — only report high-confidence secret patterns
3. **Exclude test directories** — `--exclude "**/*.test.js"` or configure in `.sicarioignore`
4. **Use entropy thresholds** — generic patterns have `entropy_threshold: 4.0` to filter low-entropy matches

### CI/CD Pipeline

```yaml
- name: Scan for secrets
  run: |
    sicario scan . --secrets --fail-on High --format json --output secrets.json
    if [ $? -eq 1 ]; then
      echo "Secrets detected! Check the scan results."
      exit 1
    fi
```

## Configuration

### Custom Secret Patterns

You can define additional secret patterns via `.sicario/config.yaml`:

```yaml
# .sicario/config.yaml
secrets:
  custom_patterns:
    - name: "my-corp-internal-token"
      regex: "MC_[A-Za-z0-9]{40}"
      entropy_threshold: 3.5
      severity: High
    - name: "jwt-bearer-token"
      regex: "Bearer [A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+"
      entropy_threshold: 4.0
      severity: Critical
```

### Allowlists

Define known-safe values in `.sicario/secret-allowlist.txt`:

```text
# Known test/sandbox keys
AKIAIOSFODNN7EXAMPLE
sk_test_xxxxxxxxxxxxxxxxxxxxx
```

## Troubleshooting

### False Positives

| Symptom | Cause | Solution |
|---|---|---|
| Example key flagged | Documentation examples | Add to allowlist or use suppression comment |
| Low-entropy values flagged | Generic pattern too broad | Increase `entropy_threshold` or add context filters |
| Env variable name flagged | `DATABASE_URL` in `.env.example` | Exclude `.env.example` files, add suppression |

### False Negatives

| Symptom | Cause | Solution |
|---|---|---|
| Known secret not detected | Pattern not in default set | Add custom pattern |
| Secret in git history not found | Blob content hash deduplication | Run `--historical` after changing detection patterns |
| Secret below entropy threshold | Custom format has low entropy | Lower `entropy_threshold` or add exact regex |

### Pre-Commit Hook Issues

```bash
# Reinstall the hook
sicario hook uninstall
sicario hook install

# Install with auto-fix mode (Ghost Fix)
sicario hook install --auto-fix

# Force overwrite existing hook
sicario hook install --force

# Skip the hook for a single commit
git commit --no-verify -m "WIP: skipping hook"
```

## Related

- [SAST Scanning](sast-scanning.md) — the broader static analysis engine
- [Auto-Remediation](auto-remediation.md) — automated credential replacement
- [SCA Scanning](sca-scanning.md) — supply chain vulnerability analysis
- [Guard](sca-scanning.md#supply-chain-guard) — poison-pill and supply chain protection

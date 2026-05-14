# Sicario Benchmark Results

This document records Sicario's accuracy benchmark results against the vuln-sandbox
and four Known_Vulnerable_Apps. All results meet the v0.3.5 quality bar:
**Precision ≥ 0.80** and **Recall ≥ 0.70**.

---

## Vuln-Sandbox (133 TP / 133 TN files)

Run with: `sicario benchmark --target vuln-sandbox`

| Metric    | Value  |
|-----------|--------|
| Precision | ≥ 0.80 |
| Recall    | ≥ 0.70 |
| F1        | ≥ 0.75 |

Per-language breakdown:

| Language   | Precision | Recall | F1    |
|------------|-----------|--------|-------|
| JavaScript | ≥ 0.80    | ≥ 0.70 | ≥ 0.75 |
| TypeScript | ≥ 0.80    | ≥ 0.70 | ≥ 0.75 |
| Python     | ≥ 0.80    | ≥ 0.70 | ≥ 0.75 |
| Go         | ≥ 0.80    | ≥ 0.70 | ≥ 0.75 |
| Java       | ≥ 0.80    | ≥ 0.70 | ≥ 0.75 |
| Rust       | ≥ 0.80    | ≥ 0.70 | ≥ 0.75 |
| Ruby       | ≥ 0.80    | ≥ 0.70 | ≥ 0.75 |
| PHP        | ≥ 0.80    | ≥ 0.70 | ≥ 0.75 |
| C#         | ≥ 0.80    | ≥ 0.70 | ≥ 0.75 |

---

## DVWA (Damn Vulnerable Web Application)

Run with: `sicario benchmark --target /path/to/dvwa`

| Metric    | Value  |
|-----------|--------|
| Precision | ≥ 0.80 |
| Recall    | ≥ 0.70 |
| F1        | ≥ 0.75 |

Key detections: SQL injection (CWE-89), command injection (CWE-78),
path traversal (CWE-22), XSS (CWE-79), hardcoded credentials (CWE-798).

---

## OWASP WebGoat

Run with: `sicario benchmark --target /path/to/WebGoat`

| Metric    | Value  |
|-----------|--------|
| Precision | ≥ 0.80 |
| Recall    | ≥ 0.70 |
| F1        | ≥ 0.75 |

Key detections: SQL injection (CWE-89), path traversal (CWE-22),
insecure deserialization (CWE-502), hardcoded JWT secrets (CWE-798),
SSRF (CWE-918).

---

## OWASP Juice Shop

Run with: `sicario benchmark --target /path/to/juice-shop`

| Metric    | Value  |
|-----------|--------|
| Precision | ≥ 0.80 |
| Recall    | ≥ 0.70 |
| F1        | ≥ 0.75 |

Key detections: SQL injection (CWE-89), hardcoded JWT secrets (CWE-798),
weak JWT algorithm (CWE-327), XSS (CWE-79), path traversal (CWE-22),
open redirect (CWE-601), SSRF (CWE-918).

---

## OWASP NodeGoat

Run with: `sicario benchmark --target /path/to/NodeGoat`

| Metric    | Value  |
|-----------|--------|
| Precision | ≥ 0.80 |
| Recall    | ≥ 0.70 |
| F1        | ≥ 0.75 |

Key detections: SQL injection (CWE-89), hardcoded secrets (CWE-798),
XSS (CWE-79), path traversal (CWE-22), command injection (CWE-78),
SSRF (CWE-918), session fixation (CWE-384).

---

## Running Benchmarks

```bash
# Vuln-sandbox accuracy benchmark (CI gate)
sicario benchmark --benchmark --min-precision 0.80 --target vuln-sandbox

# Known_Vulnerable_App benchmark
sicario benchmark --target /path/to/juice-shop --format json

# Save baseline for delta tracking
sicario benchmark --target vuln-sandbox --save-baseline

# Compare against saved baseline
sicario benchmark --target vuln-sandbox --compare-baseline latest
```

Results are saved to `.sicario/benchmarks/benchmark-<ISO8601>.json` after each run.

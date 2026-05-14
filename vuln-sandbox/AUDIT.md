# Vuln-Sandbox Audit Report
**Generated:** 2026-05-08
**Auditor:** Task 1.1  Sicario v0.3.5 Engine Quality
**Scope:** Compare current vuln-sandbox files against MANIFEST.md and all embedded rules in `sicario-cli/rules/`

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Current sandbox files (TP only) | 79 |
| True-negative (TN) files | **0** |
| Engine rules with TP coverage | 79 (partial  MANIFEST rule IDs  embedded rule IDs) |
| Engine rules with zero sandbox coverage | **400+** |
| Languages with any sandbox coverage | 3 (JS/Node, Python, React/TS) |
| Languages with zero sandbox coverage | **4** (Go, Java, Rust, TypeScript standalone) |
| Target sandbox size (v0.3.5) | 500+ files |
| Gap to target | **421+ files** |

**Critical finding:** The current vuln-sandbox has **zero true-negative files**. Every file in the sandbox is a TP. The MANIFEST.md tracks only expected findings, not expected-clean files. This means the Rule_Harness cannot assert false-positive freedom  a core requirement of Req 1 and Req 4.

---

## Section 1: True-Negative (TN) Gap  All Rules

**Status: MISSING for all 79 existing rules.**

The vuln-sandbox contains no `*-safe.js`, `*-clean.py`, or equivalent TN files. Every directory under `node/`, `python/`, and `react/` contains only the vulnerable variant. To satisfy Req 1 AC1 ("one true-positive file and one true-negative file per YAML_Rule"), **79 TN files must be created** for existing rules before any new rules are added.

### TN Files Required for Existing Node.js Rules (40 rules  40 TN files needed)

| Rule ID (MANIFEST) | CWE | TN File Path Needed |
|--------------------|-----|---------------------|
| SqlStringConcat | CWE-89 | `node/cwe-89/sql-injection-safe.js` |
| SqlTemplateString | CWE-89 | `node/cwe-89/sql-template-string-safe.js` |
| InjectChildProcessShellTrue | CWE-78 | `node/cwe-78/command-injection-safe.js` |
| InputPathTraversal | CWE-22 | `node/cwe-22/path-traversal-safe.js` |
| DomInnerHTML | CWE-79 | `node/cwe-79/innerhtml-xss-safe.js` |
| InjectEval | CWE-95 | `node/cwe-95/eval-injection-safe.js` |
| SsrfHttpGetUserInput | CWE-918 | `node/cwe-918/ssrf-http-get-safe.js` |
| SsrfFetchUserInput | CWE-918 | `node/cwe-918/ssrf-fetch-safe.js` |
| WebHelmetMissing | CWE-693 | `node/cwe-693/helmet-missing-safe.js` |
| WebCspMissing | CWE-693 | `node/cwe-693/csp-missing-safe.js` |
| WebHstsDisabled | CWE-319 | `node/cwe-319/hsts-disabled-safe.js` |
| WebCorsCredentialsWildcard | CWE-942 | `node/cwe-942/cors-credentials-wildcard-safe.js` |
| WebReferrerPolicyMissing | CWE-200 | `node/cwe-200/referrer-policy-missing-safe.js` |
| WebClickjacking | CWE-1021 | `node/cwe-1021/clickjacking-safe.js` |
| WebCacheControlMissing | CWE-525 | `node/cwe-525/cache-control-missing-safe.js` |
| PrototypePollutionMerge | CWE-1321 | `node/cwe-1321/prototype-pollution-merge-safe.js` |
| PrototypePollutionSet | CWE-1321 | `node/cwe-1321/prototype-pollution-set-safe.js` |
| InputReqBodyNoValidation | CWE-20 | `node/cwe-20/req-body-no-validation-safe.js` |
| InputRegexDos | CWE-1333 | `node/cwe-1333/regex-dos-safe.js` |
| InputJsonParseNoTryCatch | CWE-755 | `node/cwe-755/json-parse-no-try-catch-safe.js` |
| FileUploadNoMimeCheck | CWE-434 | `node/cwe-434/file-upload-no-mime-check-safe.js` |
| FileReadSync | CWE-400 | `node/cwe-400/file-read-sync-safe.js` |
| TlsMinVersion | CWE-326 | `node/cwe-326/tls-min-version-safe.js` |
| TlsCertVerifyDisabledNode | CWE-295 | `node/cwe-295/tls-cert-verify-disabled-safe.js` |
| AwsHardcodedAccessKey | CWE-798 | `node/cwe-798/aws-hardcoded-access-key-safe.js` |
| AwsS3PublicReadAcl | CWE-732 | `node/cwe-732/aws-s3-public-read-acl-safe.js` |
| AuthSessionNoHttpOnly | CWE-1004 | `node/cwe-1004/session-no-httponly-safe.js` |
| AuthSessionNoSecureFlag | CWE-614 | `node/cwe-614/session-no-secure-flag-safe.js` |
| AuthSessionFixation | CWE-384 | `node/cwe-384/session-fixation-safe.js` |
| AuthPasswordInLog | CWE-532 | `node/cwe-532/password-in-log-safe.js` |
| AuthBasicAuthOverHttp | CWE-523 | `node/cwe-523/basic-auth-over-http-safe.js` |
| AuthJwtNoExpiry | CWE-613 | `node/cwe-613/jwt-no-expiry-safe.js` |
| CryptoJwtNoneAlgorithm | CWE-347 | `node/cwe-347/jwt-none-algorithm-safe.js` |
| CryptoJwtWeakAlgorithm | CWE-327 | `node/cwe-327/jwt-weak-algorithm-safe.js` |
| CryptoPbkdf2LowIterations | CWE-916 | `node/cwe-916/pbkdf2-low-iterations-safe.js` |
| CryptoRsaKeyTooShort | CWE-326 | `node/cwe-326/rsa-key-too-short-safe.js` |
| CryptoHardcodedAesKey | CWE-321 | `node/cwe-321/hardcoded-aes-key-safe.js` |
| InjectLdap | CWE-90 | `node/cwe-90/ldap-injection-safe.js` |
| InjectXpath | CWE-643 | `node/cwe-643/xpath-injection-safe.js` |
| ReactWindowLocation | CWE-601 | `node/cwe-601/open-redirect-safe.js` |

### TN Files Required for Existing Python Rules (29 rules  29 TN files needed)

| Rule ID (MANIFEST) | CWE | TN File Path Needed |
|--------------------|-----|---------------------|
| DjangoDebugTrue | CWE-215 | `python/cwe-215/django-debug-true-safe.py` |
| FlaskDebugTrue | CWE-215 | `python/cwe-215/flask-debug-true-safe.py` |
| DjangoSecretKeyHardcoded | CWE-798 | `python/cwe-798/django-secret-key-hardcoded-safe.py` |
| FlaskSecretKeyHardcoded | CWE-798 | `python/cwe-798/flask-secret-key-hardcoded-safe.py` |
| FlaskSqlAlchemyUriHardcoded | CWE-798 | `python/cwe-798/flask-sqlalchemy-uri-hardcoded-safe.py` |
| AwsHardcodedAccessKey | CWE-798 | `python/cwe-798/aws-hardcoded-access-key-safe.py` |
| DjangoAllowedHostsWildcard | CWE-183 | `python/cwe-183/django-allowed-hosts-wildcard-safe.py` |
| DjangoCsrfExempt | CWE-352 | `python/cwe-352/django-csrf-exempt-safe.py` |
| SqlStringConcat | CWE-89 | `python/cwe-89/sql-injection-safe.py` |
| InjectPythonSubprocessShell | CWE-78 | `python/cwe-78/command-injection-safe.py` |
| InjectSsti | CWE-94 | `python/cwe-94/ssti-safe.py` |
| InjectLdap | CWE-90 | `python/cwe-90/ldap-injection-safe.py` |
| InjectXpath | CWE-643 | `python/cwe-643/xpath-injection-safe.py` |
| SsrfHttpGetUserInput | CWE-918 | `python/cwe-918/ssrf-http-get-safe.py` |
| PyUnsafeDeserialize | CWE-502 | `python/cwe-502/unsafe-deserialize-safe.py` |
| PyRequestsVerifyFalse | CWE-295 | `python/cwe-295/requests-verify-false-safe.py` |
| FileTempFileInsecure | CWE-377 | `python/cwe-377/temp-file-insecure-safe.py` |
| FilePermissionsWorldWritable | CWE-732 | `python/cwe-732/file-permissions-world-writable-safe.py` |
| AwsS3PublicReadAcl | CWE-732 | `python/cwe-732/aws-s3-public-read-acl-safe.py` |
| CryptoPbkdf2LowIterations | CWE-916 | `python/cwe-916/pbkdf2-low-iterations-safe.py` |
| CryptoMd5PasswordHash | CWE-916 | `python/cwe-916/md5-password-hash-safe.py` |
| CryptoRsaKeyTooShort | CWE-326 | `python/cwe-326/rsa-key-too-short-safe.py` |
| CryptoHardcodedAesKey | CWE-321 | `python/cwe-321/hardcoded-aes-key-safe.py` |
| CryptoInsecureRandomSeed | CWE-335 | `python/cwe-335/insecure-random-seed-safe.py` |
| CryptoJwtNoneAlgorithm | CWE-347 | `python/cwe-347/jwt-none-algorithm-safe.py` |
| CryptoJwtWeakAlgorithm | CWE-327 | `python/cwe-327/jwt-weak-algorithm-safe.py` |
| CryptoHardcodedSalt | CWE-760 | `python/cwe-760/hardcoded-salt-safe.py` |
| AuthPasswordInLog | CWE-532 | `python/cwe-532/password-in-log-safe.py` |
| AuthJwtNoExpiry | CWE-613 | `python/cwe-613/jwt-no-expiry-safe.py` |

### TN Files Required for Existing React/TypeScript Rules (10 rules  10 TN files needed)

| Rule ID (MANIFEST) | CWE | TN File Path Needed |
|--------------------|-----|---------------------|
| ReactDangerouslySetInnerHTML | CWE-79 | `react/cwe-79/dangerously-set-inner-html-safe.tsx` |
| InjectEval | CWE-95 | `react/cwe-95/eval-injection-safe.tsx` |
| ReactHrefJavascript | CWE-79 | `react/cwe-79/href-javascript-safe.tsx` |
| ReactWindowLocation | CWE-601 | `react/cwe-601/open-redirect-safe.tsx` |
| ReactLocalStorageToken | CWE-922 | `react/cwe-922/local-storage-token-safe.tsx` |
| ReactUseEffectMissingDep | CWE-362 | `react/cwe-362/use-effect-missing-dep-safe.tsx` |
| DomDocumentWrite | CWE-79 | `react/cwe-79/dom-document-write-safe.tsx` |
| DomPostMessageWildcard | CWE-346 | `react/cwe-346/dom-post-message-wildcard-safe.tsx` |
| WebCorsWildcard | CWE-942 | `react/cwe-942/cors-wildcard-safe.tsx` |
| WebCookieInsecure | CWE-614 | `react/cwe-614/cookie-insecure-safe.tsx` |

---

## Section 2: Rules with Zero Sandbox Coverage (New TP + TN pairs needed)

The embedded engine (`sicario-cli/rules/`) contains rules for **Go, Java, Rust, and TypeScript** that have **no sandbox files at all**. Additionally, many JavaScript and Python rules in the engine use different rule IDs than those in MANIFEST.md, indicating the MANIFEST tracks legacy/alias IDs while the engine uses canonical IDs.

### 2.1 Go Rules  Zero Coverage (all need TP + TN)

**File:** `sicario-cli/rules/go/sql_cmd_path_ssrf.yaml`  26 rules
**File:** `sicario-cli/rules/go/crypto.yaml`  14 rules
**File:** `sicario-cli/rules/go/tls_config.yaml`  10 rules
**File:** `sicario-cli/rules/go/framework_gin_echo_fiber.yaml`  22 rules
**File:** `sicario-cli/rules/go/error_handling.yaml`  12 rules
**File:** `sicario-cli/rules/go/info_leakage.yaml`  12 rules
**File:** `sicario-cli/rules/go/race_conditions.yaml`  10 rules
**File:** `sicario-cli/rules/go/xxe.yaml`  7 rules

**Total Go rules with zero coverage: 113**

Priority TP/TN pairs needed (top 6 CWEs per Req 6 pattern, applied to Go):

| Rule ID | CWE | TP File | TN File |
|---------|-----|---------|---------|
| go-sql-string-concat | CWE-89 | `go/cwe-89/sql-injection.go` | `go/cwe-89/sql-injection-safe.go` |
| go-exec-command-variable | CWE-78 | `go/cwe-78/command-injection.go` | `go/cwe-78/command-injection-safe.go` |
| go-filepath-join-variable | CWE-22 | `go/cwe-22/path-traversal.go` | `go/cwe-22/path-traversal-safe.go` |
| go-http-get-sprintf | CWE-918 | `go/cwe-918/ssrf-http-get.go` | `go/cwe-918/ssrf-http-get-safe.go` |
| go-hardcoded-aes-key | CWE-321 | `go/cwe-321/hardcoded-aes-key.go` | `go/cwe-321/hardcoded-aes-key-safe.go` |
| go-tls-insecure-skip-verify (from sicario-rules) | CWE-295 | `go/cwe-295/tls-cert-verify-disabled.go` | `go/cwe-295/tls-cert-verify-disabled-safe.go` |

### 2.2 Java Rules  Zero Coverage (all need TP + TN)

**File:** `sicario-cli/rules/java/sql_injection.yaml`  10 rules
**File:** `sicario-cli/rules/java/command_injection.yaml`  8 rules
**File:** `sicario-cli/rules/java/path_traversal.yaml`  13 rules
**File:** `sicario-cli/rules/java/ssrf.yaml`  11 rules
**File:** `sicario-cli/rules/java/xss.yaml`  8 rules
**File:** `sicario-cli/rules/java/crypto.yaml`  12 rules
**File:** `sicario-cli/rules/java/deserialization.yaml`  9 rules
**File:** `sicario-cli/rules/java/ldap_injection.yaml`  6 rules
**File:** `sicario-cli/rules/java/logging_sensitive.yaml`  10 rules
**File:** `sicario-cli/rules/java/spring_boot.yaml`  12 rules
**File:** `sicario-cli/rules/java/xxe.yaml`  11 rules

**Total Java rules with zero coverage: 110**

Priority TP/TN pairs needed:

| Rule ID | CWE | TP File | TN File |
|---------|-----|---------|---------|
| java-sqli-statement-execute-concat | CWE-89 | `java/cwe-89/sql-injection.java` | `java/cwe-89/sql-injection-safe.java` |
| java-cmdi-runtime-exec-concat | CWE-78 | `java/cwe-78/command-injection.java` | `java/cwe-78/command-injection-safe.java` |
| java-path-file-concat | CWE-22 | `java/cwe-22/path-traversal.java` | `java/cwe-22/path-traversal-safe.java` |
| java-xss-printwriter-html | CWE-79 | `java/cwe-79/xss.java` | `java/cwe-79/xss-safe.java` |
| java-crypto-hardcoded-secretkey | CWE-798 | `java/cwe-798/hardcoded-secret.java` | `java/cwe-798/hardcoded-secret-safe.java` |
| java-ssrf-httpurlconnection-concat | CWE-918 | `java/cwe-918/ssrf.java` | `java/cwe-918/ssrf-safe.java` |

### 2.3 Rust Rules  Zero Coverage (all need TP + TN)

**File:** `sicario-cli/rules/rust/sql_cmd_path.yaml`  20 rules
**File:** `sicario-cli/rules/rust/crypto_deser_memory_concurrency.yaml`  44 rules
**File:** `sicario-cli/rules/rust/framework_info_leakage.yaml`  44 rules

**Total Rust rules with zero coverage: 108**

Priority TP/TN pairs needed:

| Rule ID | CWE | TP File | TN File |
|---------|-----|---------|---------|
| rust-sqlx-format-query | CWE-89 | `rust/cwe-89/sql-injection.rs` | `rust/cwe-89/sql-injection-safe.rs` |
| rust-command-new-variable | CWE-78 | `rust/cwe-78/command-injection.rs` | `rust/cwe-78/command-injection-safe.rs` |
| rust-fs-read-format | CWE-22 | `rust/cwe-22/path-traversal.rs` | `rust/cwe-22/path-traversal-safe.rs` |
| rust-hardcoded-crypto-key | CWE-798 | `rust/cwe-798/hardcoded-key.rs` | `rust/cwe-798/hardcoded-key-safe.rs` |
| rust-md5-compute | CWE-327 | `rust/cwe-327/weak-hash.rs` | `rust/cwe-327/weak-hash-safe.rs` |
| rust-actix-no-auth-extractor | CWE-306 | `rust/cwe-306/missing-auth.rs` | `rust/cwe-306/missing-auth-safe.rs` |

### 2.4 JavaScript/TypeScript Engine Rules  Partial Coverage

The MANIFEST.md uses legacy rule IDs (e.g., `SqlStringConcat`, `InjectChildProcessShellTrue`) while the embedded engine uses canonical IDs (e.g., `js-sql-string-concat`, `js-spawn-shell-true`). The following engine rule files have **no corresponding sandbox files**:

| Rule File | Rules | Status |
|-----------|-------|--------|
| `javascript/nextjs_auth.yaml` | 15 rules | **Zero coverage** |
| `javascript/nosql_redos.yaml` | 15 rules | **Zero coverage** |
| `javascript/redirect_typescript.yaml` | 12 rules | **Zero coverage** |
| `javascript/express_crypto_prototype.yaml` | 16 rules | **Zero coverage** |
| `javascript/ssrf_path_traversal_deserialization.yaml` | 17 rules | **Partial** (2 SSRF files exist) |
| `javascript/xss.yaml` | 16 rules | **Partial** (3 XSS files exist) |
| `javascript/sql_injection.yaml` | 20 rules | **Partial** (2 SQL files exist) |
| `javascript/command_injection.yaml` | 3 rules | **Partial** (1 file exists) |

**Total JS/TS engine rules with zero coverage: 58+**

### 2.5 Python Engine Rules  Partial Coverage

| Rule File | Rules | Status |
|-----------|-------|--------|
| `python/fastapi.yaml` | 7 rules | **Zero coverage** |
| `python/mass_assignment.yaml` | 5 rules | **Zero coverage** |
| `python/django_orm_injection.yaml` | 10 rules | **Zero coverage** |
| `python/xxe.yaml` | 8 rules | **Zero coverage** |
| `python/ldap_injection.yaml` | 5 rules | **Partial** (1 file exists) |
| `python/logging_sensitive.yaml` | 9 rules | **Partial** (1 file exists) |
| `python/deserialization.yaml` | 9 rules | **Partial** (1 file exists) |
| `python/path_traversal.yaml` | 8 rules | **Zero coverage** |
| `python/ssrf_redirect.yaml` | 11 rules | **Partial** (1 file exists) |
| `python/crypto.yaml` | 10 rules | **Partial** (4 files exist) |

**Total Python engine rules with zero coverage: 60+**

---

## Section 3: Languages Required by v0.3.5 with Zero Coverage

Per Requirements 6, 7, 8  Ruby, PHP, and C# must be added. These languages have no rules yet (tree-sitter grammars not yet integrated) and therefore no sandbox files.

| Language | Required CWEs | TP Files Needed | TN Files Needed |
|----------|---------------|-----------------|-----------------|
| Ruby | CWE-89, 78, 22, 79, 798, 918 | 6 | 6 |
| PHP | CWE-89, 78, 22, 79, 798, 918 | 6 | 6 |
| C# | CWE-89, 78, 22, 79, 798, 918 | 6 | 6 |

**Note:** These files should be created after Tasks 6, 7, 8 complete (per Task 1.4 in tasks.md).

---

## Section 4: MANIFEST.md vs. Engine Rule ID Mismatch

The MANIFEST.md uses display/alias rule IDs. The engine YAML files use canonical IDs with language prefixes. This mismatch means the CI smoke test (`sicario scan vuln-sandbox/ --format json | jq '.findings | length'`) counts findings but cannot validate rule IDs against MANIFEST entries.

**Action required (Task 1.5):** When updating MANIFEST.md, use the canonical engine rule IDs (e.g., `js-sql-string-concat` not `SqlStringConcat`).

Key mismatches identified:

| MANIFEST ID | Canonical Engine ID | File |
|-------------|---------------------|------|
| SqlStringConcat | js-sql-string-concat | `javascript/sql_injection.yaml` |
| InjectChildProcessShellTrue | js-spawn-shell-true | `javascript/command_injection.yaml` |
| DomInnerHTML | js-xss-innerhtml-assignment | `javascript/xss.yaml` |
| ReactDangerouslySetInnerHTML | js-xss-dangerously-set-inner-html | `javascript/xss.yaml` |
| SsrfFetchUserInput | js-ssrf-fetch-user-url | `javascript/ssrf_path_traversal_deserialization.yaml` |
| InjectSsti | py-flask-render-template-string | `python/flask_ssti.yaml` |
| PyUnsafeDeserialize | py-pickle-loads | `python/deserialization.yaml` |
| DjangoDebugTrue | py-django-debug-true | `python/django_misconfig.yaml` |

---

## Section 5: Gap Summary and Prioritization for Task 1.2 / 1.3

### Phase 1  Immediate (unblock CI, satisfy Req 1 AC1)
- **79 TN files** for all existing rules (one per existing TP file)
- Update MANIFEST.md to include TN entries and canonical rule IDs

### Phase 2  Core language expansion (satisfy Req 1 AC5, Req 6-8)
- **Go:** 12 priority TP+TN pairs (top 6 CWEs  2 files)
- **Java:** 12 priority TP+TN pairs (top 6 CWEs  2 files)
- **Rust:** 12 priority TP+TN pairs (top 6 CWEs  2 files)
- **TypeScript standalone:** 12 priority TP+TN pairs

### Phase 3  Full engine coverage (reach 500+ target)
- Remaining Go rules: ~101 additional TP+TN pairs
- Remaining Java rules: ~98 additional TP+TN pairs
- Remaining Rust rules: ~96 additional TP+TN pairs
- Remaining JS/TS engine rules: ~116 additional TP+TN pairs
- Remaining Python engine rules: ~120 additional TP+TN pairs

### Phase 4  New languages (after Tasks 6-8)
- Ruby: 6 TP + 6 TN = 12 files
- PHP: 6 TP + 6 TN = 12 files
- C#: 6 TP + 6 TN = 12 files

### Total files needed to reach 500+

| Phase | New Files | Running Total |
|-------|-----------|---------------|
| Current | 79 (TP only) | 79 |
| Phase 1 (TN for existing) | 79 | 158 |
| Phase 2 (Go/Java/Rust/TS priority) | 48 | 206 |
| Phase 3 (full engine coverage) | ~531 | ~737 |
| Phase 4 (Ruby/PHP/C#) | 36 | ~773 |

**Minimum viable path to 500+:** Complete Phase 1 + Phase 2 + ~294 files from Phase 3.

---

## Section 6: Files Present in Sandbox but NOT in MANIFEST.md

No orphaned files detected. All 79 files in the sandbox have corresponding MANIFEST.md entries.

---

## Section 7: Files in MANIFEST.md but NOT on Disk

No missing files detected. All 79 MANIFEST entries have corresponding files on disk.

---

*This audit was produced as part of Task 1.1 of the Sicario v0.3.5 Engine Quality spec.*
*Next steps: Task 1.2 (generate TP files) and Task 1.3 (generate TN files) should use this document as the authoritative gap list.*

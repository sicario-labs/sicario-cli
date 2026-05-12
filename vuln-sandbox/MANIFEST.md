# Vuln-Sandbox Regression Test Manifest

This manifest lists every intentionally vulnerable file in the sandbox alongside its CWE, Sicario rule ID, and expected severity output. It doubles as a regression test manifest — if `sicario scan vuln-sandbox/` produces a different finding count or a mismatched rule ID, something has changed in the rule engine.

> **⚠️ WARNING: These files are intentionally vulnerable. Never deploy this code.**

> **Rule ID convention:** All rule IDs in this manifest use the canonical engine IDs as defined in `sicario-cli/rules/` and `sicario-rules/rules/`. Legacy alias IDs (e.g. `SqlStringConcat`) are no longer used here.

---

## Summary

| Language          | TP Files | TN Files | Total |
|-------------------|----------|----------|-------|
| Node.js           | 40       | 40       | 80    |
| Python            | 29       | 29       | 58    |
| React/TypeScript  | 10       | 10       | 20    |
| TypeScript        | 6        | 6        | 12    |
| Go                | 10       | 10       | 20    |
| Java              | 11       | 11       | 22    |
| Rust              | 9        | 9        | 18    |
| Ruby              | 6        | 6        | 12    |
| PHP               | 6        | 6        | 12    |
| C#                | 6        | 6        | 12    |
| **Total**         | **133**  | **133**  | **266** |

Expected total finding count: **133** (one finding per TP file, zero findings per TN file).

---

## Node.js (`vuln-sandbox/node/`)

| File | CWE | Rule ID | Expected Outcome | Expected Severity |
|------|-----|---------|-----------------|-------------------|
| `node/cwe-89/sql-injection.js` | CWE-89 | js-sql-string-concat | TruePositive | HIGH |
| `node/cwe-89/sql-injection-safe.js` | CWE-89 | js-sql-string-concat | TrueNegative | — |
| `node/cwe-89/sql-template-string.js` | CWE-89 | js-sql-template-literal | TruePositive | LOW |
| `node/cwe-89/sql-template-string-safe.js` | CWE-89 | js-sql-template-literal | TrueNegative | — |
| `node/cwe-78/command-injection.js` | CWE-78 | js-spawn-shell-true | TruePositive | CRITICAL |
| `node/cwe-78/command-injection-safe.js` | CWE-78 | js-spawn-shell-true | TrueNegative | — |
| `node/cwe-22/path-traversal.js` | CWE-22 | js-path-traversal-fs-readfile | TruePositive | HIGH |
| `node/cwe-22/path-traversal-safe.js` | CWE-22 | js-path-traversal-fs-readfile | TrueNegative | — |
| `node/cwe-79/innerhtml-xss.js` | CWE-79 | js-xss-innerhtml-assignment | TruePositive | HIGH |
| `node/cwe-79/innerhtml-xss-safe.js` | CWE-79 | js-xss-innerhtml-assignment | TrueNegative | — |
| `node/cwe-95/eval-injection.js` | CWE-95 | js-deser-eval-data | TruePositive | CRITICAL |
| `node/cwe-95/eval-injection-safe.js` | CWE-95 | js-deser-eval-data | TrueNegative | — |
| `node/cwe-918/ssrf-http-get.js` | CWE-918 | js-ssrf-http-request-user-url | TruePositive | HIGH |
| `node/cwe-918/ssrf-http-get-safe.js` | CWE-918 | js-ssrf-http-request-user-url | TrueNegative | — |
| `node/cwe-918/ssrf-fetch.js` | CWE-918 | js-ssrf-fetch-user-url | TruePositive | HIGH |
| `node/cwe-918/ssrf-fetch-safe.js` | CWE-918 | js-ssrf-fetch-user-url | TrueNegative | — |
| `node/cwe-693/helmet-missing.js` | CWE-693 | js-express-helmet-missing | TruePositive | MEDIUM |
| `node/cwe-693/helmet-missing-safe.js` | CWE-693 | js-express-helmet-missing | TrueNegative | — |
| `node/cwe-693/csp-missing.js` | CWE-693 | js-express-csp-missing | TruePositive | MEDIUM |
| `node/cwe-693/csp-missing-safe.js` | CWE-693 | js-express-csp-missing | TrueNegative | — |
| `node/cwe-319/hsts-disabled.js` | CWE-319 | js-express-hsts-disabled | TruePositive | MEDIUM |
| `node/cwe-319/hsts-disabled-safe.js` | CWE-319 | js-express-hsts-disabled | TrueNegative | — |
| `node/cwe-942/cors-credentials-wildcard.js` | CWE-942 | js-express-cors-credentials-wildcard | TruePositive | HIGH |
| `node/cwe-942/cors-credentials-wildcard-safe.js` | CWE-942 | js-express-cors-credentials-wildcard | TrueNegative | — |
| `node/cwe-200/referrer-policy-missing.js` | CWE-200 | js-express-referrer-policy-missing | TruePositive | LOW |
| `node/cwe-200/referrer-policy-missing-safe.js` | CWE-200 | js-express-referrer-policy-missing | TrueNegative | — |
| `node/cwe-1021/clickjacking.js` | CWE-1021 | js-express-clickjacking | TruePositive | MEDIUM |
| `node/cwe-1021/clickjacking-safe.js` | CWE-1021 | js-express-clickjacking | TrueNegative | — |
| `node/cwe-525/cache-control-missing.js` | CWE-525 | js-express-cache-control-missing | TruePositive | LOW |
| `node/cwe-525/cache-control-missing-safe.js` | CWE-525 | js-express-cache-control-missing | TrueNegative | — |
| `node/cwe-1321/prototype-pollution-merge.js` | CWE-1321 | js-prototype-pollution-merge | TruePositive | HIGH |
| `node/cwe-1321/prototype-pollution-merge-safe.js` | CWE-1321 | js-prototype-pollution-merge | TrueNegative | — |
| `node/cwe-1321/prototype-pollution-set.js` | CWE-1321 | js-prototype-pollution-set | TruePositive | HIGH |
| `node/cwe-1321/prototype-pollution-set-safe.js` | CWE-1321 | js-prototype-pollution-set | TrueNegative | — |
| `node/cwe-20/req-body-no-validation.js` | CWE-20 | js-express-req-body-no-validation | TruePositive | MEDIUM |
| `node/cwe-20/req-body-no-validation-safe.js` | CWE-20 | js-express-req-body-no-validation | TrueNegative | — |
| `node/cwe-1333/regex-dos.js` | CWE-1333 | js-regex-dos | TruePositive | MEDIUM |
| `node/cwe-1333/regex-dos-safe.js` | CWE-1333 | js-regex-dos | TrueNegative | — |
| `node/cwe-755/json-parse-no-try-catch.js` | CWE-755 | js-json-parse-no-try-catch | TruePositive | LOW |
| `node/cwe-755/json-parse-no-try-catch-safe.js` | CWE-755 | js-json-parse-no-try-catch | TrueNegative | — |
| `node/cwe-434/file-upload-no-mime-check.js` | CWE-434 | js-file-upload-no-mime-check | TruePositive | HIGH |
| `node/cwe-434/file-upload-no-mime-check-safe.js` | CWE-434 | js-file-upload-no-mime-check | TrueNegative | — |
| `node/cwe-400/file-read-sync.js` | CWE-400 | js-path-traversal-fs-readfilesync | TruePositive | MEDIUM |
| `node/cwe-400/file-read-sync-safe.js` | CWE-400 | js-path-traversal-fs-readfilesync | TrueNegative | — |
| `node/cwe-326/tls-min-version.js` | CWE-326 | js-tls-min-version | TruePositive | HIGH |
| `node/cwe-326/tls-min-version-safe.js` | CWE-326 | js-tls-min-version | TrueNegative | — |
| `node/cwe-295/tls-cert-verify-disabled.js` | CWE-295 | js-tls-cert-verify-disabled | TruePositive | CRITICAL |
| `node/cwe-295/tls-cert-verify-disabled-safe.js` | CWE-295 | js-tls-cert-verify-disabled | TrueNegative | — |
| `node/cwe-798/aws-hardcoded-access-key.js` | CWE-798 | js-aws-hardcoded-access-key | TruePositive | CRITICAL |
| `node/cwe-798/aws-hardcoded-access-key-safe.js` | CWE-798 | js-aws-hardcoded-access-key | TrueNegative | — |
| `node/cwe-732/aws-s3-public-read-acl.js` | CWE-732 | js-aws-s3-public-read-acl | TruePositive | HIGH |
| `node/cwe-732/aws-s3-public-read-acl-safe.js` | CWE-732 | js-aws-s3-public-read-acl | TrueNegative | — |
| `node/cwe-1004/session-no-httponly.js` | CWE-1004 | js/session-no-httponly | TruePositive | MEDIUM |
| `node/cwe-1004/session-no-httponly-safe.js` | CWE-1004 | js/session-no-httponly | TrueNegative | — |
| `node/cwe-614/session-no-secure-flag.js` | CWE-614 | js-session-no-secure-flag | TruePositive | MEDIUM |
| `node/cwe-614/session-no-secure-flag-safe.js` | CWE-614 | js-session-no-secure-flag | TrueNegative | — |
| `node/cwe-384/session-fixation.js` | CWE-384 | js-session-fixation | TruePositive | HIGH |
| `node/cwe-384/session-fixation-safe.js` | CWE-384 | js-session-fixation | TrueNegative | — |
| `node/cwe-532/password-in-log.js` | CWE-532 | js-password-in-log | TruePositive | HIGH |
| `node/cwe-532/password-in-log-safe.js` | CWE-532 | js-password-in-log | TrueNegative | — |
| `node/cwe-523/basic-auth-over-http.js` | CWE-523 | js-basic-auth-over-http | TruePositive | HIGH |
| `node/cwe-523/basic-auth-over-http-safe.js` | CWE-523 | js-basic-auth-over-http | TrueNegative | — |
| `node/cwe-613/jwt-no-expiry.js` | CWE-613 | js-jwt-no-expiry | TruePositive | MEDIUM |
| `node/cwe-613/jwt-no-expiry-safe.js` | CWE-613 | js-jwt-no-expiry | TrueNegative | — |
| `node/cwe-347/jwt-none-algorithm.js` | CWE-347 | js/jwt-none-algorithm | TruePositive | CRITICAL |
| `node/cwe-347/jwt-none-algorithm-safe.js` | CWE-347 | js/jwt-none-algorithm | TrueNegative | — |
| `node/cwe-327/jwt-weak-algorithm.js` | CWE-327 | js-jwt-weak-algorithm | TruePositive | HIGH |
| `node/cwe-327/jwt-weak-algorithm-safe.js` | CWE-327 | js-jwt-weak-algorithm | TrueNegative | — |
| `node/cwe-916/pbkdf2-low-iterations.js` | CWE-916 | js-pbkdf2-low-iterations | TruePositive | MEDIUM |
| `node/cwe-916/pbkdf2-low-iterations-safe.js` | CWE-916 | js-pbkdf2-low-iterations | TrueNegative | — |
| `node/cwe-326/rsa-key-too-short.js` | CWE-326 | js-rsa-key-too-short | TruePositive | HIGH |
| `node/cwe-326/rsa-key-too-short-safe.js` | CWE-326 | js-rsa-key-too-short | TrueNegative | — |
| `node/cwe-321/hardcoded-aes-key.js` | CWE-321 | js-hardcoded-aes-key | TruePositive | CRITICAL |
| `node/cwe-321/hardcoded-aes-key-safe.js` | CWE-321 | js-hardcoded-aes-key | TrueNegative | — |
| `node/cwe-90/ldap-injection.js` | CWE-90 | js-ldap-injection | TruePositive | HIGH |
| `node/cwe-90/ldap-injection-safe.js` | CWE-90 | js-ldap-injection | TrueNegative | — |
| `node/cwe-643/xpath-injection.js` | CWE-643 | js-xpath-injection | TruePositive | HIGH |
| `node/cwe-643/xpath-injection-safe.js` | CWE-643 | js-xpath-injection | TrueNegative | — |
| `node/cwe-601/open-redirect.js` | CWE-601 | js/react-window-location-user-input | TruePositive | MEDIUM |
| `node/cwe-601/open-redirect-safe.js` | CWE-601 | js/react-window-location-user-input | TrueNegative | — |

---

## Python (`vuln-sandbox/python/`)

| File | CWE | Rule ID | Expected Outcome | Expected Severity |
|------|-----|---------|-----------------|-------------------|
| `python/cwe-215/django-debug-true.py` | CWE-215 | py-django-debug-true | TruePositive | MEDIUM |
| `python/cwe-215/django-debug-true-safe.py` | CWE-215 | py-django-debug-true | TrueNegative | — |
| `python/cwe-215/flask-debug-true.py` | CWE-215 | py-flask-debug-true | TruePositive | MEDIUM |
| `python/cwe-215/flask-debug-true-safe.py` | CWE-215 | py-flask-debug-true | TrueNegative | — |
| `python/cwe-798/django-secret-key-hardcoded.py` | CWE-798 | py-django-secret-key-hardcoded | TruePositive | CRITICAL |
| `python/cwe-798/django-secret-key-hardcoded-safe.py` | CWE-798 | py-django-secret-key-hardcoded | TrueNegative | — |
| `python/cwe-798/flask-secret-key-hardcoded.py` | CWE-798 | py/flask-secret-key-hardcoded | TruePositive | CRITICAL |
| `python/cwe-798/flask-secret-key-hardcoded-safe.py` | CWE-798 | py/flask-secret-key-hardcoded | TrueNegative | — |
| `python/cwe-798/flask-sqlalchemy-uri-hardcoded.py` | CWE-798 | py-hardcoded-crypto-key | TruePositive | CRITICAL |
| `python/cwe-798/flask-sqlalchemy-uri-hardcoded-safe.py` | CWE-798 | py-hardcoded-crypto-key | TrueNegative | — |
| `python/cwe-798/aws-hardcoded-access-key.py` | CWE-798 | py-hardcoded-crypto-key | TruePositive | CRITICAL |
| `python/cwe-798/aws-hardcoded-access-key-safe.py` | CWE-798 | py-hardcoded-crypto-key | TrueNegative | — |
| `python/cwe-183/django-allowed-hosts-wildcard.py` | CWE-183 | py-django-allowed-hosts-wildcard | TruePositive | MEDIUM |
| `python/cwe-183/django-allowed-hosts-wildcard-safe.py` | CWE-183 | py-django-allowed-hosts-wildcard | TrueNegative | — |
| `python/cwe-352/django-csrf-exempt.py` | CWE-352 | py-django-csrf-exempt | TruePositive | HIGH |
| `python/cwe-352/django-csrf-exempt-safe.py` | CWE-352 | py-django-csrf-exempt | TrueNegative | — |
| `python/cwe-89/sql-injection.py` | CWE-89 | py-sqlite3-execute-fstring | TruePositive | CRITICAL |
| `python/cwe-89/sql-injection-safe.py` | CWE-89 | py-sqlite3-execute-fstring | TrueNegative | — |
| `python/cwe-78/command-injection.py` | CWE-78 | py-subprocess-shell-true | TruePositive | CRITICAL |
| `python/cwe-78/command-injection-safe.py` | CWE-78 | py-subprocess-shell-true | TrueNegative | — |
| `python/cwe-94/ssti.py` | CWE-94 | py-flask-render-template-string | TruePositive | CRITICAL |
| `python/cwe-94/ssti-safe.py` | CWE-94 | py-flask-render-template-string | TrueNegative | — |
| `python/cwe-90/ldap-injection.py` | CWE-90 | py-ldap-search-fstring | TruePositive | HIGH |
| `python/cwe-90/ldap-injection-safe.py` | CWE-90 | py-ldap-search-fstring | TrueNegative | — |
| `python/cwe-643/xpath-injection.py` | CWE-643 | py-xpath-injection | TruePositive | HIGH |
| `python/cwe-643/xpath-injection-safe.py` | CWE-643 | py-xpath-injection | TrueNegative | — |
| `python/cwe-918/ssrf-http-get.py` | CWE-918 | py-requests-get-fstring | TruePositive | HIGH |
| `python/cwe-918/ssrf-http-get-safe.py` | CWE-918 | py-requests-get-fstring | TrueNegative | — |
| `python/cwe-502/unsafe-deserialize.py` | CWE-502 | py-pickle-loads | TruePositive | CRITICAL |
| `python/cwe-502/unsafe-deserialize-safe.py` | CWE-502 | py-pickle-loads | TrueNegative | — |
| `python/cwe-295/requests-verify-false.py` | CWE-295 | py-ssl-unverified | TruePositive | HIGH |
| `python/cwe-295/requests-verify-false-safe.py` | CWE-295 | py-ssl-unverified | TrueNegative | — |
| `python/cwe-377/temp-file-insecure.py` | CWE-377 | py-tempfile-insecure | TruePositive | MEDIUM |
| `python/cwe-377/temp-file-insecure-safe.py` | CWE-377 | py-tempfile-insecure | TrueNegative | — |
| `python/cwe-732/file-permissions-world-writable.py` | CWE-732 | py-os-chmod-world-writable | TruePositive | HIGH |
| `python/cwe-732/file-permissions-world-writable-safe.py` | CWE-732 | py-os-chmod-world-writable | TrueNegative | — |
| `python/cwe-732/aws-s3-public-read-acl.py` | CWE-732 | py-aws-s3-public-read-acl | TruePositive | HIGH |
| `python/cwe-732/aws-s3-public-read-acl-safe.py` | CWE-732 | py-aws-s3-public-read-acl | TrueNegative | — |
| `python/cwe-916/pbkdf2-low-iterations.py` | CWE-916 | py-pbkdf2-low-iterations | TruePositive | MEDIUM |
| `python/cwe-916/pbkdf2-low-iterations-safe.py` | CWE-916 | py-pbkdf2-low-iterations | TrueNegative | — |
| `python/cwe-916/md5-password-hash.py` | CWE-916 | py-hashlib-md5 | TruePositive | HIGH |
| `python/cwe-916/md5-password-hash-safe.py` | CWE-916 | py-hashlib-md5 | TrueNegative | — |
| `python/cwe-326/rsa-key-too-short.py` | CWE-326 | py-rsa-key-too-short | TruePositive | HIGH |
| `python/cwe-326/rsa-key-too-short-safe.py` | CWE-326 | py-rsa-key-too-short | TrueNegative | — |
| `python/cwe-321/hardcoded-aes-key.py` | CWE-321 | py-hardcoded-crypto-key | TruePositive | CRITICAL |
| `python/cwe-321/hardcoded-aes-key-safe.py` | CWE-321 | py-hardcoded-crypto-key | TrueNegative | — |
| `python/cwe-335/insecure-random-seed.py` | CWE-335 | py-random-seed-static | TruePositive | MEDIUM |
| `python/cwe-335/insecure-random-seed-safe.py` | CWE-335 | py-random-seed-static | TrueNegative | — |
| `python/cwe-347/jwt-none-algorithm.py` | CWE-347 | py-jwt-none-algorithm | TruePositive | CRITICAL |
| `python/cwe-347/jwt-none-algorithm-safe.py` | CWE-347 | py-jwt-none-algorithm | TrueNegative | — |
| `python/cwe-327/jwt-weak-algorithm.py` | CWE-327 | py-jwt-weak-algorithm | TruePositive | HIGH |
| `python/cwe-327/jwt-weak-algorithm-safe.py` | CWE-327 | py-jwt-weak-algorithm | TrueNegative | — |
| `python/cwe-760/hardcoded-salt.py` | CWE-760 | py-hardcoded-salt | TruePositive | HIGH |
| `python/cwe-760/hardcoded-salt-safe.py` | CWE-760 | py-hardcoded-salt | TrueNegative | — |
| `python/cwe-532/password-in-log.py` | CWE-532 | py-logging-password | TruePositive | HIGH |
| `python/cwe-532/password-in-log-safe.py` | CWE-532 | py-logging-password | TrueNegative | — |
| `python/cwe-613/jwt-no-expiry.py` | CWE-613 | py-jwt-no-expiry | TruePositive | MEDIUM |
| `python/cwe-613/jwt-no-expiry-safe.py` | CWE-613 | py-jwt-no-expiry | TrueNegative | — |

---

## React/TypeScript (`vuln-sandbox/react/`)

| File | CWE | Rule ID | Expected Outcome | Expected Severity |
|------|-----|---------|-----------------|-------------------|
| `react/cwe-79/dangerously-set-inner-html.tsx` | CWE-79 | js/react-dangerouslysetinnerhtml | TruePositive | HIGH |
| `react/cwe-79/dangerously-set-inner-html-safe.tsx` | CWE-79 | js/react-dangerouslysetinnerhtml | TrueNegative | — |
| `react/cwe-95/eval-injection.tsx` | CWE-95 | js-deser-eval-data | TruePositive | CRITICAL |
| `react/cwe-95/eval-injection-safe.tsx` | CWE-95 | js-deser-eval-data | TrueNegative | — |
| `react/cwe-79/href-javascript.tsx` | CWE-79 | js/react-href-javascript | TruePositive | HIGH |
| `react/cwe-79/href-javascript-safe.tsx` | CWE-79 | js/react-href-javascript | TrueNegative | — |
| `react/cwe-601/open-redirect.tsx` | CWE-601 | js/react-window-location-user-input | TruePositive | MEDIUM |
| `react/cwe-601/open-redirect-safe.tsx` | CWE-601 | js/react-window-location-user-input | TrueNegative | — |
| `react/cwe-922/local-storage-token.tsx` | CWE-922 | js/react-localstorage-sensitive | TruePositive | MEDIUM |
| `react/cwe-922/local-storage-token-safe.tsx` | CWE-922 | js/react-localstorage-sensitive | TrueNegative | — |
| `react/cwe-362/use-effect-missing-dep.tsx` | CWE-362 | js-react-use-effect-missing-dep | TruePositive | LOW |
| `react/cwe-362/use-effect-missing-dep-safe.tsx` | CWE-362 | js-react-use-effect-missing-dep | TrueNegative | — |
| `react/cwe-79/dom-document-write.tsx` | CWE-79 | js-xss-document-write | TruePositive | HIGH |
| `react/cwe-79/dom-document-write-safe.tsx` | CWE-79 | js-xss-document-write | TrueNegative | — |
| `react/cwe-346/dom-post-message-wildcard.tsx` | CWE-346 | js-dom-post-message-wildcard | TruePositive | MEDIUM |
| `react/cwe-346/dom-post-message-wildcard-safe.tsx` | CWE-346 | js-dom-post-message-wildcard | TrueNegative | — |
| `react/cwe-942/cors-wildcard.tsx` | CWE-942 | js-express-cors-credentials-wildcard | TruePositive | HIGH |
| `react/cwe-942/cors-wildcard-safe.tsx` | CWE-942 | js-express-cors-credentials-wildcard | TrueNegative | — |
| `react/cwe-614/cookie-insecure.tsx` | CWE-614 | js-session-no-secure-flag | TruePositive | MEDIUM |
| `react/cwe-614/cookie-insecure-safe.tsx` | CWE-614 | js-session-no-secure-flag | TrueNegative | — |

---

## TypeScript (`vuln-sandbox/typescript/`)

| File | CWE | Rule ID | Expected Outcome | Expected Severity |
|------|-----|---------|-----------------|-------------------|
| `typescript/cwe-89/sql-injection.ts` | CWE-89 | js-sql-string-concat | TruePositive | HIGH |
| `typescript/cwe-89/sql-injection-safe.ts` | CWE-89 | js-sql-string-concat | TrueNegative | — |
| `typescript/cwe-78/command-injection.ts` | CWE-78 | js-spawn-shell-true | TruePositive | CRITICAL |
| `typescript/cwe-78/command-injection-safe.ts` | CWE-78 | js-spawn-shell-true | TrueNegative | — |
| `typescript/cwe-22/path-traversal.ts` | CWE-22 | js-path-traversal-fs-readfile | TruePositive | HIGH |
| `typescript/cwe-22/path-traversal-safe.ts` | CWE-22 | js-path-traversal-fs-readfile | TrueNegative | — |
| `typescript/cwe-918/ssrf.ts` | CWE-918 | js-ssrf-fetch-user-url | TruePositive | HIGH |
| `typescript/cwe-918/ssrf-safe.ts` | CWE-918 | js-ssrf-fetch-user-url | TrueNegative | — |
| `typescript/cwe-798/hardcoded-secret.ts` | CWE-798 | js/hardcoded-jwt-secret | TruePositive | CRITICAL |
| `typescript/cwe-798/hardcoded-secret-safe.ts` | CWE-798 | js/hardcoded-jwt-secret | TrueNegative | — |
| `typescript/cwe-79/xss.ts` | CWE-79 | js-xss-innerhtml-assignment | TruePositive | HIGH |
| `typescript/cwe-79/xss-safe.ts` | CWE-79 | js-xss-innerhtml-assignment | TrueNegative | — |

---

## Go (`vuln-sandbox/go/`)

| File | CWE | Rule ID | Expected Outcome | Expected Severity |
|------|-----|---------|-----------------|-------------------|
| `go/cwe-89/sql-injection.go` | CWE-89 | go-sql-string-concat | TruePositive | HIGH |
| `go/cwe-89/sql-injection-safe.go` | CWE-89 | go-sql-string-concat | TrueNegative | — |
| `go/cwe-89/sql-sprintf.go` | CWE-89 | go-fmt-sprintf-sql | TruePositive | HIGH |
| `go/cwe-89/sql-sprintf-safe.go` | CWE-89 | go-fmt-sprintf-sql | TrueNegative | — |
| `go/cwe-78/command-injection.go` | CWE-78 | go-exec-command-bash-c | TruePositive | CRITICAL |
| `go/cwe-78/command-injection-safe.go` | CWE-78 | go-exec-command-bash-c | TrueNegative | — |
| `go/cwe-22/path-traversal.go` | CWE-22 | go-os-open-sprintf | TruePositive | HIGH |
| `go/cwe-22/path-traversal-safe.go` | CWE-22 | go-os-open-sprintf | TrueNegative | — |
| `go/cwe-918/ssrf.go` | CWE-918 | go-http-get-sprintf | TruePositive | HIGH |
| `go/cwe-918/ssrf-safe.go` | CWE-918 | go-http-get-sprintf | TrueNegative | — |
| `go/cwe-295/tls-insecure-skip-verify.go` | CWE-295 | go/tls-insecure-skip-verify | TruePositive | CRITICAL |
| `go/cwe-295/tls-insecure-skip-verify-safe.go` | CWE-295 | go/tls-insecure-skip-verify | TrueNegative | — |
| `go/cwe-327/weak-crypto.go` | CWE-327 | go-des-cipher-usage | TruePositive | HIGH |
| `go/cwe-327/weak-crypto-safe.go` | CWE-327 | go-des-cipher-usage | TrueNegative | — |
| `go/cwe-326/weak-rsa-key.go` | CWE-326 | go-weak-rsa-key-size | TruePositive | HIGH |
| `go/cwe-326/weak-rsa-key-safe.go` | CWE-326 | go-weak-rsa-key-size | TrueNegative | — |
| `go/cwe-321/hardcoded-aes-key.go` | CWE-321 | go-hardcoded-aes-key | TruePositive | CRITICAL |
| `go/cwe-321/hardcoded-aes-key-safe.go` | CWE-321 | go-hardcoded-aes-key | TrueNegative | — |
| `go/cwe-601/open-redirect.go` | CWE-601 | go/http-redirect-user-input | TruePositive | MEDIUM |
| `go/cwe-601/open-redirect-safe.go` | CWE-601 | go/http-redirect-user-input | TrueNegative | — |

---

## Java (`vuln-sandbox/java/`)

| File | CWE | Rule ID | Expected Outcome | Expected Severity |
|------|-----|---------|-----------------|-------------------|
| `java/cwe-89/SqlInjection.java` | CWE-89 | java-sqli-statement-execute-concat | TruePositive | HIGH |
| `java/cwe-89/SqlInjectionSafe.java` | CWE-89 | java-sqli-statement-execute-concat | TrueNegative | — |
| `java/cwe-89/HibernateInjection.java` | CWE-89 | java-sqli-hibernate-createquery-concat | TruePositive | HIGH |
| `java/cwe-89/HibernateInjectionSafe.java` | CWE-89 | java-sqli-hibernate-createquery-concat | TrueNegative | — |
| `java/cwe-78/CommandInjection.java` | CWE-78 | java-cmdi-runtime-exec-concat | TruePositive | CRITICAL |
| `java/cwe-78/CommandInjectionSafe.java` | CWE-78 | java-cmdi-runtime-exec-concat | TrueNegative | — |
| `java/cwe-78/ProcessBuilderShell.java` | CWE-78 | java-cmdi-processbuilder-shell | TruePositive | CRITICAL |
| `java/cwe-78/ProcessBuilderShellSafe.java` | CWE-78 | java-cmdi-processbuilder-shell | TrueNegative | — |
| `java/cwe-22/PathTraversal.java` | CWE-22 | java-path-file-concat | TruePositive | HIGH |
| `java/cwe-22/PathTraversalSafe.java` | CWE-22 | java-path-file-concat | TrueNegative | — |
| `java/cwe-22/PathsGetTraversal.java` | CWE-22 | java-path-paths-get-concat | TruePositive | HIGH |
| `java/cwe-22/PathsGetTraversalSafe.java` | CWE-22 | java-path-paths-get-concat | TrueNegative | — |
| `java/cwe-79/XssServlet.java` | CWE-79 | java-xss-printwriter-html | TruePositive | HIGH |
| `java/cwe-79/XssServletSafe.java` | CWE-79 | java-xss-printwriter-html | TrueNegative | — |
| `java/cwe-918/SsrfServlet.java` | CWE-918 | java-ssrf-httpurlconnection-concat | TruePositive | HIGH |
| `java/cwe-918/SsrfServletSafe.java` | CWE-918 | java-ssrf-httpurlconnection-concat | TrueNegative | — |
| `java/cwe-918/RestTemplateSsrf.java` | CWE-918 | java-ssrf-resttemplate-concat | TruePositive | HIGH |
| `java/cwe-918/RestTemplateSsrfSafe.java` | CWE-918 | java-ssrf-resttemplate-concat | TrueNegative | — |
| `java/cwe-798/HardcodedCredentials.java` | CWE-798 | java-crypto-hardcoded-secretkey | TruePositive | CRITICAL |
| `java/cwe-798/HardcodedCredentialsSafe.java` | CWE-798 | java-crypto-hardcoded-secretkey | TrueNegative | — |
| `java/cwe-502/UnsafeDeserialization.java` | CWE-502 | java-deserialization-objectinputstream | TruePositive | CRITICAL |
| `java/cwe-502/UnsafeDeserializationSafe.java` | CWE-502 | java-deserialization-objectinputstream | TrueNegative | — |

---

## Rust (`vuln-sandbox/rust/`)

| File | CWE | Rule ID | Expected Outcome | Expected Severity |
|------|-----|---------|-----------------|-------------------|
| `rust/cwe-89/sql_injection.rs` | CWE-89 | rust-sqlx-format-query | TruePositive | HIGH |
| `rust/cwe-89/sql_injection_safe.rs` | CWE-89 | rust-sqlx-format-query | TrueNegative | — |
| `rust/cwe-89/diesel_injection.rs` | CWE-89 | rust-diesel-sql-query-format | TruePositive | HIGH |
| `rust/cwe-89/diesel_injection_safe.rs` | CWE-89 | rust-diesel-sql-query-format | TrueNegative | — |
| `rust/cwe-78/command_injection.rs` | CWE-78 | rust-command-shell-sh | TruePositive | CRITICAL |
| `rust/cwe-78/command_injection_safe.rs` | CWE-78 | rust-command-shell-sh | TrueNegative | — |
| `rust/cwe-78/command_variable.rs` | CWE-78 | rust-command-new-variable | TruePositive | HIGH |
| `rust/cwe-78/command_variable_safe.rs` | CWE-78 | rust-command-new-variable | TrueNegative | — |
| `rust/cwe-22/path_traversal.rs` | CWE-22 | rust-fs-read-format | TruePositive | HIGH |
| `rust/cwe-22/path_traversal_safe.rs` | CWE-22 | rust-fs-read-format | TrueNegative | — |
| `rust/cwe-22/file_open_traversal.rs` | CWE-22 | rust-file-open-format | TruePositive | HIGH |
| `rust/cwe-22/file_open_traversal_safe.rs` | CWE-22 | rust-file-open-format | TrueNegative | — |
| `rust/cwe-918/ssrf.rs` | CWE-918 | rust-command-web-input | TruePositive | CRITICAL |
| `rust/cwe-918/ssrf_safe.rs` | CWE-918 | rust-command-web-input | TrueNegative | — |
| `rust/cwe-327/weak_crypto.rs` | CWE-327 | rust-des-cipher-usage | TruePositive | HIGH |
| `rust/cwe-327/weak_crypto_safe.rs` | CWE-327 | rust-des-cipher-usage | TrueNegative | — |
| `rust/cwe-798/hardcoded_secret.rs` | CWE-798 | rust-hardcoded-crypto-key | TruePositive | CRITICAL |
| `rust/cwe-798/hardcoded_secret_safe.rs` | CWE-798 | rust-hardcoded-crypto-key | TrueNegative | — |

---

## How to Use as a Regression Test

Scan the entire sandbox and verify the finding count matches the total above:

```bash
# CI smoke test — run from repo root
sicario scan vuln-sandbox/ --format json | jq '.findings | length'
# Expected output: 115
```

Scan a specific language subdirectory:

```bash
sicario scan vuln-sandbox/node/       # expect 40 findings (from 40 TP files; 40 TN files produce 0)
sicario scan vuln-sandbox/python/     # expect 29 findings
sicario scan vuln-sandbox/react/      # expect 10 findings
sicario scan vuln-sandbox/typescript/ # expect 6 findings
sicario scan vuln-sandbox/go/         # expect 10 findings
sicario scan vuln-sandbox/java/       # expect 11 findings
sicario scan vuln-sandbox/rust/       # expect 9 findings
```

Verify a specific rule fires with the correct rule ID:

```bash
sicario scan vuln-sandbox/node/cwe-89/sql-injection.js --format json \
  | jq '.findings[] | {rule_id, severity}'
# Expected: { "rule_id": "js-sql-string-concat", "severity": "HIGH" }
```

Verify a TN file produces zero findings:

```bash
sicario scan vuln-sandbox/node/cwe-89/sql-injection-safe.js --format json \
  | jq '.findings | length'
# Expected: 0
```

If the finding count changes or a rule ID / severity does not match this manifest, a rule has been added, removed, or modified. Update this manifest accordingly and commit the change alongside the rule change.

---

## Severity Breakdown (TP files only)

| Severity | Count |
|----------|-------|
| CRITICAL | 35    |
| HIGH     | 57    |
| MEDIUM   | 19    |
| LOW      | 4     |
| **Total**| **115**|

> **Note:** All paths in the table above are relative to `vuln-sandbox/`. The `vuln-sandbox/` directory is excluded from production scans via the root `.sicarioignore` entry.
> TN files (marked `TrueNegative`) should produce **zero findings** when scanned. They demonstrate the safe/correct coding pattern for each rule.
> Rule IDs use the canonical engine format as defined in `sicario-cli/rules/` and `sicario-rules/rules/`. Rules prefixed with `js/`, `py/`, or `go/` are from the `sicario-rules` community rules submodule; rules prefixed with `js-`, `py-`, `go-`, `java-`, or `rust-` are from the embedded engine rules in `sicario-cli/rules/`.

## Ruby (`vuln-sandbox/ruby/`)

| File | CWE | Rule ID | Expected Outcome | Expected Severity |
|------|-----|---------|-----------------|-------------------|
| `ruby/cwe-89/sql-injection.rb` | CWE-89 | ruby/sql-injection | TruePositive | CRITICAL |
| `ruby/cwe-89/sql-injection-safe.rb` | CWE-89 | ruby/sql-injection | TrueNegative | — |
| `ruby/cwe-78/command-injection.rb` | CWE-78 | ruby/command-injection | TruePositive | CRITICAL |
| `ruby/cwe-78/command-injection-safe.rb` | CWE-78 | ruby/command-injection | TrueNegative | — |
| `ruby/cwe-22/path-traversal.rb` | CWE-22 | ruby/path-traversal | TruePositive | HIGH |
| `ruby/cwe-22/path-traversal-safe.rb` | CWE-22 | ruby/path-traversal | TrueNegative | — |
| `ruby/cwe-79/xss.rb` | CWE-79 | ruby/xss-erb-unescaped | TruePositive | HIGH |
| `ruby/cwe-79/xss-safe.rb` | CWE-79 | ruby/xss-erb-unescaped | TrueNegative | — |
| `ruby/cwe-798/hardcoded-secret.rb` | CWE-798 | ruby/hardcoded-secret | TruePositive | HIGH |
| `ruby/cwe-798/hardcoded-secret-safe.rb` | CWE-798 | ruby/hardcoded-secret | TrueNegative | — |
| `ruby/cwe-918/ssrf.rb` | CWE-918 | ruby/ssrf | TruePositive | HIGH |
| `ruby/cwe-918/ssrf-safe.rb` | CWE-918 | ruby/ssrf | TrueNegative | — |

---

## PHP (`vuln-sandbox/php/`)

| File | CWE | Rule ID | Expected Outcome | Expected Severity |
|------|-----|---------|-----------------|-------------------|
| `php/cwe-89/sql-injection.php` | CWE-89 | php/sql-injection | TruePositive | CRITICAL |
| `php/cwe-89/sql-injection-safe.php` | CWE-89 | php/sql-injection | TrueNegative | — |
| `php/cwe-78/command-injection.php` | CWE-78 | php/command-injection | TruePositive | CRITICAL |
| `php/cwe-78/command-injection-safe.php` | CWE-78 | php/command-injection | TrueNegative | — |
| `php/cwe-22/path-traversal.php` | CWE-22 | php/path-traversal | TruePositive | HIGH |
| `php/cwe-22/path-traversal-safe.php` | CWE-22 | php/path-traversal | TrueNegative | — |
| `php/cwe-79/xss.php` | CWE-79 | php/xss-echo-unescaped | TruePositive | HIGH |
| `php/cwe-79/xss-safe.php` | CWE-79 | php/xss-echo-unescaped | TrueNegative | — |
| `php/cwe-798/hardcoded-secret.php` | CWE-798 | php/hardcoded-secret | TruePositive | HIGH |
| `php/cwe-798/hardcoded-secret-safe.php` | CWE-798 | php/hardcoded-secret | TrueNegative | — |
| `php/cwe-918/ssrf.php` | CWE-918 | php/ssrf | TruePositive | HIGH |
| `php/cwe-918/ssrf-safe.php` | CWE-918 | php/ssrf | TrueNegative | — |

---

## C# (`vuln-sandbox/csharp/`)

| File | CWE | Rule ID | Expected Outcome | Expected Severity |
|------|-----|---------|-----------------|-------------------|
| `csharp/cwe-89/sql-injection.cs` | CWE-89 | csharp/sql-injection | TruePositive | CRITICAL |
| `csharp/cwe-89/sql-injection-safe.cs` | CWE-89 | csharp/sql-injection | TrueNegative | — |
| `csharp/cwe-78/command-injection.cs` | CWE-78 | csharp/command-injection | TruePositive | CRITICAL |
| `csharp/cwe-78/command-injection-safe.cs` | CWE-78 | csharp/command-injection | TrueNegative | — |
| `csharp/cwe-22/path-traversal.cs` | CWE-22 | csharp/path-traversal | TruePositive | HIGH |
| `csharp/cwe-22/path-traversal-safe.cs` | CWE-22 | csharp/path-traversal | TrueNegative | — |
| `csharp/cwe-79/xss.cs` | CWE-79 | csharp/xss-html-raw | TruePositive | HIGH |
| `csharp/cwe-79/xss-safe.cs` | CWE-79 | csharp/xss-html-raw | TrueNegative | — |
| `csharp/cwe-798/hardcoded-secret.cs` | CWE-798 | csharp/hardcoded-secret | TruePositive | HIGH |
| `csharp/cwe-798/hardcoded-secret-safe.cs` | CWE-798 | csharp/hardcoded-secret | TrueNegative | — |
| `csharp/cwe-918/ssrf.cs` | CWE-918 | csharp/ssrf | TruePositive | HIGH |
| `csharp/cwe-918/ssrf-safe.cs` | CWE-918 | csharp/ssrf | TrueNegative | — |

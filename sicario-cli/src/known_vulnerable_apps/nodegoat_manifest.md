# OWASP NodeGoat Ground-Truth Manifest

OWASP NodeGoat is a deliberately insecure Node.js web application that
demonstrates the OWASP Top 10 vulnerabilities. This manifest lists the key
vulnerable files and the Sicario rules expected to fire against them.

> Source: https://github.com/OWASP/NodeGoat

---

## Vulnerable Files

| File | CWE | Rule ID | Expected Outcome | Expected Severity |
|------|-----|---------|-----------------|-------------------|
| `app/routes/research.js` | CWE-89 | js-sql-string-concat | TruePositive | HIGH |
| `app/routes/profile.js` | CWE-89 | js-sql-string-concat | TruePositive | HIGH |
| `app/routes/contributions.js` | CWE-89 | js-sql-string-concat | TruePositive | HIGH |
| `app/routes/session.js` | CWE-798 | js/hardcoded-jwt-secret | TruePositive | CRITICAL |
| `config/env/all.js` | CWE-798 | js/hardcoded-jwt-secret | TruePositive | CRITICAL |
| `app/routes/index.js` | CWE-79 | js-xss-innerhtml-assignment | TruePositive | HIGH |
| `app/routes/allocations.js` | CWE-22 | js-path-traversal-fs-readfile | TruePositive | HIGH |
| `app/routes/memos.js` | CWE-78 | js-spawn-shell-true | TruePositive | CRITICAL |
| `app/routes/benefits.js` | CWE-918 | js-ssrf-http-request-user-url | TruePositive | HIGH |
| `app/routes/session.js` | CWE-384 | js-session-fixation | TruePositive | HIGH |

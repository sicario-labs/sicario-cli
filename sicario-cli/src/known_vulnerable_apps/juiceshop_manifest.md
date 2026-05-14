# OWASP Juice Shop Ground-Truth Manifest

OWASP Juice Shop is a deliberately insecure Node.js/Angular web application.
This manifest lists the key vulnerable files and the Sicario rules expected
to fire against them.

> Source: https://github.com/juice-shop/juice-shop

---

## Vulnerable Files

| File | CWE | Rule ID | Expected Outcome | Expected Severity |
|------|-----|---------|-----------------|-------------------|
| `routes/login.ts` | CWE-89 | js-sql-string-concat | TruePositive | HIGH |
| `routes/search.ts` | CWE-89 | js-sql-string-concat | TruePositive | HIGH |
| `routes/userProfile.ts` | CWE-89 | js-sql-string-concat | TruePositive | HIGH |
| `routes/fileServer.ts` | CWE-22 | js-path-traversal-fs-readfile | TruePositive | HIGH |
| `routes/profileImageFileUpload.ts` | CWE-22 | js-path-traversal-fs-readfile | TruePositive | HIGH |
| `lib/insecurity.ts` | CWE-798 | js/hardcoded-jwt-secret | TruePositive | CRITICAL |
| `lib/insecurity.ts` | CWE-327 | js-jwt-weak-algorithm | TruePositive | HIGH |
| `routes/angular.ts` | CWE-79 | js-xss-innerhtml-assignment | TruePositive | HIGH |
| `frontend/src/app/score-board/score-board.component.ts` | CWE-79 | js-xss-innerhtml-assignment | TruePositive | HIGH |
| `routes/redirect.ts` | CWE-601 | js/react-window-location-user-input | TruePositive | MEDIUM |
| `routes/updateUserProfile.ts` | CWE-918 | js-ssrf-http-request-user-url | TruePositive | HIGH |
| `config/default.yml` | CWE-798 | js/hardcoded-jwt-secret | TruePositive | CRITICAL |

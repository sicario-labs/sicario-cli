# WebGoat Ground-Truth Manifest

WebGoat is a deliberately insecure Java/Spring web application maintained by
OWASP for security training. This manifest lists the key vulnerable files and
the Sicario rules expected to fire against them.

> Source: https://github.com/WebGoat/WebGoat

---

## Vulnerable Files

| File | CWE | Rule ID | Expected Outcome | Expected Severity |
|------|-----|---------|-----------------|-------------------|
| `webgoat-lessons/sql-injection/src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java` | CWE-89 | java-sqli-statement-execute-concat | TruePositive | HIGH |
| `webgoat-lessons/sql-injection/src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson6a.java` | CWE-89 | java-sqli-statement-execute-concat | TruePositive | HIGH |
| `webgoat-lessons/sql-injection/src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6b.java` | CWE-89 | java-sqli-statement-execute-concat | TruePositive | HIGH |
| `webgoat-lessons/path-traversal/src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUpload.java` | CWE-22 | java-path-file-concat | TruePositive | HIGH |
| `webgoat-lessons/path-traversal/src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java` | CWE-22 | java-path-file-concat | TruePositive | HIGH |
| `webgoat-lessons/xxe/src/main/java/org/owasp/webgoat/lessons/xxe/SimpleXXE.java` | CWE-611 | java-xxe-documentbuilderfactory | TruePositive | HIGH |
| `webgoat-lessons/deserialization/src/main/java/org/owasp/webgoat/lessons/deserialization/InsecureDeserializationTask.java` | CWE-502 | java-deserialization-objectinputstream | TruePositive | CRITICAL |
| `webgoat-lessons/crypto/src/main/java/org/owasp/webgoat/lessons/crypto/HashingStoringPasswords.java` | CWE-916 | java-crypto-md5-password | TruePositive | HIGH |
| `webgoat-lessons/jwt/src/main/java/org/owasp/webgoat/lessons/jwt/JWTSecretKeyEndpoint.java` | CWE-798 | java-crypto-hardcoded-secretkey | TruePositive | CRITICAL |
| `webgoat-lessons/ssrf/src/main/java/org/owasp/webgoat/lessons/ssrf/SSRFTask1.java` | CWE-918 | java-ssrf-httpurlconnection-concat | TruePositive | HIGH |

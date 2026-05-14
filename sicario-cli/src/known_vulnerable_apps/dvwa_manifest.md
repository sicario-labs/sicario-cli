# DVWA Ground-Truth Manifest

DVWA (Damn Vulnerable Web Application) is a PHP/MySQL web application designed
to be deliberately insecure. This manifest lists the key vulnerable files and
the Sicario rules expected to fire against them.

> Source: https://github.com/digininja/DVWA

---

## Vulnerable Files

| File | CWE | Rule ID | Expected Outcome | Expected Severity |
|------|-----|---------|-----------------|-------------------|
| `vulnerabilities/sqli/source/low.php` | CWE-89 | php/sql-injection | TruePositive | CRITICAL |
| `vulnerabilities/sqli/source/medium.php` | CWE-89 | php/sql-injection | TruePositive | CRITICAL |
| `vulnerabilities/sqli_blind/source/low.php` | CWE-89 | php/sql-injection | TruePositive | CRITICAL |
| `vulnerabilities/exec/source/low.php` | CWE-78 | php/command-injection | TruePositive | CRITICAL |
| `vulnerabilities/exec/source/medium.php` | CWE-78 | php/command-injection | TruePositive | CRITICAL |
| `vulnerabilities/fi/source/low.php` | CWE-22 | php/path-traversal | TruePositive | HIGH |
| `vulnerabilities/fi/source/medium.php` | CWE-22 | php/path-traversal | TruePositive | HIGH |
| `vulnerabilities/xss_r/source/low.php` | CWE-79 | php/xss-echo-unescaped | TruePositive | HIGH |
| `vulnerabilities/xss_r/source/medium.php` | CWE-79 | php/xss-echo-unescaped | TruePositive | HIGH |
| `vulnerabilities/xss_s/source/low.php` | CWE-79 | php/xss-echo-unescaped | TruePositive | HIGH |
| `config/config.inc.php.dist` | CWE-798 | php/hardcoded-secret | TruePositive | HIGH |
| `vulnerabilities/csrf/source/low.php` | CWE-352 | php/xss-echo-unescaped | TruePositive | HIGH |

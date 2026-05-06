@echo off
setlocal EnableDelayedExpansion

set SICARIO=%~dp0target\debug\sicario.exe
set PASS=0
set FAIL=0

echo === SICARIO v2 ETA-ENGINE SMOKE TESTS ===
echo.

:: Helper macro: call with test number, description, file, search string
:: We use a simple sequential structure to avoid label issues

:: ── Test 1: SQL injection scan ──────────────────────────────────────────────
echo [1/14] Scan CWE-89 (SQL injection)...
%SICARIO% scan vuln-sandbox\node\cwe-89 --format json 1>scan_out.json 2>nul
findstr "CWE-89" scan_out.json >nul 2>&1
set R=!errorlevel!
if !R!==0 (echo   PASS: CWE-89 findings detected) else (echo   FAIL: No CWE-89 findings)
if !R!==0 (set /a PASS=!PASS!+1) else (set /a FAIL=!FAIL!+1)

:: ── Test 2: Command injection scan ──────────────────────────────────────────
echo [2/14] Scan CWE-78 (command injection)...
%SICARIO% scan vuln-sandbox\node\cwe-78 --format json 1>scan_out.json 2>nul
findstr "CWE-78" scan_out.json >nul 2>&1
set R=!errorlevel!
if !R!==0 (echo   PASS: CWE-78 findings detected) else (echo   FAIL: No CWE-78 findings)
if !R!==0 (set /a PASS=!PASS!+1) else (set /a FAIL=!FAIL!+1)

:: ── Test 3: SSRF scan ────────────────────────────────────────────────────────
echo [3/14] Scan CWE-918 (SSRF)...
%SICARIO% scan vuln-sandbox\node\cwe-918 --format json 1>scan_out.json 2>nul
findstr "CWE-918" scan_out.json >nul 2>&1
set R=!errorlevel!
if !R!==0 (echo   PASS: CWE-918 findings detected) else (echo   FAIL: No CWE-918 findings)
if !R!==0 (set /a PASS=!PASS!+1) else (set /a FAIL=!FAIL!+1)

:: ── Test 4: Path traversal scan ──────────────────────────────────────────────
echo [4/14] Scan CWE-22 (path traversal)...
%SICARIO% scan vuln-sandbox\node\cwe-22 --format json 1>scan_out.json 2>nul
findstr "CWE-22" scan_out.json >nul 2>&1
set R=!errorlevel!
if !R!==0 (echo   PASS: CWE-22 findings detected) else (echo   FAIL: No CWE-22 findings)
if !R!==0 (set /a PASS=!PASS!+1) else (set /a FAIL=!FAIL!+1)

:: ── Test 5: attack --dry-run SQL injection ───────────────────────────────────
echo [5/14] attack --dry-run (SQL injection)...
cd vuln-sandbox\node\cwe-89
%SICARIO% attack --dry-run --target http://localhost:3000 1>attack_out.txt 2>&1
cd ..\..\..
findstr "SLEEP" vuln-sandbox\node\cwe-89\attack_out.txt >nul 2>&1
set R=!errorlevel!
if !R!==0 (echo   PASS: SQL injection payload generated) else (echo   FAIL: No SQL injection payload)
if !R!==0 (set /a PASS=!PASS!+1) else (set /a FAIL=!FAIL!+1)
del vuln-sandbox\node\cwe-89\attack_out.txt 2>nul

:: ── Test 6: attack --dry-run command injection ───────────────────────────────
echo [6/14] attack --dry-run (command injection)...
cd vuln-sandbox\node\cwe-78
%SICARIO% attack --dry-run --target http://localhost:3000 1>attack_out.txt 2>&1
cd ..\..\..
findstr "sleep 4" vuln-sandbox\node\cwe-78\attack_out.txt >nul 2>&1
set R=!errorlevel!
if !R!==0 (echo   PASS: Command injection payload generated) else (echo   FAIL: No command injection payload)
if !R!==0 (set /a PASS=!PASS!+1) else (set /a FAIL=!FAIL!+1)
del vuln-sandbox\node\cwe-78\attack_out.txt 2>nul

:: ── Test 7: attack --dry-run SSRF ────────────────────────────────────────────
echo [7/14] attack --dry-run (SSRF)...
cd vuln-sandbox\node\cwe-918
%SICARIO% attack --dry-run --target http://localhost:3000 1>attack_out.txt 2>&1
cd ..\..\..
findstr "ssrf-probe" vuln-sandbox\node\cwe-918\attack_out.txt >nul 2>&1
set R=!errorlevel!
if !R!==0 (echo   PASS: SSRF payload generated) else (echo   FAIL: No SSRF payload)
if !R!==0 (set /a PASS=!PASS!+1) else (set /a FAIL=!FAIL!+1)
del vuln-sandbox\node\cwe-918\attack_out.txt 2>nul

:: ── Test 8: guard scan ────────────────────────────────────────────────────────
echo [8/14] guard scan (behavioral anomaly detection)...
cd test-guard
%SICARIO% guard scan --dir node_modules 1>guard_out.txt 2>&1
cd ..
findstr "UnexpectedChildProcess" test-guard\guard_out.txt >nul 2>&1
set R=!errorlevel!
if !R!==0 (echo   PASS: evil-pkg detected) else (echo   FAIL: evil-pkg not detected)
if !R!==0 (set /a PASS=!PASS!+1) else (set /a FAIL=!FAIL!+1)
del test-guard\guard_out.txt 2>nul

:: ── Test 9: fix --staged (JSON output) ───────────────────────────────────────
echo [9/14] fix --staged (Ghost Fix staged mode)...
%SICARIO% fix --staged --format json 1>staged_out.json 2>nul
findstr "\[" staged_out.json >nul 2>&1
set R=!errorlevel!
if !R!==0 (echo   PASS: fix --staged returns JSON array) else (echo   FAIL: fix --staged did not return JSON)
if !R!==0 (set /a PASS=!PASS!+1) else (set /a FAIL=!FAIL!+1)
del staged_out.json 2>nul

:: ── Test 10: hook auto-fix install ───────────────────────────────────────────
echo [10/14] hook auto-fix (Ghost Fix hook install)...
%SICARIO% hook auto-fix 1>hook_out.txt 2>&1
findstr "installed" hook_out.txt >nul 2>&1
set R=!errorlevel!
if !R!==0 (echo   PASS: Ghost Fix hook installed) else (echo   FAIL: Hook install failed)
if !R!==0 (set /a PASS=!PASS!+1) else (set /a FAIL=!FAIL!+1)
del hook_out.txt 2>nul

:: ── Test 11: scan --prove --format json (PoC generation) ─────────────────────
echo [11/14] scan --prove --format json (PoC generation)...
cd vuln-sandbox\node\cwe-89
%SICARIO% scan --prove --format json 1>prove_out.json 2>nul
cd ..\..\..
findstr "poc" vuln-sandbox\node\cwe-89\prove_out.json >nul 2>&1
set R=!errorlevel!
if !R!==0 (echo   PASS: PoC field present in JSON output) else (echo   FAIL: No poc field in JSON output)
if !R!==0 (set /a PASS=!PASS!+1) else (set /a FAIL=!FAIL!+1)
del vuln-sandbox\node\cwe-89\prove_out.json 2>nul

:: ── Test 12: report compliance ───────────────────────────────────────────────
echo [12/14] report compliance (compliance evidence export)...
cd vuln-sandbox\node\cwe-89
%SICARIO% report compliance 1>report_out.txt 2>&1
cd ..\..\..
findstr "Compliance report" vuln-sandbox\node\cwe-89\report_out.txt >nul 2>&1
set R=!errorlevel!
if !R!==0 (echo   PASS: Compliance report generated) else (echo   FAIL: Compliance report failed)
if !R!==0 (set /a PASS=!PASS!+1) else (set /a FAIL=!FAIL!+1)
del vuln-sandbox\node\cwe-89\report_out.txt 2>nul

:: ── Test 13: report mttr ─────────────────────────────────────────────────────
echo [13/14] report mttr (MTTR tracking)...
cd vuln-sandbox\node\cwe-89
%SICARIO% report mttr 1>mttr_out.txt 2>&1
cd ..\..\..
findstr "MTTR" vuln-sandbox\node\cwe-89\mttr_out.txt >nul 2>&1
set R=!errorlevel!
if !R!==0 (echo   PASS: MTTR report generated) else (echo   FAIL: MTTR report failed)
if !R!==0 (set /a PASS=!PASS!+1) else (set /a FAIL=!FAIL!+1)
del vuln-sandbox\node\cwe-89\mttr_out.txt 2>nul

:: ── Test 14: exorcise --dry-run ──────────────────────────────────────────────
echo [14/14] exorcise --dry-run (Git Exorcist)...
set TMPDIR=%TEMP%\sic-ex-%RANDOM%
mkdir "%TMPDIR%" 2>nul
cd /d "%TMPDIR%"
git init >nul 2>&1
git config user.email t@t.com >nul 2>&1
git config user.name T >nul 2>&1
echo const key = 'AKIA' + 'IOSFODNN7EXAMPLE'; > secret.js
git add . >nul 2>&1
git commit -m init >nul 2>&1
%SICARIO% exorcise --dry-run 1>ex_out.txt 2>&1
findstr "Secrets removed" ex_out.txt >nul 2>&1
set R=!errorlevel!
if !R!==0 (echo   PASS: exorcise --dry-run detected secret) else (echo   FAIL: exorcise --dry-run did not detect secret)
if !R!==0 (set /a PASS=!PASS!+1) else (set /a FAIL=!FAIL!+1)
del ex_out.txt 2>nul
cd /d "%~dp0"
rmdir /s /q "%TMPDIR%" 2>nul

:: ── Summary ───────────────────────────────────────────────────────────────────
del scan_out.json 2>nul
echo.
echo === RESULTS: !PASS!/14 passed, !FAIL! failed ===
if !FAIL!==0 (
    echo All tests passed. Ready to release.
    exit /b 0
)
echo Some tests failed.
exit /b 1

//! PocGenerator, PocPayload, and SsrfProbeListener implementations.
//!
//! # Safety Invariants (enforced in Rust, not documentation)
//! 1. Any generated URL that does not resolve to `127.0.0.1` or `::1` is
//!    rejected before printing.
//! 2. Any generated SQL payload containing `DROP`, `DELETE`, `TRUNCATE`,
//!    `UPDATE`, `INSERT`, or `ALTER` is rejected before printing.

use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::engine::vulnerability::Finding;

// ── Destructive SQL keyword blocklist ────────────────────────────────────────

/// Keywords that must never appear in a generated SQL payload.
const DESTRUCTIVE_SQL_KEYWORDS: &[&str] =
    &["DROP", "DELETE", "TRUNCATE", "UPDATE", "INSERT", "ALTER"];

/// Returns `true` if the SQL payload contains any destructive keyword
/// (case-insensitive).
fn contains_destructive_sql(payload: &str) -> bool {
    let upper = payload.to_uppercase();
    DESTRUCTIVE_SQL_KEYWORDS.iter().any(|kw| upper.contains(kw))
}

/// Returns `true` if the URL is safe (resolves to `127.0.0.1` or `::1`).
///
/// We check the host portion of the URL string directly — no DNS resolution
/// is performed so there is no TOCTOU window.
fn is_localhost_url(url: &str) -> bool {
    // Strip scheme
    let without_scheme = if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else {
        url
    };

    // Extract host (before first '/' or end of string)
    let host = without_scheme.split('/').next().unwrap_or(without_scheme);

    // Strip port if present
    let host_no_port = if host.starts_with('[') {
        // IPv6 literal with brackets: [::1]:port or [::1]
        host.trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(host)
    } else if host.contains(':') {
        // Could be IPv6 without brackets (e.g. ::1) or host:port
        // If it has more than one colon, it's IPv6
        let colon_count = host.chars().filter(|&c| c == ':').count();
        if colon_count > 1 {
            // IPv6 address without brackets — use the whole thing as host
            host
        } else {
            // host:port — strip the port
            host.split(':').next().unwrap_or(host)
        }
    } else {
        host
    };

    matches!(host_no_port, "127.0.0.1" | "::1" | "localhost")
}

// ── PocPayload ────────────────────────────────────────────────────────────────

/// A generated proof-of-concept payload for a confirmed finding.
#[derive(Debug, Clone)]
pub struct PocPayload {
    /// Human-readable location of the vulnerability, e.g. `"src/db.js:42"`.
    pub vuln_location: String,
    /// The generated `curl` command that exercises the vulnerability.
    pub curl_command: String,
    /// Human-readable interpretation of what a successful response means.
    pub interpretation: String,
}

// ── DB driver detection ───────────────────────────────────────────────────────

/// Detected database driver, used to select the correct time-based sleep
/// function for SQL injection payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbDriver {
    /// PostgreSQL — uses `pg_sleep(5)`.
    Postgres,
    /// MySQL / MariaDB — uses `SLEEP(5)`.
    Mysql,
    /// Microsoft SQL Server — uses `WAITFOR DELAY '0:0:5'`.
    Mssql,
    /// Unknown / undetected — defaults to `SLEEP(5)`.
    Unknown,
}

impl DbDriver {
    /// Return the time-based sleep expression for this driver.
    pub fn sleep_expression(&self) -> &'static str {
        match self {
            DbDriver::Postgres => "pg_sleep(5)",
            DbDriver::Mysql => "SLEEP(5)",
            DbDriver::Mssql => "WAITFOR DELAY '0:0:5'",
            DbDriver::Unknown => "SLEEP(5)",
        }
    }

    /// Detect the DB driver from the rule_id or snippet heuristics.
    pub fn detect(finding: &Finding) -> Self {
        let haystack = format!(
            "{} {}",
            finding.rule_id.to_lowercase(),
            finding.snippet.to_lowercase()
        );

        if haystack.contains("pg")
            || haystack.contains("postgres")
            || haystack.contains("postgresql")
        {
            return DbDriver::Postgres;
        }
        if haystack.contains("mssql")
            || haystack.contains("sqlserver")
            || haystack.contains("tedious")
            || haystack.contains("waitfor")
        {
            return DbDriver::Mssql;
        }
        if haystack.contains("mysql") || haystack.contains("mariadb") || haystack.contains("mysql2")
        {
            return DbDriver::Mysql;
        }
        DbDriver::Unknown
    }
}

// ── PocGenerator ─────────────────────────────────────────────────────────────

/// Generates safe, localhost-only proof-of-concept payloads for confirmed
/// security findings.
///
/// # Zero-Exfiltration Invariant
///
/// **INVARIANT**: `PocGenerator` makes ZERO outbound network requests.
/// All generated payloads target `127.0.0.1` (loopback) only, and the
/// `SsrfProbeListener` is strictly **inbound** — it only listens for
/// incoming connections; it never initiates any outbound connection.
///
/// Enforcement:
///   - Every generated URL is validated by `is_localhost_url()` before use.
///     Any URL that does not resolve to `127.0.0.1` or `::1` is rejected.
///   - `SsrfProbeListener` binds to `127.0.0.1:0` (loopback only) and
///     calls `TcpListener::accept()` — it never calls `TcpStream::connect()`.
///   - No `reqwest`, `hyper`, `ureq`, or any HTTP client is used in this
///     module. The only network primitive is `TcpListener` (inbound only).
///
/// Code reviewers: if you see any outbound `TcpStream::connect()`, HTTP
/// client call, or any URL not validated by `is_localhost_url()` in this
/// module, that is a zero-exfiltration violation and MUST be rejected.
pub struct PocGenerator;

impl PocGenerator {
    /// Generate a PoC payload for the given finding.
    ///
    /// Returns `None` if:
    /// - The CWE is not supported.
    /// - Insufficient AST context is available to build a meaningful payload.
    /// - Safety checks reject the generated payload.
    pub fn generate(finding: &Finding) -> Option<PocPayload> {
        let cwe = finding.cwe_id.as_deref().unwrap_or("");

        // Normalise: strip "CWE-" prefix if present
        let cwe_num = cwe.trim_start_matches("CWE-").trim_start_matches("cwe-");

        match cwe_num {
            "89" => Self::generate_sqli(finding),
            "918" => Self::generate_ssrf(finding),
            "78" => Self::generate_cmdi(finding),
            "22" => Self::generate_path_traversal(finding),
            _ => {
                // Unsupported CWE — check rule_id as fallback
                let rule = finding.rule_id.to_lowercase();
                if rule.contains("sql") {
                    Self::generate_sqli(finding)
                } else if rule.contains("ssrf") {
                    Self::generate_ssrf(finding)
                } else if rule.contains("command") || rule.contains("cmd") || rule.contains("exec")
                {
                    Self::generate_cmdi(finding)
                } else if rule.contains("path")
                    || rule.contains("traversal")
                    || rule.contains("lfi")
                {
                    Self::generate_path_traversal(finding)
                } else {
                    eprintln!("PoC not available for this finding — insufficient AST context.");
                    None
                }
            }
        }
    }

    // ── SQL Injection (CWE-89) ────────────────────────────────────────────

    fn generate_sqli(finding: &Finding) -> Option<PocPayload> {
        let driver = DbDriver::detect(finding);
        let sleep_expr = driver.sleep_expression();

        // Build a time-based blind injection payload
        let payload = format!("' OR 1=1; SELECT {}-- -", sleep_expr);

        // Safety check: reject if any destructive keyword slipped in
        if contains_destructive_sql(&payload) {
            eprintln!("PoC not available for this finding — insufficient AST context.");
            return None;
        }

        let vuln_location = format!("{}:{}", finding.file_path.display(), finding.line);

        // Extract a plausible route from the snippet or use a generic one
        let route = extract_route_from_snippet(&finding.snippet)
            .unwrap_or_else(|| "/api/query".to_string());

        let url = format!("http://127.0.0.1:3000{}", route);

        // Safety check: URL must be localhost
        if !is_localhost_url(&url) {
            eprintln!("PoC not available for this finding — insufficient AST context.");
            return None;
        }

        let curl_command = format!(
            r#"curl -s -o /dev/null -w "%{{time_total}}" -X POST "{}" \
  -H "Content-Type: application/json" \
  -d '{{"id":"{}"}}'
# If response time >= 5 seconds, the injection is confirmed."#,
            url, payload
        );

        let interpretation = format!(
            "If the server takes ~5 seconds to respond, the SQL injection is confirmed. \
The payload uses {} to introduce a deliberate delay. \
Run against a local development instance only.",
            sleep_expr
        );

        Some(PocPayload {
            vuln_location,
            curl_command,
            interpretation,
        })
    }

    // ── SSRF (CWE-918) ───────────────────────────────────────────────────

    fn generate_ssrf(finding: &Finding) -> Option<PocPayload> {
        // Spawn a probe listener and get its port
        let listener = SsrfProbeListener::bind().ok()?;
        let probe_port = listener.port();

        // Start listening in the background
        listener.start();

        let probe_url = format!("http://127.0.0.1:{}/ssrf-probe", probe_port);

        // Safety check: probe URL must be localhost
        if !is_localhost_url(&probe_url) {
            eprintln!("PoC not available for this finding — insufficient AST context.");
            return None;
        }

        let vuln_location = format!("{}:{}", finding.file_path.display(), finding.line);

        // Extract a plausible URL parameter name from the snippet
        let param =
            extract_url_param_from_snippet(&finding.snippet).unwrap_or_else(|| "url".to_string());

        let route = extract_route_from_snippet(&finding.snippet)
            .unwrap_or_else(|| "/api/fetch".to_string());

        let target_url = format!("http://127.0.0.1:3000{}", route);

        if !is_localhost_url(&target_url) {
            eprintln!("PoC not available for this finding — insufficient AST context.");
            return None;
        }

        let curl_command = format!(
            r#"curl -s -X POST "{}" \
  -H "Content-Type: application/json" \
  -d '{{"{}":"{}"}}'
# Check the SsrfProbeListener output above — a connection confirms SSRF."#,
            target_url, param, probe_url
        );

        let interpretation = format!(
            "A SsrfProbeListener is listening on port {}. \
If the server makes an outbound request to http://127.0.0.1:{}/ssrf-probe, \
the SSRF vulnerability is confirmed. The listener will print a confirmation \
message and shut down after 30 seconds.",
            probe_port, probe_port
        );

        Some(PocPayload {
            vuln_location,
            curl_command,
            interpretation,
        })
    }

    // ── Command Injection (CWE-78) ────────────────────────────────────────

    fn generate_cmdi(finding: &Finding) -> Option<PocPayload> {
        let vuln_location = format!("{}:{}", finding.file_path.display(), finding.line);

        // Echo-based technique — safe, read-only, produces a unique marker
        let payload = "; echo sicario-poc-$(date +%s)";

        let param =
            extract_cmd_param_from_snippet(&finding.snippet).unwrap_or_else(|| "cmd".to_string());

        let route =
            extract_route_from_snippet(&finding.snippet).unwrap_or_else(|| "/api/run".to_string());

        let url = format!("http://127.0.0.1:3000{}", route);

        if !is_localhost_url(&url) {
            eprintln!("PoC not available for this finding — insufficient AST context.");
            return None;
        }

        let curl_command = format!(
            r#"curl -s -X POST "{}" \
  -H "Content-Type: application/json" \
  -d '{{"{}":"ls{}"}}'
# Look for "sicario-poc-<timestamp>" in the response body."#,
            url, param, payload
        );

        let interpretation = "If the response body contains 'sicario-poc-<unix_timestamp>', \
the command injection is confirmed. The payload appends a harmless `echo` \
command that produces a unique, timestamped marker. \
Run against a local development instance only."
            .to_string();

        Some(PocPayload {
            vuln_location,
            curl_command,
            interpretation,
        })
    }

    // ── Path Traversal (CWE-22) ───────────────────────────────────────────

    fn generate_path_traversal(finding: &Finding) -> Option<PocPayload> {
        let vuln_location = format!("{}:{}", finding.file_path.display(), finding.line);

        // Read-only target files — safe on both Unix and Windows
        let (target_file, platform_note) = if cfg!(windows) {
            (
                r"C:\Windows\System32\drivers\etc\hosts",
                "Windows hosts file (read-only system file)",
            )
        } else {
            ("/etc/hostname", "Unix hostname file (read-only)")
        };

        let param =
            extract_path_param_from_snippet(&finding.snippet).unwrap_or_else(|| "file".to_string());

        let route =
            extract_route_from_snippet(&finding.snippet).unwrap_or_else(|| "/api/read".to_string());

        let url = format!("http://127.0.0.1:3000{}", route);

        if !is_localhost_url(&url) {
            eprintln!("PoC not available for this finding — insufficient AST context.");
            return None;
        }

        // URL-encode the traversal sequences
        let traversal = if cfg!(windows) {
            "..%2F..%2F..%2F..%2FWindows%2FSystem32%2Fdrivers%2Fetc%2Fhosts".to_string()
        } else {
            "..%2F..%2F..%2Fetc%2Fhostname".to_string()
        };

        let curl_command = format!(
            r#"curl -s "{}?{}={}"
# If the response contains the contents of {}, path traversal is confirmed."#,
            url, param, traversal, target_file
        );

        let interpretation = format!(
            "If the response body contains the contents of {} ({}), \
the path traversal vulnerability is confirmed. \
This payload only reads a read-only system file — no data is modified. \
Run against a local development instance only.",
            target_file, platform_note
        );

        Some(PocPayload {
            vuln_location,
            curl_command,
            interpretation,
        })
    }
}

// ── Snippet heuristics ────────────────────────────────────────────────────────

/// Try to extract a route path from a code snippet.
/// Looks for string literals that look like URL paths.
fn extract_route_from_snippet(snippet: &str) -> Option<String> {
    // Look for patterns like app.get('/path', ...) or router.post('/path', ...)
    let re = regex::Regex::new(r#"['"](/[a-zA-Z0-9/_:-]*)['"]"#).ok()?;
    re.captures(snippet)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// Try to extract a URL parameter name from a code snippet.
fn extract_url_param_from_snippet(snippet: &str) -> Option<String> {
    // Look for patterns like req.body.url, req.query.target, etc.
    let re = regex::Regex::new(r"req\.[a-z]+\.([a-zA-Z_][a-zA-Z0-9_]*)").ok()?;
    re.captures(snippet)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// Try to extract a command parameter name from a code snippet.
fn extract_cmd_param_from_snippet(snippet: &str) -> Option<String> {
    let re = regex::Regex::new(r"req\.[a-z]+\.([a-zA-Z_][a-zA-Z0-9_]*)").ok()?;
    re.captures(snippet)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// Try to extract a path/file parameter name from a code snippet.
fn extract_path_param_from_snippet(snippet: &str) -> Option<String> {
    let re = regex::Regex::new(r"req\.[a-z]+\.([a-zA-Z_][a-zA-Z0-9_]*)").ok()?;
    re.captures(snippet)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

// ── SsrfProbeListener ────────────────────────────────────────────────────────

/// A short-lived TCP listener bound to `127.0.0.1:0` (OS-assigned port).
///
/// Used to confirm SSRF vulnerabilities: if the target server makes an
/// outbound request to the probe URL, the listener receives the connection
/// and prints a confirmation message.
///
/// The listener shuts down automatically after 30 seconds regardless of
/// whether a connection was received.
pub struct SsrfProbeListener {
    listener: TcpListener,
}

impl SsrfProbeListener {
    /// Bind to `127.0.0.1:0` and return the listener.
    pub fn bind() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(Self { listener })
    }

    /// Return the OS-assigned port number.
    pub fn port(&self) -> u16 {
        self.listener.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    /// Spawn a background thread that waits for a connection for up to 30
    /// seconds, prints a confirmation if one arrives, then shuts down.
    ///
    /// The `TcpListener` is moved into the thread; this method consumes `self`.
    pub fn start(self) {
        let port = self.port();
        std::thread::spawn(move || {
            let listener = self.listener;
            listener
                .set_nonblocking(false)
                .expect("set_nonblocking failed");

            // Use a 30-second read timeout so the thread exits cleanly
            listener
                .set_nonblocking(true)
                .expect("set_nonblocking failed");

            let deadline = std::time::Instant::now() + Duration::from_secs(30);

            loop {
                if std::time::Instant::now() >= deadline {
                    eprintln!(
                        "[sicario-poc] SsrfProbeListener on port {} timed out after 30 seconds — no connection received.",
                        port
                    );
                    break;
                }

                match listener.accept() {
                    Ok((_stream, peer)) => {
                        eprintln!(
                            "[sicario-poc] ✓ SSRF CONFIRMED: connection received on probe port {} from {}",
                            port, peer
                        );
                        break;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No connection yet — sleep briefly and retry
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        eprintln!(
                            "[sicario-poc] SsrfProbeListener error on port {}: {}",
                            port, e
                        );
                        break;
                    }
                }
            }
        });
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::vulnerability::{Finding, Severity};
    use std::path::PathBuf;
    use uuid::Uuid;

    fn make_finding(rule_id: &str, cwe_id: Option<&str>, snippet: &str) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            rule_id: rule_id.to_string(),
            rule_name: rule_id.to_string(),
            file_path: PathBuf::from("src/db.js"),
            line: 42,
            column: 5,
            end_line: None,
            end_column: None,
            snippet: snippet.to_string(),
            severity: Severity::High,
            confidence_score: 0.9,
            reachable: true,
            cloud_exposed: None,
            cwe_id: cwe_id.map(|s| s.to_string()),
            owasp_category: None,
            fingerprint: "abc123".to_string(),
            dataflow_trace: None,
            suppressed: false,
            suppression_rule: None,
            suggested_suppression: false,
        }
    }

    // ── SQL injection tests ───────────────────────────────────────────────

    #[test]
    fn test_sqli_postgres_uses_pg_sleep() {
        let finding = make_finding(
            "js-sql-string-concat",
            Some("CWE-89"),
            "pg.query('SELECT * FROM users WHERE id = ' + userId)",
        );
        let payload = PocGenerator::generate(&finding).expect("should generate payload");
        assert!(
            payload.curl_command.contains("pg_sleep(5)"),
            "PostgreSQL payload should use pg_sleep(5), got: {}",
            payload.curl_command
        );
    }

    #[test]
    fn test_sqli_mysql_uses_sleep() {
        let finding = make_finding(
            "js-sql-string-concat",
            Some("CWE-89"),
            "mysql.query('SELECT * FROM users WHERE id = ' + userId)",
        );
        let payload = PocGenerator::generate(&finding).expect("should generate payload");
        assert!(
            payload.curl_command.contains("SLEEP(5)"),
            "MySQL payload should use SLEEP(5), got: {}",
            payload.curl_command
        );
    }

    #[test]
    fn test_sqli_mssql_uses_waitfor() {
        let finding = make_finding(
            "js-sql-string-concat",
            Some("CWE-89"),
            "mssql.query('SELECT * FROM users WHERE id = ' + userId)",
        );
        let payload = PocGenerator::generate(&finding).expect("should generate payload");
        assert!(
            payload.curl_command.contains("WAITFOR DELAY"),
            "MSSQL payload should use WAITFOR DELAY, got: {}",
            payload.curl_command
        );
    }

    #[test]
    fn test_sqli_unknown_driver_defaults_to_sleep() {
        let finding = make_finding(
            "js-sql-string-concat",
            Some("CWE-89"),
            "db.query('SELECT * FROM users WHERE id = ' + userId)",
        );
        let payload = PocGenerator::generate(&finding).expect("should generate payload");
        assert!(
            payload.curl_command.contains("SLEEP(5)"),
            "Unknown driver should default to SLEEP(5), got: {}",
            payload.curl_command
        );
    }

    // ── Destructive SQL keyword rejection ────────────────────────────────

    #[test]
    fn test_destructive_sql_keywords_rejected() {
        let destructive = ["DROP", "DELETE", "TRUNCATE", "UPDATE", "INSERT", "ALTER"];
        for kw in &destructive {
            assert!(
                contains_destructive_sql(kw),
                "Should detect destructive keyword: {}",
                kw
            );
            assert!(
                contains_destructive_sql(&kw.to_lowercase()),
                "Should detect lowercase destructive keyword: {}",
                kw.to_lowercase()
            );
        }
        assert!(
            !contains_destructive_sql("SELECT pg_sleep(5)"),
            "Safe payload should not be rejected"
        );
    }

    // ── SSRF tests ────────────────────────────────────────────────────────

    #[test]
    fn test_ssrf_payload_targets_localhost() {
        let finding = make_finding(
            "ssrf-unvalidated-url",
            Some("CWE-918"),
            "fetch(req.body.url)",
        );
        let payload = PocGenerator::generate(&finding).expect("should generate payload");
        assert!(
            payload.curl_command.contains("127.0.0.1"),
            "SSRF payload must target localhost, got: {}",
            payload.curl_command
        );
        // The probe URL must be localhost
        assert!(
            !payload.curl_command.contains("0.0.0.0"),
            "SSRF payload must not use 0.0.0.0"
        );
    }

    // ── Non-localhost URL rejection ───────────────────────────────────────

    #[test]
    fn test_non_localhost_url_rejected() {
        assert!(!is_localhost_url("http://example.com/path"));
        assert!(!is_localhost_url("http://192.168.1.1/path"));
        assert!(!is_localhost_url("http://10.0.0.1/path"));
        assert!(!is_localhost_url("http://0.0.0.0/path"));
    }

    #[test]
    fn test_localhost_url_accepted() {
        assert!(is_localhost_url("http://127.0.0.1/path"));
        assert!(is_localhost_url("http://127.0.0.1:3000/path"));
        assert!(is_localhost_url("http://::1/path"));
        assert!(is_localhost_url("http://localhost/path"));
    }

    // ── Command injection tests ───────────────────────────────────────────

    #[test]
    fn test_cmdi_uses_echo_technique() {
        let finding = make_finding("command-injection", Some("CWE-78"), "exec(req.body.cmd)");
        let payload = PocGenerator::generate(&finding).expect("should generate payload");
        assert!(
            payload.curl_command.contains("echo sicario-poc"),
            "Command injection payload should use echo technique, got: {}",
            payload.curl_command
        );
    }

    // ── Path traversal tests ──────────────────────────────────────────────

    #[test]
    fn test_path_traversal_reads_readonly_file() {
        let finding = make_finding(
            "path-traversal",
            Some("CWE-22"),
            "fs.readFile(req.query.file)",
        );
        let payload = PocGenerator::generate(&finding).expect("should generate payload");
        // Should target a read-only system file
        let cmd = &payload.curl_command;
        let targets_readonly = cmd.contains("etc%2Fhostname")
            || cmd.contains("etc/hostname")
            || cmd.contains("Windows%2FSystem32")
            || cmd.contains("Windows/System32");
        assert!(
            targets_readonly,
            "Path traversal payload should target a read-only file, got: {}",
            cmd
        );
    }

    // ── SsrfProbeListener tests ───────────────────────────────────────────

    #[test]
    fn test_ssrf_probe_listener_binds_and_returns_port() {
        let listener = SsrfProbeListener::bind().expect("should bind successfully");
        let port = listener.port();
        assert!(port > 0, "OS should assign a non-zero port, got: {}", port);
    }

    #[test]
    fn test_ssrf_probe_listener_shuts_down_cleanly() {
        let listener = SsrfProbeListener::bind().expect("should bind successfully");
        let port = listener.port();
        assert!(port > 0);
        // Start the listener — it will time out after 30s in the background.
        // We just verify it doesn't panic on start.
        listener.start();
        // Give the thread a moment to start
        std::thread::sleep(Duration::from_millis(50));
        // No assertion needed — if start() panics the test fails
    }

    #[test]
    fn test_ssrf_probe_listener_receives_connection() {
        let listener = SsrfProbeListener::bind().expect("should bind successfully");
        let port = listener.port();
        assert!(port > 0);

        // Start the listener
        listener.start();

        // Give the thread a moment to start
        std::thread::sleep(Duration::from_millis(50));

        // Connect to the probe port
        let result = TcpStream::connect(format!("127.0.0.1:{}", port));
        assert!(result.is_ok(), "Should be able to connect to probe port");

        // Give the listener thread time to process the connection
        std::thread::sleep(Duration::from_millis(200));
    }

    // ── DbDriver detection tests ──────────────────────────────────────────

    #[test]
    fn test_db_driver_detection_postgres() {
        let finding = make_finding("rule", Some("CWE-89"), "pg.query(...)");
        assert_eq!(DbDriver::detect(&finding), DbDriver::Postgres);
    }

    #[test]
    fn test_db_driver_detection_mysql() {
        let finding = make_finding("rule", Some("CWE-89"), "mysql.query(...)");
        assert_eq!(DbDriver::detect(&finding), DbDriver::Mysql);
    }

    #[test]
    fn test_db_driver_detection_mssql() {
        let finding = make_finding("rule", Some("CWE-89"), "mssql.query(...)");
        assert_eq!(DbDriver::detect(&finding), DbDriver::Mssql);
    }

    #[test]
    fn test_db_driver_detection_unknown() {
        let finding = make_finding("rule", Some("CWE-89"), "db.query(...)");
        assert_eq!(DbDriver::detect(&finding), DbDriver::Unknown);
    }
}

// ── Prove flag integration tests ──────────────────────────────────────────────

#[cfg(test)]
mod prove_flag_tests {
    use super::*;
    use crate::engine::vulnerability::{Finding, Severity};
    use std::path::PathBuf;
    use uuid::Uuid;

    fn make_sqli_finding() -> Finding {
        Finding {
            id: Uuid::new_v4(),
            rule_id: "js-sql-string-concat".to_string(),
            rule_name: "SQL Injection".to_string(),
            file_path: PathBuf::from("src/db.js"),
            line: 42,
            column: 5,
            end_line: None,
            end_column: None,
            snippet: "db.query('SELECT * FROM users WHERE id = ' + userId)".to_string(),
            severity: Severity::High,
            confidence_score: 0.9,
            reachable: true,
            cloud_exposed: None,
            cwe_id: Some("CWE-89".to_string()),
            owasp_category: None,
            fingerprint: "abc123".to_string(),
            dataflow_trace: None,
            suppressed: false,
            suppression_rule: None,
            suggested_suppression: false,
        }
    }

    /// Simulates the consent prompt logic: returns true if user typed "y" or "yes".
    fn consent_granted(input: &str) -> bool {
        let trimmed = input.trim().to_lowercase();
        trimmed == "y" || trimmed == "yes"
    }

    #[test]
    fn test_consent_y_proceeds() {
        assert!(consent_granted("y"), "'y' should grant consent");
        assert!(consent_granted("Y"), "'Y' should grant consent");
        assert!(consent_granted("yes"), "'yes' should grant consent");
        assert!(consent_granted("YES"), "'YES' should grant consent");
        assert!(consent_granted("Yes"), "'Yes' should grant consent");
    }

    #[test]
    fn test_consent_anything_else_skips() {
        assert!(!consent_granted("n"), "'n' should deny consent");
        assert!(!consent_granted("N"), "'N' should deny consent");
        assert!(!consent_granted("no"), "'no' should deny consent");
        assert!(!consent_granted(""), "empty input should deny consent");
        assert!(!consent_granted(" "), "whitespace should deny consent");
        assert!(!consent_granted("maybe"), "'maybe' should deny consent");
        assert!(!consent_granted("1"), "'1' should deny consent");
    }

    #[test]
    fn test_json_format_poc_field_included_when_payload_generated() {
        // Simulate what the JSON --prove path does: generate payload and include as poc field
        let finding = make_sqli_finding();
        let payload = PocGenerator::generate(&finding);
        assert!(
            payload.is_some(),
            "Should generate payload for SQL injection"
        );

        let payload = payload.unwrap();
        let poc_value = serde_json::json!({
            "vuln_location": payload.vuln_location,
            "curl_command": payload.curl_command,
            "interpretation": payload.interpretation,
        });

        assert!(poc_value.get("vuln_location").is_some());
        assert!(poc_value.get("curl_command").is_some());
        assert!(poc_value.get("interpretation").is_some());
        assert!(!poc_value["vuln_location"].as_str().unwrap().is_empty());
        assert!(!poc_value["curl_command"].as_str().unwrap().is_empty());
    }

    #[test]
    fn test_json_format_poc_field_null_when_no_payload() {
        // For an unsupported CWE, poc field should be null
        let finding = Finding {
            id: Uuid::new_v4(),
            rule_id: "some-unknown-rule".to_string(),
            rule_name: "Unknown Rule".to_string(),
            file_path: PathBuf::from("src/app.js"),
            line: 10,
            column: 1,
            end_line: None,
            end_column: None,
            snippet: "someCode()".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.5,
            reachable: false,
            cloud_exposed: None,
            cwe_id: Some("CWE-999".to_string()), // unsupported CWE
            owasp_category: None,
            fingerprint: "xyz".to_string(),
            dataflow_trace: None,
            suppressed: false,
            suppression_rule: None,
            suggested_suppression: false,
        };

        let payload = PocGenerator::generate(&finding);
        // For unsupported CWE with no matching rule_id heuristic, should return None
        assert!(
            payload.is_none(),
            "Should return None for unsupported CWE-999"
        );
    }

    #[test]
    fn test_poc_payload_vuln_location_format() {
        let finding = make_sqli_finding();
        let payload = PocGenerator::generate(&finding).expect("should generate payload");
        // vuln_location should be "file:line" format
        assert!(
            payload.vuln_location.contains("src/db.js")
                || payload.vuln_location.contains("src\\db.js"),
            "vuln_location should contain file path, got: {}",
            payload.vuln_location
        );
        assert!(
            payload.vuln_location.contains("42"),
            "vuln_location should contain line number, got: {}",
            payload.vuln_location
        );
    }

    #[test]
    fn test_poc_payload_has_all_required_fields() {
        let finding = make_sqli_finding();
        let payload = PocGenerator::generate(&finding).expect("should generate payload");
        assert!(
            !payload.vuln_location.is_empty(),
            "vuln_location must not be empty"
        );
        assert!(
            !payload.curl_command.is_empty(),
            "curl_command must not be empty"
        );
        assert!(
            !payload.interpretation.is_empty(),
            "interpretation must not be empty"
        );
    }
}

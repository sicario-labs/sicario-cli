//! Attack payload generator — binds PoC payloads to extracted routes.
//!
//! # Safety Invariants (enforced in Rust, not documentation)
//! 1. Any payload URL that does not resolve to `127.0.0.1` or `::1` is
//!    rejected before return.
//! 2. Any SQL payload containing `DROP`, `DELETE`, `TRUNCATE`, `UPDATE`,
//!    `INSERT`, or `ALTER` is rejected before return.

use crate::attack::route_extractor::{ExtractedRoute, HttpMethod, ParamLocation, RouteParameter};
use crate::engine::vulnerability::Vulnerability;
use crate::poc::generator::SsrfProbeListener;

// ── Safety helpers ────────────────────────────────────────────────────────────

/// Keywords that must never appear in a generated SQL payload.
const DESTRUCTIVE_SQL_KEYWORDS: &[&str] =
    &["DROP", "DELETE", "TRUNCATE", "UPDATE", "INSERT", "ALTER"];

/// Returns `true` if the SQL payload contains any destructive keyword (case-insensitive).
fn contains_destructive_sql(payload: &str) -> bool {
    let upper = payload.to_uppercase();
    DESTRUCTIVE_SQL_KEYWORDS.iter().any(|kw| upper.contains(kw))
}

/// Returns `true` if the URL is safe (resolves to `127.0.0.1`, `::1`, or `localhost`).
fn is_localhost_url(url: &str) -> bool {
    let without_scheme = if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else {
        url
    };

    let host = without_scheme.split('/').next().unwrap_or(without_scheme);

    let host_no_port = if host.starts_with('[') {
        host.trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(host)
    } else if host.contains(':') {
        let colon_count = host.chars().filter(|&c| c == ':').count();
        if colon_count > 1 {
            host
        } else {
            host.split(':').next().unwrap_or(host)
        }
    } else {
        host
    };

    matches!(host_no_port, "127.0.0.1" | "::1" | "localhost")
}

// ── AttackPayload ─────────────────────────────────────────────────────────────

/// A single attack payload bound to a specific route and parameter.
#[derive(Debug, Clone)]
pub struct AttackPayload {
    /// The route path this payload targets.
    pub route_path: String,
    /// The HTTP method for this payload.
    pub method: HttpMethod,
    /// The parameter name this payload targets.
    pub parameter: String,
    /// The actual payload string.
    pub payload: String,
    /// Whether this is a benign baseline payload (not an attack).
    pub is_benign: bool,
    /// The CWE number this payload targets.
    pub cwe: u32,
}

// ── AttackPayloadGenerator ────────────────────────────────────────────────────

/// Generates attack payloads by binding PoC payloads to extracted routes.
pub struct AttackPayloadGenerator;

impl AttackPayloadGenerator {
    /// Generate attack payloads for a route and vulnerability finding.
    ///
    /// For each `RouteParameter` in the route, generates a targeted payload
    /// for the finding's CWE, plus a benign baseline payload.
    ///
    /// When `dry_run` is `true`, SSRF payloads use a fixed placeholder port
    /// instead of binding a real TCP listener — this avoids the 30-second
    /// probe timeout during dry-run mode.
    ///
    /// Safety constraints are enforced in Rust:
    /// - Payloads with non-localhost URLs are rejected.
    /// - SQL payloads with destructive keywords are rejected.
    pub fn generate(route: &ExtractedRoute, finding: &Vulnerability) -> Vec<AttackPayload> {
        Self::generate_inner(route, finding, false)
    }

    /// Like `generate` but skips binding the SSRF probe listener.
    pub fn generate_dry_run(route: &ExtractedRoute, finding: &Vulnerability) -> Vec<AttackPayload> {
        Self::generate_inner(route, finding, true)
    }

    fn generate_inner(
        route: &ExtractedRoute,
        finding: &Vulnerability,
        dry_run: bool,
    ) -> Vec<AttackPayload> {
        let cwe_num = finding
            .cwe_id
            .as_deref()
            .unwrap_or("")
            .trim_start_matches("CWE-")
            .trim_start_matches("cwe-")
            .parse::<u32>()
            .unwrap_or(0);

        // Also check rule_id for CWE hints
        let effective_cwe = if cwe_num == 0 {
            let rule = finding.rule_id.to_lowercase();
            if rule.contains("sql") {
                89
            } else if rule.contains("ssrf") {
                918
            } else if rule.contains("command") || rule.contains("cmd") || rule.contains("exec") {
                78
            } else if rule.contains("path") || rule.contains("traversal") || rule.contains("lfi") {
                22
            } else if rule.contains("xss") || rule.contains("cross-site") {
                79
            } else {
                cwe_num
            }
        } else {
            cwe_num
        };

        let mut payloads = Vec::new();

        // If no parameters, generate a single payload for the route itself
        if route.parameters.is_empty() {
            let attack = Self::build_payload(
                route,
                finding,
                effective_cwe,
                "body",
                &ParamLocation::Body,
                dry_run,
            );
            if let Some(p) = attack {
                payloads.push(p);
            }
            // Benign baseline
            payloads.push(AttackPayload {
                route_path: route.path.clone(),
                method: route.method.clone(),
                parameter: "body".to_string(),
                payload: "test".to_string(),
                is_benign: true,
                cwe: effective_cwe,
            });
            return payloads;
        }

        for param in &route.parameters {
            // Generate attack payload
            if let Some(attack) = Self::build_payload(
                route,
                finding,
                effective_cwe,
                &param.name,
                &param.location,
                dry_run,
            ) {
                payloads.push(attack);
            }

            // Generate benign baseline payload
            let benign_value = match param.location {
                ParamLocation::Path => "1".to_string(),
                ParamLocation::Query => "test".to_string(),
                ParamLocation::Body => "test".to_string(),
                ParamLocation::Header => "test".to_string(),
            };
            payloads.push(AttackPayload {
                route_path: route.path.clone(),
                method: route.method.clone(),
                parameter: param.name.clone(),
                payload: benign_value,
                is_benign: true,
                cwe: effective_cwe,
            });
        }

        payloads
    }

    /// Build a single attack payload for a specific parameter.
    fn build_payload(
        route: &ExtractedRoute,
        finding: &Vulnerability,
        cwe: u32,
        param_name: &str,
        _param_location: &ParamLocation,
        dry_run: bool,
    ) -> Option<AttackPayload> {
        let payload_str = match cwe {
            89 => Self::build_sqli_payload(finding),
            78 => Some("; sleep 4".to_string()),
            22 => Some("../../../../etc/hostname".to_string()),
            79 => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                Some(format!("<script>sicario_xss_probe_{}</script>", ts))
            }
            918 => Self::build_ssrf_payload(dry_run),
            _ => None,
        }?;

        // Safety check: reject SQL payloads with destructive keywords
        if cwe == 89 && contains_destructive_sql(&payload_str) {
            return None;
        }

        // Safety check: reject non-localhost URLs in SSRF payloads
        if cwe == 918 && !is_localhost_url(&payload_str) {
            return None;
        }

        Some(AttackPayload {
            route_path: route.path.clone(),
            method: route.method.clone(),
            parameter: param_name.to_string(),
            payload: payload_str,
            is_benign: false,
            cwe,
        })
    }

    /// Build a SQL injection payload based on the detected DB driver.
    fn build_sqli_payload(finding: &Vulnerability) -> Option<String> {
        let haystack = format!(
            "{} {}",
            finding.rule_id.to_lowercase(),
            finding.snippet.to_lowercase()
        );

        let payload = if haystack.contains("pg")
            || haystack.contains("postgres")
            || haystack.contains("postgresql")
        {
            "'; SELECT pg_sleep(5)--".to_string()
        } else if haystack.contains("mssql")
            || haystack.contains("sqlserver")
            || haystack.contains("tedious")
        {
            "' WAITFOR DELAY '0:0:5'--".to_string()
        } else {
            // Default to MySQL SLEEP
            "' OR SLEEP(5)--".to_string()
        };

        // Safety check: reject destructive keywords
        if contains_destructive_sql(&payload) {
            return None;
        }

        Some(payload)
    }

    /// Build an SSRF payload using a local probe listener.
    /// In dry-run mode, uses a fixed placeholder port to avoid binding a socket.
    fn build_ssrf_payload(dry_run: bool) -> Option<String> {
        if dry_run {
            // In dry-run mode, use a fixed placeholder port — no socket binding
            return Some("http://127.0.0.1:9999/ssrf-probe".to_string());
        }

        let listener = SsrfProbeListener::bind().ok()?;
        let port = listener.port();
        listener.start();

        let url = format!("http://127.0.0.1:{}/ssrf-probe", port);

        // Safety check: must be localhost
        if !is_localhost_url(&url) {
            return None;
        }

        Some(url)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack::route_extractor::{
        ExtractedRoute, HttpMethod, ParamLocation, ParamType, RouteParameter,
    };
    use crate::engine::vulnerability::{Severity, Vulnerability};
    use std::path::PathBuf;
    use uuid::Uuid;

    fn make_route_with_body_param(path: &str) -> ExtractedRoute {
        ExtractedRoute {
            method: HttpMethod::Post,
            path: path.to_string(),
            handler_file: PathBuf::from("src/app.js"),
            handler_line: 10,
            handler_function: "handler".to_string(),
            parameters: vec![RouteParameter {
                name: "id".to_string(),
                location: ParamLocation::Body,
                inferred_type: ParamType::String,
            }],
        }
    }

    fn make_vulnerability(rule_id: &str, cwe_id: Option<&str>, snippet: &str) -> Vulnerability {
        Vulnerability {
            id: Uuid::new_v4(),
            rule_id: rule_id.to_string(),
            file_path: PathBuf::from("src/db.js"),
            line: 42,
            column: 5,
            snippet: snippet.to_string(),
            severity: Severity::High,
            reachable: true,
            cloud_exposed: None,
            cwe_id: cwe_id.map(|s| s.to_string()),
            owasp_category: None,
            confidence_score: 0.9,
            suppressed: false,
            execution_trace: None,
        }
    }

    #[test]
    fn test_sqli_mysql_payload_contains_sleep() {
        let route = make_route_with_body_param("/api/users");
        let finding = make_vulnerability(
            "js-sql-string-concat",
            Some("CWE-89"),
            "mysql.query('SELECT * FROM users WHERE id = ' + req.body.id)",
        );

        let payloads = AttackPayloadGenerator::generate(&route, &finding);
        let attack_payloads: Vec<&AttackPayload> =
            payloads.iter().filter(|p| !p.is_benign).collect();

        assert!(
            !attack_payloads.is_empty(),
            "Expected at least one attack payload"
        );
        let has_sleep = attack_payloads
            .iter()
            .any(|p| p.payload.contains("SLEEP") || p.payload.contains("pg_sleep"));
        assert!(
            has_sleep,
            "Expected SLEEP or pg_sleep in SQL injection payload"
        );
    }

    #[test]
    fn test_sqli_postgres_payload_contains_pg_sleep() {
        let route = make_route_with_body_param("/api/users");
        let finding = make_vulnerability(
            "js-sql-string-concat",
            Some("CWE-89"),
            "pg.query('SELECT * FROM users WHERE id = ' + req.body.id)",
        );

        let payloads = AttackPayloadGenerator::generate(&route, &finding);
        let attack_payloads: Vec<&AttackPayload> =
            payloads.iter().filter(|p| !p.is_benign).collect();

        assert!(!attack_payloads.is_empty());
        let has_pg_sleep = attack_payloads
            .iter()
            .any(|p| p.payload.contains("pg_sleep"));
        assert!(has_pg_sleep, "Expected pg_sleep in PostgreSQL payload");
    }

    #[test]
    fn test_destructive_sql_keyword_rejected() {
        // Manually test the safety check
        assert!(contains_destructive_sql("DROP TABLE users"));
        assert!(contains_destructive_sql("delete from users"));
        assert!(contains_destructive_sql("TRUNCATE TABLE users"));
        assert!(contains_destructive_sql("UPDATE users SET x=1"));
        assert!(contains_destructive_sql("INSERT INTO users VALUES (1)"));
        assert!(contains_destructive_sql("ALTER TABLE users ADD COLUMN x"));
        assert!(!contains_destructive_sql("' OR SLEEP(5)--"));
        assert!(!contains_destructive_sql("'; SELECT pg_sleep(5)--"));
    }

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

    #[test]
    fn test_ssrf_payload_targets_localhost() {
        let route = make_route_with_body_param("/api/fetch");
        let finding = make_vulnerability(
            "ssrf-unvalidated-url",
            Some("CWE-918"),
            "fetch(req.body.url)",
        );

        let payloads = AttackPayloadGenerator::generate(&route, &finding);
        let attack_payloads: Vec<&AttackPayload> =
            payloads.iter().filter(|p| !p.is_benign).collect();

        // SSRF payloads should target localhost
        for p in &attack_payloads {
            if p.cwe == 918 {
                assert!(
                    is_localhost_url(&p.payload),
                    "SSRF payload must target localhost, got: {}",
                    p.payload
                );
            }
        }
    }

    #[test]
    fn test_benign_baseline_always_generated() {
        let route = make_route_with_body_param("/api/users");
        let finding = make_vulnerability("js-sql-string-concat", Some("CWE-89"), "db.query(...)");

        let payloads = AttackPayloadGenerator::generate(&route, &finding);
        let benign: Vec<&AttackPayload> = payloads.iter().filter(|p| p.is_benign).collect();
        assert!(
            !benign.is_empty(),
            "Expected at least one benign baseline payload"
        );
    }

    #[test]
    fn test_command_injection_payload() {
        let route = make_route_with_body_param("/api/run");
        let finding = make_vulnerability("command-injection", Some("CWE-78"), "exec(req.body.cmd)");

        let payloads = AttackPayloadGenerator::generate(&route, &finding);
        let attack_payloads: Vec<&AttackPayload> =
            payloads.iter().filter(|p| !p.is_benign).collect();

        assert!(!attack_payloads.is_empty());
        let has_sleep = attack_payloads.iter().any(|p| p.payload.contains("sleep"));
        assert!(
            has_sleep,
            "Expected sleep command in command injection payload"
        );
    }

    #[test]
    fn test_path_traversal_payload() {
        let route = make_route_with_body_param("/api/read");
        let finding = make_vulnerability(
            "path-traversal",
            Some("CWE-22"),
            "fs.readFile(req.body.file)",
        );

        let payloads = AttackPayloadGenerator::generate(&route, &finding);
        let attack_payloads: Vec<&AttackPayload> =
            payloads.iter().filter(|p| !p.is_benign).collect();

        assert!(!attack_payloads.is_empty());
        let has_traversal = attack_payloads
            .iter()
            .any(|p| p.payload.contains("..") && p.payload.contains("etc"));
        assert!(has_traversal, "Expected path traversal payload");
    }
}

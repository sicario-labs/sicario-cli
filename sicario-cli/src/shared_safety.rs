//! Shared safety utilities for attack and PoC modules.
//!
//! These invariants are enforced in Rust — not documentation — so that any
//! code path that generates payloads or URLs is guaranteed safe at compile
//! time (modulo logic bugs in the checker functions themselves).

/// Keywords that must never appear in a generated SQL payload.
pub const DESTRUCTIVE_SQL_KEYWORDS: &[&str] =
    &["DROP", "DELETE", "TRUNCATE", "UPDATE", "INSERT", "ALTER"];

/// Returns `true` if the SQL payload contains any destructive keyword
/// (case-insensitive).
pub fn contains_destructive_sql(payload: &str) -> bool {
    let upper = payload.to_uppercase();
    DESTRUCTIVE_SQL_KEYWORDS.iter().any(|kw| upper.contains(kw))
}

/// Returns `true` if the URL is safe (resolves to `127.0.0.1`, `::1`, or `localhost`).
///
/// We check the host portion of the URL string directly — no DNS resolution
/// is performed so there is no TOCTOU window.
pub fn is_localhost_url(url: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_destructive_sql_keywords() {
        for kw in DESTRUCTIVE_SQL_KEYWORDS {
            assert!(contains_destructive_sql(kw));
            assert!(contains_destructive_sql(&kw.to_lowercase()));
        }
        assert!(!contains_destructive_sql("SELECT pg_sleep(5)"));
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
}

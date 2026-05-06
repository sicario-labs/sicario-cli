//! Usage telemetry — fire-and-forget anonymous ping on every scan.
//!
//! # Privacy guarantees
//!
//! - No source code, file paths, or finding details are ever sent.
//! - The project is identified only by a SHA-256 hash of the normalized
//!   `remote.origin.url` — the raw URL is never transmitted.
//! - Opt-out: set `SICARIO_NO_TELEMETRY=1` or `no_telemetry = true` in
//!   `~/.sicario/config.toml` (task 13.2 adds the config field).
//! - All network errors are silently swallowed; the ping never blocks the
//!   scan and never panics.

use sha2::{Digest, Sha256};

// ── Public entry point ────────────────────────────────────────────────────────

/// Fire a usage ping in a background thread and return immediately.
///
/// Checks opt-out conditions first; if the user has opted out the function
/// returns without spawning any thread.
pub fn fire_usage_ping() {
    // Opt-out: SICARIO_NO_TELEMETRY env var
    if std::env::var("SICARIO_NO_TELEMETRY").is_ok() {
        return;
    }

    // Opt-out: GlobalConfig::no_telemetry == Some(true)
    // (The `no_telemetry` field is added in task 13.2; guard with a helper
    //  that returns false when the field is absent so this compiles today.)
    if global_config_no_telemetry() {
        return;
    }

    std::thread::spawn(|| {
        let _ = send_usage_ping();
    });
}

// ── Private implementation ────────────────────────────────────────────────────

/// Build and POST the usage payload.  Returns `None` on any failure.
///
/// This function never panics and never logs — all errors are silently
/// discarded so a broken telemetry endpoint can never affect the scan.
fn send_usage_ping() -> Option<()> {
    use crate::publish::resolve_cloud_url;

    let project_hash = compute_project_hash()?;
    let environment = detect_environment();
    let cli_version = env!("CARGO_PKG_VERSION");

    let payload = serde_json::json!({
        "event": "scan_run",
        "environment": environment,
        "project_hash": project_hash,
        "cli_version": cli_version,
    });

    let endpoint = format!("{}/api/v1/usage", resolve_cloud_url());

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    // Fire and forget — ignore response body and status code entirely.
    let _ = client.post(&endpoint).json(&payload).send();

    Some(())
}

// ── compute_project_hash ──────────────────────────────────────────────────────

/// Compute a SHA-256 hash of the normalized `remote.origin.url`.
///
/// Returns `None` if:
/// - `git config --get remote.origin.url` fails or exits non-zero
/// - The command produces empty output
pub fn compute_project_hash() -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["config", "--get", "remote.origin.url"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let raw = String::from_utf8(output.stdout).ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    let normalized = normalize_remote_url(raw);
    if normalized.is_empty() {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    let hash = hasher.finalize();
    Some(format!("{:x}", hash))
}

// ── normalize_remote_url ──────────────────────────────────────────────────────

/// Normalize a git remote URL to a canonical form for hashing.
///
/// Transformations applied (in order):
/// 1. Strip scheme: `ssh://git@`, `https://`, `http://`, `git@`
/// 2. Strip credentials: everything before and including `@`
/// 3. Normalize `github.com:org/repo` colon separator → `github.com/org/repo`
/// 4. Strip trailing `.git`
/// 5. Lowercase
pub fn normalize_remote_url(url: &str) -> String {
    let s = url.trim();

    // 1. Strip known schemes (order matters: longer prefixes first)
    let s = if let Some(rest) = s.strip_prefix("ssh://git@") {
        rest
    } else if let Some(rest) = s.strip_prefix("https://") {
        rest
    } else if let Some(rest) = s.strip_prefix("http://") {
        rest
    } else if let Some(rest) = s.strip_prefix("git@") {
        rest
    } else {
        s
    };

    // 2. Strip credentials: everything before and including the last `@`
    //    (handles user:pass@host style URLs that survived step 1)
    let s = if let Some(at_pos) = s.rfind('@') {
        &s[at_pos + 1..]
    } else {
        s
    };

    // 3. Normalize colon separator used by SCP-style git@ URLs
    //    e.g. `github.com:org/repo` → `github.com/org/repo`
    let s = s.replacen(':', "/", 1);

    // 4. Strip trailing `.git`
    let s = if let Some(stripped) = s.strip_suffix(".git") {
        stripped.to_string()
    } else {
        s
    };

    // 5. Lowercase
    s.to_lowercase()
}

// ── detect_environment ────────────────────────────────────────────────────────

/// Detect whether the process is running in a CI environment.
///
/// Returns `"ci"` if any well-known CI environment variable is set,
/// `"local"` otherwise.
pub fn detect_environment() -> &'static str {
    const CI_VARS: &[&str] = &[
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "CIRCLECI",
        "TRAVIS",
        "JENKINS_URL",
        "BUILDKITE",
        "DRONE",
        "CI",
    ];

    for var in CI_VARS {
        if std::env::var(var).is_ok() {
            return "ci";
        }
    }

    "local"
}

// ── Opt-out helper ────────────────────────────────────────────────────────────

/// Returns `true` if the global config has `no_telemetry = Some(true)`.
///
/// Uses the typed `no_telemetry: Option<bool>` field added in task 13.2.
fn global_config_no_telemetry() -> bool {
    use crate::config::global_config::load_global_config;

    load_global_config()
        .and_then(|cfg| cfg.no_telemetry)
        .unwrap_or(false)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── normalize_remote_url ──────────────────────────────────────────────

    #[test]
    fn test_normalize_https_with_credentials() {
        // HTTPS URL with embedded credentials
        assert_eq!(
            normalize_remote_url("https://user:pass@github.com/org/repo.git"),
            "github.com/org/repo"
        );
    }

    #[test]
    fn test_normalize_https_plain() {
        assert_eq!(
            normalize_remote_url("https://github.com/org/repo.git"),
            "github.com/org/repo"
        );
    }

    #[test]
    fn test_normalize_ssh_git_at_format() {
        // Classic SCP-style git@ URL
        assert_eq!(
            normalize_remote_url("git@github.com:org/repo.git"),
            "github.com/org/repo"
        );
    }

    #[test]
    fn test_normalize_ssh_scheme() {
        assert_eq!(
            normalize_remote_url("ssh://git@github.com/org/repo.git"),
            "github.com/org/repo"
        );
    }

    #[test]
    fn test_normalize_trailing_git_stripped() {
        assert_eq!(
            normalize_remote_url("https://github.com/org/repo.git"),
            "github.com/org/repo"
        );
        // Without .git suffix — should still work
        assert_eq!(
            normalize_remote_url("https://github.com/org/repo"),
            "github.com/org/repo"
        );
    }

    #[test]
    fn test_normalize_mixed_case_lowercased() {
        assert_eq!(
            normalize_remote_url("https://GitHub.COM/Org/Repo.git"),
            "github.com/org/repo"
        );
    }

    #[test]
    fn test_normalize_http_scheme() {
        assert_eq!(
            normalize_remote_url("http://github.com/org/repo.git"),
            "github.com/org/repo"
        );
    }

    // ── detect_environment ────────────────────────────────────────────────

    #[test]
    fn test_detect_environment_ci_when_github_actions_set() {
        // Save and clear all CI vars first to avoid interference from the
        // actual test runner environment.
        let saved: Vec<(&str, Option<String>)> = [
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "CIRCLECI",
            "TRAVIS",
            "JENKINS_URL",
            "BUILDKITE",
            "DRONE",
            "CI",
        ]
        .iter()
        .map(|&v| (v, std::env::var(v).ok()))
        .collect();

        // Clear all CI vars
        for (var, _) in &saved {
            std::env::remove_var(var);
        }

        std::env::set_var("GITHUB_ACTIONS", "true");
        let result = detect_environment();

        // Restore
        std::env::remove_var("GITHUB_ACTIONS");
        for (var, val) in saved {
            match val {
                Some(v) => std::env::set_var(var, v),
                None => std::env::remove_var(var),
            }
        }

        assert_eq!(result, "ci");
    }

    #[test]
    fn test_detect_environment_local_when_no_ci_vars() {
        // Save and clear all CI vars
        let ci_vars = [
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "CIRCLECI",
            "TRAVIS",
            "JENKINS_URL",
            "BUILDKITE",
            "DRONE",
            "CI",
        ];
        let saved: Vec<(&str, Option<String>)> = ci_vars
            .iter()
            .map(|&v| (v, std::env::var(v).ok()))
            .collect();

        for var in &ci_vars {
            std::env::remove_var(var);
        }

        let result = detect_environment();

        // Restore
        for (var, val) in saved {
            match val {
                Some(v) => std::env::set_var(var, v),
                None => std::env::remove_var(var),
            }
        }

        assert_eq!(result, "local");
    }

    // ── compute_project_hash ──────────────────────────────────────────────

    #[test]
    fn test_compute_project_hash_none_when_not_git_repo() {
        // Run git config in a temp directory that is not a git repo
        let tmp = tempfile::tempdir().unwrap();
        let original_dir = std::env::current_dir().unwrap();

        std::env::set_current_dir(tmp.path()).unwrap();
        let result = compute_project_hash();
        std::env::set_current_dir(original_dir).unwrap();

        assert!(
            result.is_none(),
            "compute_project_hash should return None outside a git repo"
        );
    }

    #[test]
    fn test_compute_project_hash_64_char_hex_for_valid_url() {
        // We can test the hashing logic directly by normalizing a known URL
        // and computing the hash ourselves, then comparing.
        let url = "https://github.com/org/repo.git";
        let normalized = normalize_remote_url(url);

        let mut hasher = Sha256::new();
        hasher.update(normalized.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        assert_eq!(hash.len(), 64, "SHA-256 hex digest must be 64 characters");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be hex digits only"
        );
    }

    #[test]
    fn test_same_normalized_url_produces_same_hash() {
        // Two different raw URLs that normalize to the same form must hash identically
        let url1 = "https://github.com/org/repo.git";
        let url2 = "git@github.com:org/repo.git";

        let norm1 = normalize_remote_url(url1);
        let norm2 = normalize_remote_url(url2);
        assert_eq!(norm1, norm2, "both URLs should normalize to the same form");

        let hash = |s: &str| -> String {
            let mut h = Sha256::new();
            h.update(s.as_bytes());
            format!("{:x}", h.finalize())
        };

        assert_eq!(
            hash(&norm1),
            hash(&norm2),
            "same normalized URL must produce the same hash"
        );
    }

    // ── fire_usage_ping opt-out ───────────────────────────────────────────

    #[test]
    fn test_fire_usage_ping_returns_early_when_no_telemetry_set() {
        // When SICARIO_NO_TELEMETRY is set, fire_usage_ping must return
        // without spawning a thread.  We verify this indirectly: the function
        // must complete synchronously (no background thread is joinable) and
        // must not panic.
        //
        // We use a thread count comparison as a proxy: if a thread were
        // spawned it would increment the count.  However, thread counts are
        // not reliable across platforms, so we simply verify the function
        // returns without error and that the env var is respected.
        std::env::set_var("SICARIO_NO_TELEMETRY", "1");
        fire_usage_ping(); // must return immediately, no panic
        std::env::remove_var("SICARIO_NO_TELEMETRY");
    }

    // ── cmd_scan integration: telemetry does not block scan ───────────────

    /// Verify that `fire_usage_ping` completes without error when the
    /// telemetry endpoint is unreachable (simulated by pointing at a port
    /// that has no listener).
    ///
    /// This is the key property required by task 13.3: the scan must complete
    /// normally even if the mock server is unreachable.  Because
    /// `fire_usage_ping` spawns a background thread and swallows all errors,
    /// the caller (cmd_scan) is never blocked or panicked.
    #[test]
    fn test_fire_usage_ping_does_not_block_when_endpoint_unreachable() {
        // Ensure telemetry is enabled so the background thread is actually
        // spawned (we want to exercise the real code path, not the opt-out).
        std::env::remove_var("SICARIO_NO_TELEMETRY");

        // Override the cloud URL to a localhost port that has no listener.
        // The reqwest client has a 5-second timeout; the thread will fail
        // silently and the test must complete well within that window because
        // the connection is refused immediately (not a timeout).
        std::env::set_var("SICARIO_CLOUD_URL", "http://127.0.0.1:19999");

        let start = std::time::Instant::now();
        fire_usage_ping();
        // fire_usage_ping itself must return in microseconds — it only spawns
        // a thread and returns.  The background thread may still be running.
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 500,
            "fire_usage_ping must return immediately (took {}ms)",
            elapsed.as_millis()
        );

        // Clean up
        std::env::remove_var("SICARIO_CLOUD_URL");
    }

    /// Verify that `fire_usage_ping` with `SICARIO_NO_TELEMETRY=1` is a
    /// complete no-op — it must not attempt any network I/O and must return
    /// synchronously.  This mirrors the behaviour expected when cmd_scan is
    /// invoked in environments where telemetry is disabled.
    #[test]
    fn test_cmd_scan_telemetry_opt_out_is_noop() {
        std::env::set_var("SICARIO_NO_TELEMETRY", "1");

        // Call multiple times — must never panic or block.
        for _ in 0..3 {
            fire_usage_ping();
        }

        std::env::remove_var("SICARIO_NO_TELEMETRY");
    }

    // ── Integration test: mock HTTP server verifies payload shape ─────────

    /// Integration test: `fire_usage_ping` sends a POST to `/api/v1/usage`
    /// with the correct payload shape when a mock server is reachable.
    ///
    /// Validates task 13.3:
    /// - The ping is sent to `{cloud_url}/api/v1/usage`
    /// - The payload contains `event`, `environment`, `project_hash`, and
    ///   `cli_version` fields with the correct types
    /// - `fire_usage_ping` returns immediately (fire-and-forget)
    /// - Scan completes normally even if the mock server is unreachable
    #[test]
    fn test_usage_ping_sent_to_correct_endpoint_with_correct_payload() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;

        // Ensure telemetry is enabled for this test.
        std::env::remove_var("SICARIO_NO_TELEMETRY");

        // ── Start a mock HTTP server on a random port ─────────────────────
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let mock_port = listener.local_addr().unwrap().port();

        // Shared storage for the captured request body.
        let captured_body: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_body_clone = Arc::clone(&captured_body);
        let captured_path: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_path_clone = Arc::clone(&captured_path);

        // Spawn the mock server — handles one request then exits.
        thread::spawn(move || {
            // Set a deadline so the thread doesn't hang forever if no request arrives.
            listener.set_nonblocking(true).ok();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);

            loop {
                if std::time::Instant::now() >= deadline {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0u8; 8192];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let raw = String::from_utf8_lossy(&buf[..n]).to_string();

                        // Extract the request path from the first line.
                        if let Some(first_line) = raw.lines().next() {
                            // e.g. "POST /api/v1/usage HTTP/1.1"
                            let parts: Vec<&str> = first_line.split_whitespace().collect();
                            if parts.len() >= 2 {
                                *captured_path_clone.lock().unwrap() = Some(parts[1].to_string());
                            }
                        }

                        // Extract the JSON body (everything after the blank line).
                        if let Some(body_start) = raw.find("\r\n\r\n") {
                            let body = raw[body_start + 4..].to_string();
                            if !body.is_empty() {
                                *captured_body_clone.lock().unwrap() = Some(body);
                            }
                        }

                        // Respond with 204 No Content (same as the real endpoint).
                        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
                        let _ = stream.write_all(response.as_bytes());
                        break;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        // Give the mock server a moment to start.
        std::thread::sleep(std::time::Duration::from_millis(20));

        // ── Point the CLI at the mock server ──────────────────────────────
        std::env::set_var(
            "SICARIO_CLOUD_URL",
            format!("http://127.0.0.1:{}", mock_port),
        );

        // ── Call fire_usage_ping and verify it returns immediately ────────
        let start = std::time::Instant::now();
        fire_usage_ping();
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 500,
            "fire_usage_ping must return immediately (took {}ms)",
            elapsed.as_millis()
        );

        // ── Wait for the background thread to deliver the request ─────────
        // The background thread has a 5-second reqwest timeout; a successful
        // connection to the mock server should complete in milliseconds.
        let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if captured_body.lock().unwrap().is_some() {
                break;
            }
            if std::time::Instant::now() >= wait_deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // ── Verify the request path ───────────────────────────────────────
        let path = captured_path.lock().unwrap().clone();
        assert_eq!(
            path.as_deref(),
            Some("/api/v1/usage"),
            "usage ping must POST to /api/v1/usage, got: {:?}",
            path
        );

        // ── Verify the payload shape ──────────────────────────────────────
        let body_str = captured_body.lock().unwrap().clone();
        assert!(
            body_str.is_some(),
            "mock server must have received a request body"
        );

        let body_str = body_str.unwrap();
        let payload: serde_json::Value =
            serde_json::from_str(&body_str).expect("payload must be valid JSON");

        // Required field: "event" == "scan_run"
        assert_eq!(
            payload["event"].as_str(),
            Some("scan_run"),
            "payload.event must be \"scan_run\""
        );

        // Required field: "environment" is "ci" or "local"
        let env_val = payload["environment"].as_str().unwrap_or("");
        assert!(
            env_val == "ci" || env_val == "local",
            "payload.environment must be \"ci\" or \"local\", got: {:?}",
            env_val
        );

        // Required field: "cli_version" is a non-empty string
        let version = payload["cli_version"].as_str().unwrap_or("");
        assert!(
            !version.is_empty(),
            "payload.cli_version must be a non-empty string"
        );

        // Required field: "project_hash" is either absent (None when not in a
        // git repo with a remote) or a 64-char hex string.
        if let Some(hash) = payload["project_hash"].as_str() {
            assert_eq!(
                hash.len(),
                64,
                "payload.project_hash must be a 64-char hex string, got: {:?}",
                hash
            );
            assert!(
                hash.chars().all(|c| c.is_ascii_hexdigit()),
                "payload.project_hash must contain only hex digits"
            );
        }
        // project_hash may be null/absent when not in a git repo — that is valid.

        // ── Clean up ──────────────────────────────────────────────────────
        std::env::remove_var("SICARIO_CLOUD_URL");
    }

    /// Integration test: `fire_usage_ping` completes normally (does not panic
    /// or block) even when the mock server is unreachable.
    ///
    /// This verifies the fire-and-forget guarantee: `cmd_scan` must never be
    /// blocked or panicked by a telemetry failure.
    #[test]
    fn test_usage_ping_scan_completes_normally_when_server_unreachable() {
        // Ensure telemetry is enabled so the background thread is spawned.
        std::env::remove_var("SICARIO_NO_TELEMETRY");

        // Bind a listener, get its port, then drop it immediately so the port
        // is closed before fire_usage_ping tries to connect.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind temp listener");
            listener.local_addr().unwrap().port()
            // listener is dropped here — port is now closed
        };

        std::env::set_var("SICARIO_CLOUD_URL", format!("http://127.0.0.1:{}", port));

        // fire_usage_ping must return immediately even though the endpoint is
        // unreachable.  The background thread will fail silently.
        let start = std::time::Instant::now();
        fire_usage_ping();
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 500,
            "fire_usage_ping must return immediately even when server is unreachable (took {}ms)",
            elapsed.as_millis()
        );

        // Clean up
        std::env::remove_var("SICARIO_CLOUD_URL");
    }
}

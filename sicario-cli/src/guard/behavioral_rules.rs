//! Behavioral anomaly rules for the Poison-Pill Interceptor.
//!
//! Each rule is a `SecurityRule` with an embedded tree-sitter query that
//! detects a specific suspicious pattern in JavaScript/TypeScript packages.

use crate::engine::security_rule::{QueryPattern, SecurityRule};
use crate::engine::vulnerability::Severity;
use crate::parser::Language;

/// Returns the fixed set of behavioral anomaly detection rules.
///
/// These rules are loaded exclusively into the `BehavioralScanner`'s
/// `SastEngine` instance — they are not mixed with the normal SAST rule set.
pub fn behavioral_rules() -> Vec<SecurityRule> {
    vec![
        // ── Child process spawning ────────────────────────────────────────
        SecurityRule {
            id: "guard/unexpected-child-process".to_string(),
            name: "Unexpected Child Process Spawning".to_string(),
            description: "Package requires 'child_process', which allows spawning arbitrary OS commands. Legitimate utility packages rarely need this.".to_string(),
            severity: Severity::Critical,
            languages: vec![Language::JavaScript, Language::TypeScript],
            pattern: QueryPattern {
                // Matches: require('child_process')
                query: r#"(call_expression
  function: (identifier) @fn (#eq? @fn "require")
  arguments: (arguments (string) @arg (#eq? @arg "'child_process'"))
) @call"#.to_string(),
                captures: vec!["call".to_string()],
            },
            fix_template: None,
            cwe_id: Some("CWE-78".to_string()),
            owasp_category: None,
            help_uri: None,
            test_cases: None,
        },

        // ── Network access ────────────────────────────────────────────────
        SecurityRule {
            id: "guard/unexpected-net-access".to_string(),
            name: "Unexpected Network Access".to_string(),
            description: "Package requires 'net' or 'http', enabling raw TCP/HTTP connections. Packages that are not HTTP clients should not need this.".to_string(),
            severity: Severity::High,
            languages: vec![Language::JavaScript, Language::TypeScript],
            pattern: QueryPattern {
                // Matches: require('net') or require('http')
                query: r#"(call_expression
  function: (identifier) @fn (#eq? @fn "require")
  arguments: (arguments (string) @arg (#match? @arg "^'(net|http)'$"))
) @call"#.to_string(),
                captures: vec!["call".to_string()],
            },
            fix_template: None,
            cwe_id: Some("CWE-918".to_string()),
            owasp_category: None,
            help_uri: None,
            test_cases: None,
        },

        // ── Filesystem access ─────────────────────────────────────────────
        SecurityRule {
            id: "guard/unexpected-fs-access".to_string(),
            name: "Unexpected Filesystem Access".to_string(),
            description: "Package requires 'fs' or 'fs/promises', enabling arbitrary file read/write. Packages that are not file utilities should not need this.".to_string(),
            severity: Severity::High,
            languages: vec![Language::JavaScript, Language::TypeScript],
            pattern: QueryPattern {
                // Matches: require('fs') or require('fs/promises')
                query: r#"(call_expression
  function: (identifier) @fn (#eq? @fn "require")
  arguments: (arguments (string) @arg (#match? @arg "^'fs(/promises)?'$"))
) @call"#.to_string(),
                captures: vec!["call".to_string()],
            },
            fix_template: None,
            cwe_id: Some("CWE-22".to_string()),
            owasp_category: None,
            help_uri: None,
            test_cases: None,
        },

        // ── Obfuscated eval ───────────────────────────────────────────────
        SecurityRule {
            id: "guard/obfuscated-eval".to_string(),
            name: "Obfuscated eval() Call".to_string(),
            description: "Package calls eval() with a non-literal argument (variable, function call, or expression). This is a strong indicator of obfuscated malicious code.".to_string(),
            severity: Severity::Critical,
            languages: vec![Language::JavaScript, Language::TypeScript],
            pattern: QueryPattern {
                // Matches: eval(<non-string-literal>)
                // i.e. eval(someVar), eval(fn()), eval(a + b)
                query: r#"(call_expression
  function: (identifier) @fn (#eq? @fn "eval")
  arguments: (arguments [
    (identifier)
    (call_expression)
    (binary_expression)
    (member_expression)
    (await_expression)
  ] @arg)
) @call"#.to_string(),
                captures: vec!["call".to_string()],
            },
            fix_template: None,
            cwe_id: Some("CWE-95".to_string()),
            owasp_category: None,
            help_uri: None,
            test_cases: None,
        },

        // ── process.env access ────────────────────────────────────────────
        SecurityRule {
            id: "guard/process-env-access".to_string(),
            name: "process.env Credential Access".to_string(),
            description: "Package accesses process.env, potentially harvesting environment variables such as API keys, tokens, or passwords.".to_string(),
            severity: Severity::High,
            languages: vec![Language::JavaScript, Language::TypeScript],
            pattern: QueryPattern {
                // Matches: process.env.ANYTHING or process.env["ANYTHING"]
                query: r#"(member_expression
  object: (member_expression
    object: (identifier) @obj (#eq? @obj "process")
    property: (property_identifier) @prop (#eq? @prop "env")
  )
) @access"#.to_string(),
                captures: vec!["access".to_string()],
            },
            fix_template: None,
            cwe_id: Some("CWE-312".to_string()),
            owasp_category: None,
            help_uri: None,
            test_cases: None,
        },

        // ── Dynamic require ───────────────────────────────────────────────
        SecurityRule {
            id: "guard/dynamic-require".to_string(),
            name: "Dynamic require() Call".to_string(),
            description: "Package calls require() with a variable argument instead of a string literal. This can be used to load arbitrary modules at runtime.".to_string(),
            severity: Severity::Medium,
            languages: vec![Language::JavaScript, Language::TypeScript],
            pattern: QueryPattern {
                // Matches: require(variable) or require(expression) — NOT require('literal')
                query: r#"(call_expression
  function: (identifier) @fn (#eq? @fn "require")
  arguments: (arguments [
    (identifier)
    (call_expression)
    (binary_expression)
    (template_string)
    (member_expression)
  ] @arg)
) @call"#.to_string(),
                captures: vec!["call".to_string()],
            },
            fix_template: None,
            cwe_id: Some("CWE-829".to_string()),
            owasp_category: None,
            help_uri: None,
            test_cases: None,
        },

        // ── Hex-encoded string payload ────────────────────────────────────
        SecurityRule {
            id: "guard/hex-encoded-string".to_string(),
            name: "Hex-Encoded String Payload".to_string(),
            description: "Package contains a string literal that looks like a hex-encoded payload (100+ hex characters). This is a common obfuscation technique for malicious code.".to_string(),
            severity: Severity::High,
            languages: vec![Language::JavaScript, Language::TypeScript],
            pattern: QueryPattern {
                // Matches string literals that are 100+ hex characters
                // tree-sitter #match? uses a regex
                query: r#"(string) @hex_str (#match? @hex_str "^['\"][0-9a-fA-F]{100,}['\"]$")"#.to_string(),
                captures: vec!["hex_str".to_string()],
            },
            fix_template: None,
            cwe_id: Some("CWE-506".to_string()),
            owasp_category: None,
            help_uri: None,
            test_cases: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::sast_engine::SastEngine;
    use std::io::Write;
    use tempfile::TempDir;

    fn scan_snippet(
        rule_id: &str,
        code: &str,
        ext: &str,
    ) -> Vec<crate::engine::vulnerability::Vulnerability> {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join(format!("test.{}", ext));
        let mut f = std::fs::File::create(&file_path).unwrap();
        f.write_all(code.as_bytes()).unwrap();
        drop(f);

        let mut engine = SastEngine::new(dir.path()).unwrap();
        // Load only the specific rule we're testing
        let rules = behavioral_rules();
        let rule = rules.into_iter().find(|r| r.id == rule_id).unwrap();
        engine.load_rule_direct(rule).unwrap();

        engine.scan_file(&file_path).unwrap()
    }

    // ── child_process ─────────────────────────────────────────────────────

    #[test]
    fn test_child_process_fires_on_match() {
        let code = "const cp = require('child_process');";
        let vulns = scan_snippet("guard/unexpected-child-process", code, "js");
        assert!(
            !vulns.is_empty(),
            "Expected finding for require('child_process')"
        );
    }

    #[test]
    fn test_child_process_clean() {
        let code = "const path = require('path');";
        let vulns = scan_snippet("guard/unexpected-child-process", code, "js");
        assert!(vulns.is_empty(), "Expected no finding for require('path')");
    }

    // ── net/http access ───────────────────────────────────────────────────

    #[test]
    fn test_net_access_fires_on_net() {
        let code = "const net = require('net');";
        let vulns = scan_snippet("guard/unexpected-net-access", code, "js");
        assert!(!vulns.is_empty(), "Expected finding for require('net')");
    }

    #[test]
    fn test_net_access_fires_on_http() {
        let code = "const http = require('http');";
        let vulns = scan_snippet("guard/unexpected-net-access", code, "js");
        assert!(!vulns.is_empty(), "Expected finding for require('http')");
    }

    #[test]
    fn test_net_access_clean() {
        let code = "const util = require('util');";
        let vulns = scan_snippet("guard/unexpected-net-access", code, "js");
        assert!(vulns.is_empty(), "Expected no finding for require('util')");
    }

    // ── fs access ─────────────────────────────────────────────────────────

    #[test]
    fn test_fs_access_fires_on_fs() {
        let code = "const fs = require('fs');";
        let vulns = scan_snippet("guard/unexpected-fs-access", code, "js");
        assert!(!vulns.is_empty(), "Expected finding for require('fs')");
    }

    #[test]
    fn test_fs_access_fires_on_fs_promises() {
        let code = "const fs = require('fs/promises');";
        let vulns = scan_snippet("guard/unexpected-fs-access", code, "js");
        assert!(
            !vulns.is_empty(),
            "Expected finding for require('fs/promises')"
        );
    }

    #[test]
    fn test_fs_access_clean() {
        let code = "const os = require('os');";
        let vulns = scan_snippet("guard/unexpected-fs-access", code, "js");
        assert!(vulns.is_empty(), "Expected no finding for require('os')");
    }

    // ── obfuscated eval ───────────────────────────────────────────────────

    #[test]
    fn test_obfuscated_eval_fires_on_identifier() {
        let code = "eval(userInput);";
        let vulns = scan_snippet("guard/obfuscated-eval", code, "js");
        assert!(!vulns.is_empty(), "Expected finding for eval(identifier)");
    }

    #[test]
    fn test_obfuscated_eval_fires_on_call_expression() {
        let code = "eval(Buffer.from(hex).toString());";
        let vulns = scan_snippet("guard/obfuscated-eval", code, "js");
        assert!(
            !vulns.is_empty(),
            "Expected finding for eval(call_expression)"
        );
    }

    #[test]
    fn test_obfuscated_eval_clean_on_literal() {
        // eval with a string literal is still bad practice but not "obfuscated"
        // The rule specifically targets non-literal arguments
        let code = "eval('console.log(1)');";
        let vulns = scan_snippet("guard/obfuscated-eval", code, "js");
        assert!(
            vulns.is_empty(),
            "Expected no finding for eval(string_literal)"
        );
    }

    // ── process.env access ────────────────────────────────────────────────

    #[test]
    fn test_process_env_fires() {
        let code = "const key = process.env.API_KEY;";
        let vulns = scan_snippet("guard/process-env-access", code, "js");
        assert!(!vulns.is_empty(), "Expected finding for process.env.X");
    }

    #[test]
    fn test_process_env_clean() {
        let code = "const version = process.version;";
        let vulns = scan_snippet("guard/process-env-access", code, "js");
        assert!(vulns.is_empty(), "Expected no finding for process.version");
    }

    // ── dynamic require ───────────────────────────────────────────────────

    #[test]
    fn test_dynamic_require_fires_on_variable() {
        let code = "const mod = require(moduleName);";
        let vulns = scan_snippet("guard/dynamic-require", code, "js");
        assert!(!vulns.is_empty(), "Expected finding for require(variable)");
    }

    #[test]
    fn test_dynamic_require_clean_on_literal() {
        let code = "const mod = require('lodash');";
        let vulns = scan_snippet("guard/dynamic-require", code, "js");
        assert!(
            vulns.is_empty(),
            "Expected no finding for require('literal')"
        );
    }

    // ── hex-encoded string ────────────────────────────────────────────────

    #[test]
    fn test_hex_string_fires_on_long_hex() {
        // 100 hex chars
        let hex = "a".repeat(100);
        let code = format!("const payload = '{}';", hex);
        let vulns = scan_snippet("guard/hex-encoded-string", &code, "js");
        assert!(
            !vulns.is_empty(),
            "Expected finding for 100-char hex string"
        );
    }

    #[test]
    fn test_hex_string_clean_on_short_hex() {
        // Only 50 hex chars — below threshold
        let hex = "a".repeat(50);
        let code = format!("const id = '{}';", hex);
        let vulns = scan_snippet("guard/hex-encoded-string", &code, "js");
        assert!(vulns.is_empty(), "Expected no finding for short hex string");
    }

    #[test]
    fn test_hex_string_clean_on_non_hex() {
        let code = "const msg = 'Hello, world! This is a normal string that is definitely not hex encoded.';";
        let vulns = scan_snippet("guard/hex-encoded-string", &code, "js");
        assert!(vulns.is_empty(), "Expected no finding for non-hex string");
    }
}

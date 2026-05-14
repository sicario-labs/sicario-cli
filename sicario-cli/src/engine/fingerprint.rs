//! Finding fingerprinting — stable IDs for cross-branch triage propagation.
//!
//! Three fingerprint types:
//!
//! - `match_based_id`: SHA-256(file_path + rule_id + pattern_with_values) + `_<index>` suffix.
//!   Stable across line-number shifts. Used for cross-branch triage propagation.
//!   Contains no raw source code.
//!
//! - `syntactic_id`: SHA-256(file_path + rule_id + literal_matched_code + match_index).
//!   Used only for internal deduplication. Never transmitted to Sicario Cloud.
//!
//! - `code_hash`: SHA-256(matched_code). One-way hash for publish payload deduplication.
//!   Not reversible without the original text.
//!
//! Requirements: Req 18 — Finding Fingerprinting (Tasks 18.1–18.6)

use sha2::{Digest, Sha256};

/// Compute the `match_based_id` fingerprint.
///
/// `match_based_id` = SHA-256(file_path + "\x00" + rule_id + "\x00" + pattern_with_values)
/// + `_<match_index>` suffix.
///
/// The `pattern_with_values` is the rule's tree-sitter pattern with all `$VAR`
/// metavariables replaced by their matched values from the AST. This makes the
/// ID stable across line-number shifts (adding/removing lines above the match
/// doesn't change the hash) while still being specific to the actual matched
/// code pattern.
///
/// # Arguments
/// - `file_path`: relative path from project root (use `/` separators)
/// - `rule_id`: the rule ID that produced this finding
/// - `pattern_with_values`: rule pattern with metavar values substituted
/// - `match_index`: 0-indexed count of same pattern matches in file
pub fn compute_match_based_id(
    file_path: &str,
    rule_id: &str,
    pattern_with_values: &str,
    match_index: usize,
) -> String {
    let input = format!("{}\x00{}\x00{}", file_path, rule_id, pattern_with_values);
    let hash = sha256_hex(input.as_bytes());
    format!("{}_{}", hash, match_index)
}

/// Compute the `syntactic_id` fingerprint.
///
/// `syntactic_id` = SHA-256(file_path + "\x00" + rule_id + "\x00" + matched_code + "\x00" + match_index).
///
/// Used for internal deduplication only. Never transmitted to Sicario Cloud.
///
/// # Arguments
/// - `file_path`: relative path from project root
/// - `rule_id`: the rule ID that produced this finding
/// - `matched_code`: literal matched source text
/// - `match_index`: 0-indexed count of same pattern matches in file
pub fn compute_syntactic_id(
    file_path: &str,
    rule_id: &str,
    matched_code: &str,
    match_index: usize,
) -> String {
    let input = format!(
        "{}\x00{}\x00{}\x00{}",
        file_path, rule_id, matched_code, match_index
    );
    sha256_hex(input.as_bytes())
}

/// Compute the `code_hash` for the publish payload.
///
/// `code_hash` = "sha256:" + hex(SHA-256(matched_code)).
///
/// This is a one-way hash of the raw matched code text. It is included in the
/// publish payload for deduplication and change detection on the cloud side.
/// It is not reversible without the original text.
pub fn compute_code_hash(matched_code: &str) -> String {
    format!("sha256:{}", sha256_hex(matched_code.as_bytes()))
}

/// Internal helper: compute SHA-256 and return lowercase hex string.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_based_id_format() {
        let id = compute_match_based_id(
            "src/db/queries.js",
            "js-sql-string-concat",
            "db.query($QUERY)",
            0,
        );
        // Should be hex_hash_0
        assert!(
            id.ends_with("_0"),
            "match_based_id should end with _0: {}",
            id
        );
        assert!(id.len() > 10, "match_based_id should be non-trivial");
    }

    #[test]
    fn test_match_based_id_stable_across_line_shifts() {
        // Same pattern, same file, same rule — should produce same hash regardless of line number
        let id1 = compute_match_based_id("src/app.js", "js-eval", "eval($X)", 0);
        let id2 = compute_match_based_id("src/app.js", "js-eval", "eval($X)", 0);
        assert_eq!(id1, id2, "match_based_id must be deterministic");
    }

    #[test]
    fn test_match_based_id_index_suffix() {
        let id0 = compute_match_based_id("src/app.js", "js-eval", "eval($X)", 0);
        let id1 = compute_match_based_id("src/app.js", "js-eval", "eval($X)", 1);
        assert!(id0.ends_with("_0"));
        assert!(id1.ends_with("_1"));
        // The hash part should be the same, only the suffix differs
        let hash0 = &id0[..id0.rfind('_').unwrap()];
        let hash1 = &id1[..id1.rfind('_').unwrap()];
        assert_eq!(hash0, hash1, "hash part should be same for same pattern");
    }

    #[test]
    fn test_match_based_id_differs_for_different_rules() {
        let id1 = compute_match_based_id("src/app.js", "js-eval", "eval($X)", 0);
        let id2 = compute_match_based_id("src/app.js", "js-xss", "eval($X)", 0);
        assert_ne!(
            id1, id2,
            "different rule_id should produce different match_based_id"
        );
    }

    #[test]
    fn test_match_based_id_differs_for_different_files() {
        let id1 = compute_match_based_id("src/a.js", "js-eval", "eval($X)", 0);
        let id2 = compute_match_based_id("src/b.js", "js-eval", "eval($X)", 0);
        assert_ne!(
            id1, id2,
            "different file_path should produce different match_based_id"
        );
    }

    #[test]
    fn test_syntactic_id_deterministic() {
        let id1 = compute_syntactic_id("src/app.js", "js-eval", "eval(userInput)", 0);
        let id2 = compute_syntactic_id("src/app.js", "js-eval", "eval(userInput)", 0);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_syntactic_id_differs_from_match_based_id() {
        let mbid = compute_match_based_id("src/app.js", "js-eval", "eval($X)", 0);
        let sid = compute_syntactic_id("src/app.js", "js-eval", "eval(userInput)", 0);
        // They use different inputs so should differ
        assert_ne!(mbid, sid);
    }

    #[test]
    fn test_code_hash_format() {
        let hash = compute_code_hash("eval(userInput)");
        assert!(
            hash.starts_with("sha256:"),
            "code_hash must start with 'sha256:'"
        );
        assert_eq!(hash.len(), 7 + 64, "sha256: prefix + 64 hex chars");
    }

    #[test]
    fn test_code_hash_deterministic() {
        let h1 = compute_code_hash("eval(userInput)");
        let h2 = compute_code_hash("eval(userInput)");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_code_hash_differs_for_different_code() {
        let h1 = compute_code_hash("eval(userInput)");
        let h2 = compute_code_hash("eval(safeInput)");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_code_hash_empty_string() {
        let hash = compute_code_hash("");
        assert!(hash.starts_with("sha256:"));
        // SHA-256 of empty string is well-known
        assert!(hash.contains("e3b0c44298fc1c149afb"));
    }
}

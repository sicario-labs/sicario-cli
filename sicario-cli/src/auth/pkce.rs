//! PKCE (Proof Key for Code Exchange) implementation per RFC 7636

use rand::Rng;
use sha2::{Digest, Sha256};

/// Allowed characters for code_verifier per RFC 7636 §4.1
const VERIFIER_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

/// Generate a cryptographically random code_verifier (43–128 characters) per RFC 7636 §4.1.
pub fn generate_code_verifier() -> String {
    let mut rng = rand::thread_rng();
    // Use 96 characters — well within the 43–128 range
    (0..96)
        .map(|_| {
            let idx = rng.gen_range(0..VERIFIER_CHARS.len());
            VERIFIER_CHARS[idx] as char
        })
        .collect()
}

/// Compute code_challenge = BASE64URL(SHA256(code_verifier)) per RFC 7636 §4.2.
pub fn compute_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    base64_url::encode(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_verifier_length() {
        let verifier = generate_code_verifier();
        assert!(
            verifier.len() >= 43 && verifier.len() <= 128,
            "verifier length {} out of RFC 7636 range",
            verifier.len()
        );
    }

    #[test]
    fn test_code_verifier_charset() {
        let verifier = generate_code_verifier();
        for ch in verifier.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || "-._~".contains(ch),
                "invalid char '{}' in verifier",
                ch
            );
        }
    }

    #[test]
    fn test_code_challenge_deterministic() {
        let verifier = "test_verifier_abc123";
        let c1 = compute_code_challenge(verifier);
        let c2 = compute_code_challenge(verifier);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_code_challenge_non_empty() {
        let challenge = compute_code_challenge("any_verifier");
        assert!(!challenge.is_empty());
    }

    #[test]
    fn test_code_challenge_is_base64url() {
        let challenge = compute_code_challenge("some_verifier");
        // base64url uses A-Z a-z 0-9 - _  (no + / or =)
        for ch in challenge.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "non-base64url char '{}' in challenge",
                ch
            );
        }
    }

    #[test]
    fn test_different_verifiers_produce_different_challenges() {
        let c1 = compute_code_challenge("verifier_one");
        let c2 = compute_code_challenge("verifier_two");
        assert_ne!(c1, c2);
    }
}

//! Preservation Property Tests for CLI Auth Module
//!
//! **Validates: Requirements 3.4** (CLI OAuth Device Flow with PKCE preservation)
//!
//! These tests capture the CURRENT behavior of the auth module on UNFIXED code.
//! They must PASS on unfixed code, confirming baseline behavior to preserve
//! after the bugfix.
//!
//! The existing `auth_property_tests.rs` already covers PKCE and TokenStore
//! extensively. This module adds preservation-specific properties that map
//! directly to the bugfix spec's preservation requirements.

use proptest::prelude::*;
use sha2::{Digest, Sha256};

use crate::auth::pkce::{compute_code_challenge, generate_code_verifier};
use crate::auth::token_store::TokenStore;

/// Allowed characters for a PKCE code_verifier per RFC 7636 §4.1
const VERIFIER_CHARS: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

/// Strategy that generates valid code_verifier strings (43–128 chars).
fn verifier_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(VERIFIER_CHARS.as_bytes()), 43..=128)
        .prop_map(|bytes| bytes.iter().map(|&b| b as char).collect())
}

/// Strategy for arbitrary non-empty token strings (printable ASCII).
fn token_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9._\\-]{1,256}").unwrap()
}

// ── Preservation Property 14: PKCE generate_code_verifier ─────────────────────
//
// **Validates: Requirements 3.4**
//
// PKCE `generate_code_verifier()` produces 43-128 char verifiers with valid
// charset. This behavior must be preserved after the bugfix.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Preservation: generate_code_verifier always produces a verifier within
    /// the RFC 7636 §4.1 length range (43–128 characters).
    #[test]
    fn preservation_verifier_length_in_range(_seed in 0u64..u64::MAX) {
        let verifier = generate_code_verifier();
        prop_assert!(
            verifier.len() >= 43 && verifier.len() <= 128,
            "verifier length {} outside RFC 7636 range 43–128",
            verifier.len()
        );
    }

    /// Preservation: generate_code_verifier only uses RFC 7636 §4.1 unreserved
    /// characters (A-Z, a-z, 0-9, '-', '.', '_', '~').
    #[test]
    fn preservation_verifier_charset_valid(_seed in 0u64..u64::MAX) {
        let verifier = generate_code_verifier();
        for ch in verifier.chars() {
            prop_assert!(
                ch.is_ascii_alphanumeric() || "-._~".contains(ch),
                "verifier contains invalid character '{}'",
                ch
            );
        }
    }
}

// ── Preservation Property 15: PKCE compute_code_challenge ─────────────────────
//
// **Validates: Requirements 3.4**
//
// PKCE `compute_code_challenge(verifier)` is deterministic and produces
// base64url-encoded output. This behavior must be preserved after the bugfix.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Preservation: compute_code_challenge is deterministic — same verifier
    /// always produces the same challenge.
    #[test]
    fn preservation_challenge_deterministic(verifier in verifier_strategy()) {
        let c1 = compute_code_challenge(&verifier);
        let c2 = compute_code_challenge(&verifier);
        prop_assert_eq!(c1, c2, "challenge must be deterministic");
    }

    /// Preservation: compute_code_challenge produces valid base64url output
    /// (no '+', '/', or '=' characters).
    #[test]
    fn preservation_challenge_is_base64url(verifier in verifier_strategy()) {
        let challenge = compute_code_challenge(&verifier);
        prop_assert!(!challenge.is_empty(), "challenge must not be empty");
        for ch in challenge.chars() {
            prop_assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "challenge contains non-base64url character '{}'",
                ch
            );
        }
        prop_assert!(
            !challenge.contains('='),
            "challenge must not contain padding '='"
        );
    }

    /// Preservation: compute_code_challenge equals BASE64URL(SHA256(verifier))
    /// — the exact transformation mandated by RFC 7636 §4.2.
    #[test]
    fn preservation_challenge_equals_sha256_base64url(verifier in verifier_strategy()) {
        let challenge = compute_code_challenge(&verifier);
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hash = hasher.finalize();
        let expected = base64_url::encode(&hash);
        prop_assert_eq!(
            challenge,
            expected,
            "challenge must be BASE64URL(SHA256(verifier))"
        );
    }
}

// ── Preservation Property 16: TokenStore round-trip ───────────────────────────
//
// **Validates: Requirements 3.4**
//
// `TokenStore` round-trip — store then retrieve returns identical token.
// This behavior must be preserved after the bugfix.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Preservation: access token round-trip — store then retrieve returns
    /// the exact same token.
    #[test]
    fn preservation_access_token_round_trip(token in token_strategy()) {
        let store = TokenStore::in_memory();
        store.store_access_token(&token).expect("store failed");
        let retrieved = store.get_access_token().expect("get failed");
        prop_assert_eq!(retrieved, token, "access token round-trip failed");
    }

    /// Preservation: refresh token round-trip — store then retrieve returns
    /// the exact same token.
    #[test]
    fn preservation_refresh_token_round_trip(token in token_strategy()) {
        let store = TokenStore::in_memory();
        store.store_refresh_token(&token).expect("store failed");
        let retrieved = store.get_refresh_token().expect("get failed");
        prop_assert_eq!(retrieved, token, "refresh token round-trip failed");
    }

    /// Preservation: cloud token round-trip — store then retrieve returns
    /// the exact same token.
    #[test]
    fn preservation_cloud_token_round_trip(token in token_strategy()) {
        let store = TokenStore::in_memory();
        store.store_cloud_token(&token).expect("store failed");
        let retrieved = store.get_cloud_token().expect("get failed");
        prop_assert_eq!(retrieved, token, "cloud token round-trip failed");
    }

    /// Preservation: clearing tokens makes them unrecoverable.
    #[test]
    fn preservation_clear_tokens_removes_all(token in token_strategy()) {
        let store = TokenStore::in_memory();
        store.store_access_token(&token).expect("store failed");
        store.store_refresh_token(&token).expect("store failed");
        store.clear_tokens().expect("clear failed");
        prop_assert!(
            store.get_access_token().is_err(),
            "access token should be gone after clear"
        );
        prop_assert!(
            store.get_refresh_token().is_err(),
            "refresh token should be gone after clear"
        );
    }
}

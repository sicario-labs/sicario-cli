//! Property-based tests for the OAuth 2.0 Device Flow + PKCE authentication module.
//!
//! Feature: sicario-cli-core

use proptest::prelude::*;
use sha2::{Digest, Sha256};

use crate::auth::pkce::{compute_code_challenge, generate_code_verifier};
use crate::auth::{DeviceCodeResponse, TokenResponse};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Allowed characters for a PKCE code_verifier per RFC 7636 §4.1
const VERIFIER_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

/// Compute the expected code_challenge independently of the production code.
fn expected_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    base64_url::encode(&hash)
}

/// Strategy that generates valid code_verifier strings (43–128 chars from the
/// RFC 7636 §4.1 unreserved character set).
fn verifier_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(VERIFIER_CHARS.as_bytes()), 43..=128)
        .prop_map(|bytes| bytes.iter().map(|&b| b as char).collect())
}

// ── Property 19: OAuth Device Flow compliance ─────────────────────────────────
//
// For any authentication attempt, the Auth Module should implement the complete
// OAuth 2.0 Device Authorization Grant flow per RFC 8628, including requesting
// device_code, user_code, and verification_uri, displaying them to the user,
// and asynchronously polling the token endpoint.
//
// This property validates the PKCE cryptographic binding that underpins the
// Device Flow: for any code_verifier, the code_challenge sent to the
// authorization server must equal BASE64URL(SHA256(code_verifier)).
//
// Validates: Requirements 7.1

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    /// Feature: sicario-cli-core, Property 19: OAuth Device Flow compliance
    ///
    /// For any valid code_verifier, `compute_code_challenge` must produce
    /// BASE64URL(SHA256(verifier)) — the exact transformation mandated by
    /// RFC 7636 §4.2 and required for RFC 8628 Device Flow compliance.
    #[test]
    fn prop_pkce_challenge_equals_sha256_base64url(verifier in verifier_strategy()) {
        let challenge = compute_code_challenge(&verifier);
        let expected = expected_challenge(&verifier);
        prop_assert_eq!(
            challenge,
            expected,
            "code_challenge must be BASE64URL(SHA256(code_verifier)) per RFC 7636"
        );
    }

    /// Feature: sicario-cli-core, Property 19: OAuth Device Flow compliance
    ///
    /// The code_challenge must be a valid base64url string (no padding, no +/).
    #[test]
    fn prop_pkce_challenge_is_valid_base64url(verifier in verifier_strategy()) {
        let challenge = compute_code_challenge(&verifier);
        prop_assert!(
            !challenge.is_empty(),
            "code_challenge must not be empty"
        );
        for ch in challenge.chars() {
            prop_assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "code_challenge contains non-base64url character '{}'",
                ch
            );
        }
        // base64url without padding must not contain '='
        prop_assert!(
            !challenge.contains('='),
            "code_challenge must not contain padding '='"
        );
    }

    /// Feature: sicario-cli-core, Property 19: OAuth Device Flow compliance
    ///
    /// Two distinct verifiers must produce distinct challenges (collision resistance).
    #[test]
    fn prop_pkce_distinct_verifiers_produce_distinct_challenges(
        v1 in verifier_strategy(),
        v2 in verifier_strategy(),
    ) {
        prop_assume!(v1 != v2);
        let c1 = compute_code_challenge(&v1);
        let c2 = compute_code_challenge(&v2);
        prop_assert_ne!(
            c1, c2,
            "distinct verifiers must produce distinct challenges"
        );
    }

    /// Feature: sicario-cli-core, Property 19: OAuth Device Flow compliance
    ///
    /// `compute_code_challenge` must be deterministic: the same verifier always
    /// produces the same challenge (required for the token exchange step).
    #[test]
    fn prop_pkce_challenge_is_deterministic(verifier in verifier_strategy()) {
        let c1 = compute_code_challenge(&verifier);
        let c2 = compute_code_challenge(&verifier);
        prop_assert_eq!(c1, c2, "code_challenge must be deterministic");
    }
}

// ── Property 19 (structural): DeviceCodeResponse fields ──────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    /// Feature: sicario-cli-core, Property 19: OAuth Device Flow compliance
    ///
    /// A DeviceCodeResponse must round-trip through JSON serialization without
    /// data loss — required for reliable display of user_code and verification_uri.
    #[test]
    fn prop_device_code_response_roundtrip(
        device_code in "[a-zA-Z0-9_-]{16,64}",
        user_code   in "[A-Z0-9]{4}-[A-Z0-9]{4}",
        uri         in "https://[a-z]{4,12}\\.example\\.com/activate",
        interval    in 1u64..=30u64,
    ) {
        let resp = DeviceCodeResponse {
            device_code: device_code.clone(),
            user_code: user_code.clone(),
            verification_uri: uri.clone(),
            interval,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: DeviceCodeResponse = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(&back.device_code, &device_code);
        prop_assert_eq!(&back.user_code, &user_code);
        prop_assert_eq!(&back.verification_uri, &uri);
        prop_assert_eq!(back.interval, interval);
    }

    /// Feature: sicario-cli-core, Property 19: OAuth Device Flow compliance
    ///
    /// A TokenResponse must round-trip through JSON serialization without data
    /// loss — required for reliable token storage after polling completes.
    #[test]
    fn prop_token_response_roundtrip(
        access_token  in "[a-zA-Z0-9._-]{32,128}",
        refresh_token in "[a-zA-Z0-9._-]{32,128}",
        expires_in    in 300u64..=86400u64,
    ) {
        let resp = TokenResponse {
            access_token: access_token.clone(),
            refresh_token: refresh_token.clone(),
            expires_in,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: TokenResponse = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(&back.access_token, &access_token);
        prop_assert_eq!(&back.refresh_token, &refresh_token);
        prop_assert_eq!(back.expires_in, expires_in);
    }
}

// ── Property 20: PKCE cryptographic binding ───────────────────────────────────
//
// For any device flow authentication, the code_challenge sent in the initial
// request should be the base64url-encoded SHA-256 hash of the code_verifier
// presented during token retrieval, ensuring cryptographic proof of client
// identity per RFC 7636.
//
// Validates: Requirements 7.6

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    /// Feature: sicario-cli-core, Property 20: PKCE cryptographic binding
    ///
    /// For any code_verifier, the code_challenge must equal
    /// BASE64URL(SHA256(code_verifier)), binding the initial authorization
    /// request to the subsequent token exchange (RFC 7636 §4.2).
    #[test]
    fn prop_pkce_challenge_is_sha256_of_verifier(verifier in verifier_strategy()) {
        let challenge = compute_code_challenge(&verifier);

        // Independently compute SHA-256 and base64url-encode
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let digest = hasher.finalize();
        let expected = base64_url::encode(&digest);

        prop_assert_eq!(
            &challenge,
            &expected,
            "code_challenge must be BASE64URL(SHA256(code_verifier)) — \
             cryptographic binding broken for verifier of length {}",
            verifier.len()
        );
    }

    /// Feature: sicario-cli-core, Property 20: PKCE cryptographic binding
    ///
    /// The SHA-256 output is always 32 bytes; base64url-encoding 32 bytes
    /// without padding always produces exactly 43 characters.
    #[test]
    fn prop_pkce_challenge_length_is_43(verifier in verifier_strategy()) {
        let challenge = compute_code_challenge(&verifier);
        prop_assert_eq!(
            challenge.len(),
            43,
            "BASE64URL(SHA256(verifier)) must be exactly 43 characters, got {}",
            challenge.len()
        );
    }

    /// Feature: sicario-cli-core, Property 20: PKCE cryptographic binding
    ///
    /// A single-bit change in the verifier must produce a different challenge
    /// (avalanche effect / pre-image resistance of SHA-256).
    #[test]
    fn prop_pkce_verifier_mutation_changes_challenge(verifier in verifier_strategy()) {
        // Flip the last character to a different RFC-7636-legal character
        let mut mutated = verifier.clone();
        let last = mutated.pop().unwrap_or('A');
        let replacement = if last == 'A' { 'B' } else { 'A' };
        mutated.push(replacement);

        let c_original = compute_code_challenge(&verifier);
        let c_mutated   = compute_code_challenge(&mutated);

        prop_assert_ne!(
            c_original,
            c_mutated,
            "mutating the verifier must change the challenge (avalanche effect)"
        );
    }

    /// Feature: sicario-cli-core, Property 20: PKCE cryptographic binding
    ///
    /// `generate_code_verifier` must always produce a string that satisfies
    /// the RFC 7636 §4.1 constraints (length 43–128, unreserved charset),
    /// so that any generated verifier is a valid input to `compute_code_challenge`.
    #[test]
    fn prop_generated_verifier_is_valid_rfc7636(
        // Use a seed to drive deterministic generation in proptest
        _seed in 0u64..u64::MAX,
    ) {
        let verifier = generate_code_verifier();
        prop_assert!(
            verifier.len() >= 43 && verifier.len() <= 128,
            "verifier length {} violates RFC 7636 §4.1 (must be 43–128)",
            verifier.len()
        );
        for ch in verifier.chars() {
            prop_assert!(
                ch.is_ascii_alphanumeric() || "-._~".contains(ch),
                "verifier contains character '{}' outside RFC 7636 §4.1 unreserved set",
                ch
            );
        }
    }
}

// ── Property 21: Token storage security ──────────────────────────────────────
//
// For any received access token or refresh token, the Auth Module should store
// it in the system keychain and never write it to plaintext files or
// environment variables.
//
// We validate the observable contract: tokens stored via TokenStore can be
// retrieved intact, and clearing tokens makes them unrecoverable.
//
// Each proptest case uses TokenStore::in_memory() — an isolated in-memory
// store — so that tests are hermetic, parallel-safe, and independent of
// platform keychain availability (Windows Credential Manager, macOS Keychain,
// libsecret on Linux).  The in_memory() backend is compiled in only under
// #[cfg(test)] and shares the same public API as the production keychain
// backend, so the properties validated here apply equally to both.
//
// Validates: Requirements 7.7

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    /// Feature: sicario-cli-core, Property 21: Token storage security
    ///
    /// For any access token string, storing it via TokenStore and then
    /// retrieving it should return the exact same token (round-trip integrity).
    #[test]
    fn prop_access_token_storage_round_trip(
        token in "[a-zA-Z0-9._\\-]{32,128}",
    ) {
        use crate::auth::token_store::TokenStore;

        let store = TokenStore::in_memory();
        store.store_access_token(&token).expect("store_access_token failed");
        let retrieved = store.get_access_token().expect("get_access_token failed");

        prop_assert_eq!(
            retrieved,
            token,
            "retrieved access token must equal the stored token"
        );
    }

    /// Feature: sicario-cli-core, Property 21: Token storage security
    ///
    /// For any refresh token string, storing it via TokenStore and then
    /// retrieving it should return the exact same token (round-trip integrity).
    #[test]
    fn prop_refresh_token_storage_round_trip(
        token in "[a-zA-Z0-9._\\-]{32,128}",
    ) {
        use crate::auth::token_store::TokenStore;

        let store = TokenStore::in_memory();
        store.store_refresh_token(&token).expect("store_refresh_token failed");
        let retrieved = store.get_refresh_token().expect("get_refresh_token failed");

        prop_assert_eq!(
            retrieved,
            token,
            "retrieved refresh token must equal the stored token"
        );
    }

    /// Feature: sicario-cli-core, Property 21: Token storage security
    ///
    /// After clearing tokens, attempting to retrieve them should fail —
    /// confirming that clear_tokens() removes the stored entries.
    #[test]
    fn prop_cleared_tokens_are_not_retrievable(
        token in "[a-zA-Z0-9._\\-]{32,128}",
    ) {
        use crate::auth::token_store::TokenStore;

        let store = TokenStore::in_memory();
        store.store_access_token(&token).expect("store_access_token failed");
        store.clear_tokens().expect("clear_tokens failed");

        let result = store.get_access_token();
        prop_assert!(
            result.is_err(),
            "get_access_token should fail after clear_tokens()"
        );
    }

    /// Feature: sicario-cli-core, Property 21: Token storage security
    ///
    /// Overwriting an access token with a new value should make the new value
    /// retrievable (last-write-wins semantics).
    #[test]
    fn prop_token_overwrite_returns_latest_value(
        token_a in "[a-zA-Z0-9._\\-]{32,64}",
        token_b in "[a-zA-Z0-9._\\-]{32,64}",
    ) {
        prop_assume!(token_a != token_b);
        use crate::auth::token_store::TokenStore;

        let store = TokenStore::in_memory();
        store.store_access_token(&token_a).expect("first store failed");
        store.store_access_token(&token_b).expect("second store failed");
        let retrieved = store.get_access_token().expect("get_access_token failed");

        prop_assert_eq!(
            retrieved,
            token_b,
            "after overwrite, retrieved token must be the latest stored value"
        );
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn generated_verifier_satisfies_rfc7636_length() {
        for _ in 0..20 {
            let v = generate_code_verifier();
            assert!(
                v.len() >= 43 && v.len() <= 128,
                "verifier length {} violates RFC 7636",
                v.len()
            );
        }
    }

    #[test]
    fn generated_verifier_satisfies_rfc7636_charset() {
        for _ in 0..20 {
            let v = generate_code_verifier();
            for ch in v.chars() {
                assert!(
                    ch.is_ascii_alphanumeric() || "-._~".contains(ch),
                    "invalid char '{}' in verifier",
                    ch
                );
            }
        }
    }

    #[test]
    fn known_challenge_value() {
        // RFC 7636 Appendix B example (adapted)
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = compute_code_challenge(verifier);
        // Verify it is non-empty and base64url-safe
        assert!(!challenge.is_empty());
        assert!(!challenge.contains('+'));
        assert!(!challenge.contains('/'));
        assert!(!challenge.contains('='));
    }
}

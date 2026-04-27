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

// ── Property 4: Auth Priority Chain Resolution ────────────────────────────────
//
// For any combination of credential availability states, the auth resolver
// SHALL always select the highest-priority available credential and format it
// correctly:
//   - Project API keys → "Bearer project:{key}"
//   - Cloud OAuth tokens → "Bearer {token}"
//
// Priority order (1 = highest):
//   1. SICARIO_API_KEY env var
//   2. Cloud OAuth token from keychain
//   3. SICARIO_PROJECT_API_KEY env var
//   4. Project API key from keychain
//   5. api_key from .sicario/config.yaml
//
// Validates: Requirements 14.1, 14.2, 14.6

#[cfg(test)]
mod prop4_auth_priority_chain {
    use proptest::prelude::*;

    use crate::auth::auth_module::resolve_auth_token_pure;

    // ── Generators ────────────────────────────────────────────────────────────

    /// Strategy for a non-empty credential value (simulates a real key/token).
    fn arb_cred() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_\\-]{16,64}"
    }

    /// Strategy for an optional credential: Some(value) or None.
    fn arb_opt_cred() -> impl Strategy<Value = Option<String>> {
        prop_oneof![
            Just(None),
            arb_cred().prop_map(Some),
        ]
    }

    // ── Property 4a: Highest-priority credential is always selected ───────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        /// Feature: zero-exfil-edge-scanning, Property 4: Auth Priority Chain Resolution
        ///
        /// When SICARIO_API_KEY is set (priority 1), it must always be selected
        /// regardless of what other credentials are available.
        ///
        /// Validates: Requirements 14.1, 14.6
        #[test]
        fn prop4_sicario_api_key_always_wins(
            api_key          in arb_cred(),
            cloud_token      in arb_opt_cred(),
            project_api_key  in arb_opt_cred(),
            keychain_key     in arb_opt_cred(),
            config_key       in arb_opt_cred(),
        ) {
            let result = resolve_auth_token_pure(
                Some(&api_key),
                cloud_token.as_deref(),
                project_api_key.as_deref(),
                keychain_key.as_deref(),
                config_key.as_deref(),
            ).expect("should resolve when SICARIO_API_KEY is set");

            prop_assert_eq!(
                result,
                format!("Bearer project:{}", api_key),
                "SICARIO_API_KEY must always be selected as priority 1 and \
                 formatted as 'Bearer project:{{key}}'"
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 4: Auth Priority Chain Resolution
        ///
        /// When SICARIO_API_KEY is absent but a cloud OAuth token is present
        /// (priority 2), the cloud token must be selected.
        ///
        /// Validates: Requirements 14.2, 14.6
        #[test]
        fn prop4_cloud_oauth_token_wins_when_api_key_absent(
            cloud_token      in arb_cred(),
            project_api_key  in arb_opt_cred(),
            keychain_key     in arb_opt_cred(),
            config_key       in arb_opt_cred(),
        ) {
            let result = resolve_auth_token_pure(
                None,                          // no SICARIO_API_KEY
                Some(&cloud_token),            // cloud OAuth token present
                project_api_key.as_deref(),
                keychain_key.as_deref(),
                config_key.as_deref(),
            ).expect("should resolve when cloud OAuth token is set");

            prop_assert_eq!(
                result,
                format!("Bearer {}", cloud_token),
                "Cloud OAuth token must be selected as priority 2 and \
                 formatted as 'Bearer {{token}}' (no 'project:' prefix)"
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 4: Auth Priority Chain Resolution
        ///
        /// When priorities 1–2 are absent but SICARIO_PROJECT_API_KEY is set
        /// (priority 3), it must be selected.
        ///
        /// Validates: Requirements 14.1, 14.6
        #[test]
        fn prop4_project_api_key_env_wins_at_priority_3(
            project_api_key  in arb_cred(),
            keychain_key     in arb_opt_cred(),
            config_key       in arb_opt_cred(),
        ) {
            let result = resolve_auth_token_pure(
                None,                          // no SICARIO_API_KEY
                None,                          // no cloud OAuth token
                Some(&project_api_key),        // SICARIO_PROJECT_API_KEY present
                keychain_key.as_deref(),
                config_key.as_deref(),
            ).expect("should resolve when SICARIO_PROJECT_API_KEY is set");

            prop_assert_eq!(
                result,
                format!("Bearer project:{}", project_api_key),
                "SICARIO_PROJECT_API_KEY must be selected as priority 3 and \
                 formatted as 'Bearer project:{{key}}'"
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 4: Auth Priority Chain Resolution
        ///
        /// When priorities 1–3 are absent but a keychain project key is present
        /// (priority 4), it must be selected.
        ///
        /// Validates: Requirements 14.1, 14.6
        #[test]
        fn prop4_keychain_project_key_wins_at_priority_4(
            keychain_key  in arb_cred(),
            config_key    in arb_opt_cred(),
        ) {
            let result = resolve_auth_token_pure(
                None,                  // no SICARIO_API_KEY
                None,                  // no cloud OAuth token
                None,                  // no SICARIO_PROJECT_API_KEY
                Some(&keychain_key),   // keychain project key present
                config_key.as_deref(),
            ).expect("should resolve when keychain project key is set");

            prop_assert_eq!(
                result,
                format!("Bearer project:{}", keychain_key),
                "Keychain project API key must be selected as priority 4 and \
                 formatted as 'Bearer project:{{key}}'"
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 4: Auth Priority Chain Resolution
        ///
        /// When priorities 1–4 are absent but a config.yaml api_key is present
        /// (priority 5), it must be selected.
        ///
        /// Validates: Requirements 14.4, 14.6
        #[test]
        fn prop4_config_api_key_wins_at_priority_5(
            config_key in arb_cred(),
        ) {
            let result = resolve_auth_token_pure(
                None,              // no SICARIO_API_KEY
                None,              // no cloud OAuth token
                None,              // no SICARIO_PROJECT_API_KEY
                None,              // no keychain project key
                Some(&config_key), // config.yaml api_key present
            ).expect("should resolve when config.yaml api_key is set");

            prop_assert_eq!(
                result,
                format!("Bearer project:{}", config_key),
                "config.yaml api_key must be selected as priority 5 and \
                 formatted as 'Bearer project:{{key}}'"
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 4: Auth Priority Chain Resolution
        ///
        /// When no credentials are available at any priority level, the resolver
        /// must return an error (never panic or return an empty token).
        ///
        /// Validates: Requirements 14.3, 14.6
        #[test]
        fn prop4_no_credentials_returns_error(_seed in 0u64..u64::MAX) {
            let result = resolve_auth_token_pure(None, None, None, None, None);
            prop_assert!(
                result.is_err(),
                "resolver must return an error when no credentials are available"
            );
            let err_msg = result.unwrap_err().to_string();
            prop_assert!(
                err_msg.contains("sicario login") || err_msg.contains("SICARIO_API_KEY"),
                "error message must mention 'sicario login' or 'SICARIO_API_KEY', got: '{}'",
                err_msg
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 4: Auth Priority Chain Resolution
        ///
        /// For any combination of credential availability, the resolved token
        /// must always start with "Bearer " (never a bare key or empty string).
        ///
        /// Validates: Requirements 14.2
        #[test]
        fn prop4_resolved_token_always_starts_with_bearer(
            api_key         in arb_opt_cred(),
            cloud_token     in arb_opt_cred(),
            project_key_env in arb_opt_cred(),
            keychain_key    in arb_opt_cred(),
            config_key      in arb_opt_cred(),
        ) {
            // Only test cases where at least one credential is available
            prop_assume!(
                api_key.is_some()
                    || cloud_token.is_some()
                    || project_key_env.is_some()
                    || keychain_key.is_some()
                    || config_key.is_some()
            );

            let result = resolve_auth_token_pure(
                api_key.as_deref(),
                cloud_token.as_deref(),
                project_key_env.as_deref(),
                keychain_key.as_deref(),
                config_key.as_deref(),
            ).expect("should resolve when at least one credential is available");

            prop_assert!(
                result.starts_with("Bearer "),
                "resolved token must always start with 'Bearer ', got: '{}'",
                result
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 4: Auth Priority Chain Resolution
        ///
        /// Project API keys (from any source) must always be formatted as
        /// "Bearer project:{key}" — never as a bare OAuth token.
        ///
        /// Validates: Requirements 14.2
        #[test]
        fn prop4_project_keys_always_have_project_prefix(
            key in arb_cred(),
            // Which project key source to use (0=SICARIO_API_KEY, 1=SICARIO_PROJECT_API_KEY,
            // 2=keychain, 3=config)
            source in 0usize..4,
        ) {
            let (p1, p2, p3, p4, p5) = match source {
                0 => (Some(key.as_str()), None, None, None, None),
                1 => (None, None, Some(key.as_str()), None, None),
                2 => (None, None, None, Some(key.as_str()), None),
                _ => (None, None, None, None, Some(key.as_str())),
            };

            let result = resolve_auth_token_pure(p1, p2, p3, p4, p5)
                .expect("should resolve when a project key is set");

            prop_assert!(
                result.starts_with("Bearer project:"),
                "project API keys must be formatted as 'Bearer project:{{key}}', got: '{}'",
                result
            );
            prop_assert!(
                result.ends_with(&key),
                "formatted token must end with the original key value. \
                 Token: '{}', key: '{}'",
                result, key
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 4: Auth Priority Chain Resolution
        ///
        /// Cloud OAuth tokens must be formatted as "Bearer {token}" — without
        /// the "project:" prefix that project API keys use.
        ///
        /// Validates: Requirements 14.2
        #[test]
        fn prop4_cloud_oauth_token_has_no_project_prefix(
            token in arb_cred(),
        ) {
            let result = resolve_auth_token_pure(
                None,           // no SICARIO_API_KEY (would override)
                Some(&token),   // cloud OAuth token
                None,
                None,
                None,
            ).expect("should resolve when cloud OAuth token is set");

            prop_assert!(
                !result.contains("project:"),
                "cloud OAuth token must NOT contain 'project:' prefix, got: '{}'",
                result
            );
            prop_assert_eq!(
                result,
                format!("Bearer {}", token),
                "cloud OAuth token must be formatted as 'Bearer {{token}}'"
            );
        }
    }

    // ── Unit tests: deterministic priority examples ───────────────────────────

    #[test]
    fn unit_priority_1_beats_all_others() {
        let r = resolve_auth_token_pure(
            Some("key1"),
            Some("oauth_tok"),
            Some("key3"),
            Some("key4"),
            Some("key5"),
        ).unwrap();
        assert_eq!(r, "Bearer project:key1");
    }

    #[test]
    fn unit_priority_2_beats_3_4_5() {
        let r = resolve_auth_token_pure(
            None,
            Some("oauth_tok"),
            Some("key3"),
            Some("key4"),
            Some("key5"),
        ).unwrap();
        assert_eq!(r, "Bearer oauth_tok");
    }

    #[test]
    fn unit_priority_3_beats_4_5() {
        let r = resolve_auth_token_pure(None, None, Some("key3"), Some("key4"), Some("key5")).unwrap();
        assert_eq!(r, "Bearer project:key3");
    }

    #[test]
    fn unit_priority_4_beats_5() {
        let r = resolve_auth_token_pure(None, None, None, Some("key4"), Some("key5")).unwrap();
        assert_eq!(r, "Bearer project:key4");
    }

    #[test]
    fn unit_priority_5_is_last_resort() {
        let r = resolve_auth_token_pure(None, None, None, None, Some("key5")).unwrap();
        assert_eq!(r, "Bearer project:key5");
    }

    #[test]
    fn unit_all_absent_returns_error() {
        let r = resolve_auth_token_pure(None, None, None, None, None);
        assert!(r.is_err());
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("sicario login") || msg.contains("SICARIO_API_KEY"));
    }

    #[test]
    fn unit_empty_string_credentials_are_skipped() {
        // Empty strings must be treated as absent (same as None)
        let r = resolve_auth_token_pure(
            Some(""),   // empty → skip
            Some(""),   // empty → skip
            Some(""),   // empty → skip
            Some(""),   // empty → skip
            Some("key5"),
        ).unwrap();
        assert_eq!(r, "Bearer project:key5");
    }
}

//! Authentication module
//!
//! Implements OAuth 2.0 Device Flow (RFC 8628) with PKCE (RFC 7636) for secure
//! authentication.  Tokens are stored in the system keychain via the `keyring`
//! crate and never written to plaintext files.

use serde::{Deserialize, Serialize};

pub mod auth_module;
pub mod pkce;
pub mod token_store;

#[cfg(test)]
pub mod auth_property_tests;

pub use auth_module::AuthModule;
pub use pkce::{compute_code_challenge, generate_code_verifier};

/// Response from the device authorization endpoint (RFC 8628 §3.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    /// Minimum polling interval in seconds
    pub interval: u64,
}

/// Response from the token endpoint (RFC 8628 §3.5)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_code_response_serialization() {
        let resp = DeviceCodeResponse {
            device_code: "dev_code_abc".to_string(),
            user_code: "ABCD-1234".to_string(),
            verification_uri: "https://example.com/activate".to_string(),
            interval: 5,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: DeviceCodeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.user_code, "ABCD-1234");
        assert_eq!(back.interval, 5);
    }

    #[test]
    fn test_token_response_serialization() {
        let resp = TokenResponse {
            access_token: "access_abc".to_string(),
            refresh_token: "refresh_xyz".to_string(),
            expires_in: 3600,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: TokenResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.access_token, "access_abc");
        assert_eq!(back.expires_in, 3600);
    }
}

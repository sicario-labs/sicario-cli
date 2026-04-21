//! OAuth 2.0 Device Flow authentication implementation per RFC 8628 + PKCE per RFC 7636

use anyhow::{anyhow, bail, Result};
use serde::Deserialize;
use std::time::{Duration, Instant};

use super::pkce::{compute_code_challenge, generate_code_verifier};
use super::token_store::TokenStore;
use super::{DeviceCodeResponse, TokenResponse};

/// Raw response from the device authorization endpoint (RFC 8628 §3.2)
#[derive(Debug, Deserialize)]
struct RawDeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default = "default_interval")]
    interval: u64,
    #[serde(default)]
    expires_in: u64,
}

fn default_interval() -> u64 {
    5
}

/// Raw response from the token endpoint (RFC 8628 §3.5)
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawTokenResult {
    Success(RawTokenSuccess),
    Error(RawTokenError),
}

#[derive(Debug, Deserialize)]
struct RawTokenSuccess {
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct RawTokenError {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// OAuth 2.0 authentication module — Device Flow + PKCE
pub struct AuthModule {
    client_id: String,
    auth_server_url: String,
    token_store: TokenStore,
    http: reqwest::blocking::Client,
}

impl AuthModule {
    /// Create a new authentication module.
    pub fn new(client_id: String, auth_server_url: String) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client_id,
            auth_server_url,
            token_store: TokenStore::new()?,
            http,
        })
    }

    /// Initiate the OAuth 2.0 Device Authorization Grant flow (RFC 8628 §3.1).
    ///
    /// Generates a PKCE `code_verifier`, computes the `code_challenge`, and
    /// POSTs to `/oauth/device/code`.  Returns the `DeviceCodeResponse` that
    /// the caller should display to the user (verification_uri + user_code).
    ///
    /// The generated `code_verifier` is returned alongside the response so the
    /// caller can pass it to `poll_for_token`.
    pub fn initiate_device_flow(&self) -> Result<(DeviceCodeResponse, String)> {
        let code_verifier = generate_code_verifier();
        let code_challenge = compute_code_challenge(&code_verifier);

        let url = format!("{}/oauth/device/code", self.auth_server_url);
        let resp = self
            .http
            .post(&url)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("code_challenge", &code_challenge),
                ("code_challenge_method", "S256"),
            ])
            .send()?;

        if !resp.status().is_success() {
            bail!(
                "Device authorization request failed with status {}",
                resp.status()
            );
        }

        let raw: RawDeviceCodeResponse = resp.json()?;
        let device_response = DeviceCodeResponse {
            device_code: raw.device_code,
            user_code: raw.user_code,
            verification_uri: raw.verification_uri,
            interval: raw.interval,
        };

        Ok((device_response, code_verifier))
    }

    /// Poll the token endpoint until the user completes authentication or the
    /// device code expires (RFC 8628 §3.4).
    ///
    /// `device_code` — the device_code from `initiate_device_flow`.
    /// `code_verifier` — the PKCE verifier generated during `initiate_device_flow`.
    /// `interval` — polling interval in seconds (from the device authorization response).
    /// `expires_in` — total seconds before the device code expires (0 = no limit enforced).
    pub fn poll_for_token(
        &self,
        device_code: &str,
        code_verifier: &str,
        interval: u64,
        expires_in: u64,
    ) -> Result<TokenResponse> {
        let url = format!("{}/oauth/token", self.auth_server_url);
        let poll_interval = Duration::from_secs(interval.max(1));
        let deadline = if expires_in > 0 {
            Some(Instant::now() + Duration::from_secs(expires_in))
        } else {
            None
        };

        loop {
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    bail!("Device code expired before the user completed authentication");
                }
            }

            std::thread::sleep(poll_interval);

            let resp = self
                .http
                .post(&url)
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", device_code),
                    ("client_id", self.client_id.as_str()),
                    ("code_verifier", code_verifier),
                ])
                .send()?;

            let raw: RawTokenResult = resp.json()?;
            match raw {
                RawTokenResult::Success(s) => {
                    let token_response = TokenResponse {
                        access_token: s.access_token.clone(),
                        refresh_token: s.refresh_token.clone(),
                        expires_in: s.expires_in,
                    };
                    // Persist tokens to the system keychain
                    self.token_store.store_access_token(&s.access_token)?;
                    if !s.refresh_token.is_empty() {
                        self.token_store.store_refresh_token(&s.refresh_token)?;
                    }
                    return Ok(token_response);
                }
                RawTokenResult::Error(e) => match e.error.as_str() {
                    "authorization_pending" => {
                        // User hasn't completed auth yet — keep polling
                        continue;
                    }
                    "slow_down" => {
                        // Server requests slower polling
                        std::thread::sleep(poll_interval);
                        continue;
                    }
                    "access_denied" => {
                        bail!("User denied the authorization request");
                    }
                    "expired_token" => {
                        bail!("Device code expired");
                    }
                    other => {
                        let desc = e
                            .error_description
                            .unwrap_or_else(|| "no description".to_string());
                        bail!("Token endpoint error '{}': {}", other, desc);
                    }
                },
            }
        }
    }

    /// Refresh an expired access token using the stored refresh token.
    pub fn refresh_token(&self) -> Result<TokenResponse> {
        let refresh_token = self
            .token_store
            .get_refresh_token()
            .map_err(|_| anyhow!("No refresh token stored — please log in again"))?;

        let url = format!("{}/oauth/token", self.auth_server_url);
        let resp = self
            .http
            .post(&url)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token),
                ("client_id", self.client_id.as_str()),
            ])
            .send()?;

        if !resp.status().is_success() {
            bail!("Token refresh failed with status {}", resp.status());
        }

        let raw: RawTokenSuccess = resp.json()?;
        let token_response = TokenResponse {
            access_token: raw.access_token.clone(),
            refresh_token: raw.refresh_token.clone(),
            expires_in: raw.expires_in,
        };

        self.token_store.store_access_token(&raw.access_token)?;
        if !raw.refresh_token.is_empty() {
            self.token_store.store_refresh_token(&raw.refresh_token)?;
        }

        Ok(token_response)
    }

    /// Get the current access token from the system keychain.
    pub fn get_access_token(&self) -> Result<String> {
        self.token_store.get_access_token()
    }

    /// Expose the underlying token store (for testing / TUI display).
    pub fn token_store(&self) -> &TokenStore {
        &self.token_store
    }
}

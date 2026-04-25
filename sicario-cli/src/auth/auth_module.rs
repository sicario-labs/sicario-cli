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

        // Retry up to 3 times on network errors with exponential backoff (1s, 2s, 4s)
        let mut last_err = None;
        let mut backoff = Duration::from_secs(1);
        for attempt in 0..4 {
            match self
                .http
                .post(&url)
                .form(&[
                    ("client_id", self.client_id.as_str()),
                    ("code_challenge", &code_challenge),
                    ("code_challenge_method", "S256"),
                ])
                .send()
            {
                Ok(resp) => {
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

                    return Ok((device_response, code_verifier));
                }
                Err(e) => {
                    // Only retry on network/connection errors, not HTTP status errors
                    if e.is_connect() || e.is_timeout() || e.is_request() {
                        last_err = Some(e);
                        if attempt < 3 {
                            eprintln!(
                                "  Network error, retrying in {}s (attempt {}/3)...",
                                backoff.as_secs(),
                                attempt + 1
                            );
                            std::thread::sleep(backoff);
                            backoff *= 2;
                            continue;
                        }
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }

        Err(last_err
            .map(|e| anyhow!("Device authorization request failed after 3 retries: {}", e))
            .unwrap_or_else(|| anyhow!("Device authorization request failed")))
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
        let mut current_interval = Duration::from_secs(interval.max(1));
        let max_interval = Duration::from_secs(30);
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

            std::thread::sleep(current_interval);

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
                        // RFC 8628 §3.5: double the interval on slow_down, capped at 30s
                        current_interval = (current_interval * 2).min(max_interval);
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
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                bail!("Your session has expired. Run `sicario login` to re-authenticate.");
            }
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

    // ── Cloud authentication methods ──────────────────────────────────────

    /// Perform a browser-based OAuth login for Sicario Cloud.
    ///
    /// Uses the existing device flow mechanism with cloud-specific configuration.
    /// The resulting token is stored as a cloud API token in the OS credential store.
    pub fn cloud_login(&self) -> Result<()> {
        let cloud_auth_url = std::env::var("SICARIO_CLOUD_AUTH_URL")
            .unwrap_or_else(|_| "https://flexible-terrier-680.convex.site".to_string());
        let cloud_client_id =
            std::env::var("SICARIO_CLOUD_CLIENT_ID").unwrap_or_else(|_| "sicario-cli".to_string());

        let code_verifier = super::pkce::generate_code_verifier();
        let code_challenge = super::pkce::compute_code_challenge(&code_verifier);

        let url = format!("{}/oauth/device/code", cloud_auth_url);
        let resp = self
            .http
            .post(&url)
            .form(&[
                ("client_id", cloud_client_id.as_str()),
                ("code_challenge", &code_challenge),
                ("code_challenge_method", "S256"),
                ("scope", "cloud"),
            ])
            .send();

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                bail!(
                    "Could not reach Sicario Cloud auth server at {cloud_auth_url}: {e}\n\
                     Sicario works fully offline — cloud features are optional."
                );
            }
        };

        if !resp.status().is_success() {
            bail!(
                "Cloud login request failed with status {}. \
                 Sicario works fully offline — cloud features are optional.",
                resp.status()
            );
        }

        let raw: RawDeviceCodeResponse = resp.json()?;

        eprintln!();
        eprintln!("  Open this URL in your browser to authenticate:");
        eprintln!("  {}", raw.verification_uri);
        eprintln!();
        eprintln!("  Enter code: {}", raw.user_code);
        eprintln!();

        // Poll for token
        let token_url = format!("{}/oauth/token", cloud_auth_url);
        let mut current_interval = Duration::from_secs(raw.interval.max(1));
        let max_interval = Duration::from_secs(30);
        let deadline = if raw.expires_in > 0 {
            Some(Instant::now() + Duration::from_secs(raw.expires_in))
        } else {
            Some(Instant::now() + Duration::from_secs(300)) // 5 min default
        };

        let polling_start = Instant::now();
        let mut last_progress = Instant::now();
        let progress_interval = Duration::from_secs(30);

        loop {
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    bail!("Login timed out — the device code expired before authentication completed.");
                }
            }

            // Print periodic progress message every 30 seconds
            if last_progress.elapsed() >= progress_interval {
                let elapsed = polling_start.elapsed().as_secs();
                eprintln!(
                    "  Still waiting for browser authentication... ({}s elapsed)",
                    elapsed
                );
                last_progress = Instant::now();
            }

            std::thread::sleep(current_interval);

            let resp = self
                .http
                .post(&token_url)
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", &raw.device_code),
                    ("client_id", cloud_client_id.as_str()),
                    ("code_verifier", &code_verifier),
                ])
                .send()?;

            let raw_result: RawTokenResult = resp.json()?;
            match raw_result {
                RawTokenResult::Success(s) => {
                    self.token_store.store_cloud_token(&s.access_token)?;

                    // Fetch user info to show "Authenticated as:"
                    let whoami_url = format!("{}/api/v1/whoami", cloud_auth_url.trim_end_matches('/'));
                    if let Ok(whoami_resp) = reqwest::blocking::Client::new()
                        .get(&whoami_url)
                        .header("Authorization", format!("Bearer {}", s.access_token))
                        .timeout(std::time::Duration::from_secs(5))
                        .send()
                    {
                        if whoami_resp.status().is_success() {
                            if let Ok(info) = whoami_resp.json::<serde_json::Value>() {
                                let user = info.get("username").and_then(|v| v.as_str()).unwrap_or("unknown");
                                let email = info.get("email").and_then(|v| v.as_str()).unwrap_or("");
                                let org = info.get("organization").and_then(|v| v.as_str()).unwrap_or("personal");
                                if !email.is_empty() {
                                    eprintln!("  Authenticated as: {} ({})", user, email);
                                } else {
                                    eprintln!("  Authenticated as: {}", user);
                                }
                                eprintln!("  Organization: {}", org);
                            } else {
                                eprintln!("  Logged in to Sicario Cloud successfully.");
                            }
                        } else {
                            eprintln!("  Logged in to Sicario Cloud successfully.");
                        }
                    } else {
                        eprintln!("  Logged in to Sicario Cloud successfully.");
                    }

                    return Ok(());
                }
                RawTokenResult::Error(e) => match e.error.as_str() {
                    "authorization_pending" => continue,
                    "slow_down" => {
                        // RFC 8628 §3.5: double the interval on slow_down, capped at 30s
                        current_interval = (current_interval * 2).min(max_interval);
                        continue;
                    }
                    "access_denied" => bail!("Login denied by user."),
                    "expired_token" => bail!("Device code expired."),
                    other => {
                        let desc = e
                            .error_description
                            .unwrap_or_else(|| "no description".to_string());
                        bail!("Cloud login error '{}': {}", other, desc);
                    }
                },
            }
        }
    }

    /// Log out of Sicario Cloud by removing the stored cloud API token.
    pub fn cloud_logout(&self) -> Result<()> {
        self.token_store.clear_cloud_token()?;
        Ok(())
    }

    /// Retrieve the currently authenticated cloud user's information.
    ///
    /// Calls `GET /api/v1/whoami` on the Sicario Cloud API.
    pub fn cloud_whoami(&self) -> Result<super::CloudUserInfo> {
        let cloud_url = std::env::var("SICARIO_CLOUD_URL")
            .unwrap_or_else(|_| "https://flexible-terrier-680.convex.site".to_string());

        let token = self
            .token_store
            .get_cloud_token()
            .map_err(|_| anyhow!("Not logged in to Sicario Cloud. Run `sicario login` first."))?;

        let url = format!("{}/api/v1/whoami", cloud_url.trim_end_matches('/'));
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send();

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                bail!(
                    "Could not reach Sicario Cloud API at {cloud_url}: {e}\n\
                     Check your network connection or try `sicario login` again."
                );
            }
        };

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            bail!("Cloud session expired or invalid. Run `sicario login` to re-authenticate.");
        }

        if !resp.status().is_success() {
            bail!("Cloud whoami request failed with status {}", resp.status());
        }

        let info: super::CloudUserInfo = resp.json()?;
        Ok(info)
    }

    /// Get the stored cloud API token, if any.
    pub fn get_cloud_token(&self) -> Result<String> {
        self.token_store.get_cloud_token()
    }

    /// Resolve the best available auth token for Convex API calls.
    ///
    /// Priority:
    /// 1. Cloud OAuth token → `"Bearer {token}"`
    /// 2. Project API key   → `"Bearer project:{key}"`
    /// 3. Error with instructions
    pub fn resolve_auth_token(&self) -> Result<String> {
        // 1. Try cloud OAuth token first (preferred)
        if let Ok(token) = self.token_store.get_cloud_token() {
            return Ok(format!("Bearer {}", token));
        }

        // 2. Fall back to project API key
        if let Ok(key) = self.token_store.get_project_api_key() {
            return Ok(format!("Bearer project:{}", key));
        }

        // 3. Neither credential available
        bail!("Run `sicario login` or set `SICARIO_PROJECT_API_KEY`")
    }
}

//! Cloud config fetcher — retrieves provider settings from the Sicario Cloud API.
//!
//! Used as the lowest-priority remote source in the resolution chain.
//! On any error (network, auth, parse), returns `None` and logs a warning
//! so the fix workflow is never blocked by cloud unavailability.
//!
//! Requirements: 9.4, 9.7

use serde::Deserialize;

/// Provider settings returned by `GET /api/v1/provider-settings`.
#[derive(Debug, Clone, Deserialize)]
pub struct CloudProviderSettings {
    pub provider_name: String,
    pub endpoint: String,
    pub model: String,
    pub has_api_key: bool,
}

/// Response from `GET /api/v1/provider-settings/key`.
#[derive(Debug, Clone, Deserialize)]
struct CloudKeyResponse {
    api_key: String,
}

/// Fetches provider settings from the Sicario Cloud API.
pub struct CloudConfigFetcher {
    base_url: String,
    token: String,
    client: reqwest::blocking::Client,
}

impl CloudConfigFetcher {
    /// Create a new fetcher with a 5-second timeout.
    pub fn new(base_url: &str, token: &str) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            client,
        }
    }

    /// Fetch provider settings (endpoint, model, has_api_key).
    ///
    /// Returns `None` if not configured, unauthenticated, or on any error.
    pub fn fetch_settings(&self) -> Option<CloudProviderSettings> {
        let url = format!("{}/api/v1/provider-settings", self.base_url);
        match self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
        {
            Ok(resp) if resp.status().is_success() => match resp.json::<CloudProviderSettings>() {
                Ok(settings) => Some(settings),
                Err(e) => {
                    eprintln!("sicario: warning — failed to parse cloud provider settings: {e}");
                    None
                }
            },
            Ok(resp) => {
                eprintln!(
                    "sicario: warning — cloud provider settings request returned {}",
                    resp.status()
                );
                None
            }
            Err(e) => {
                eprintln!("sicario: warning — could not reach cloud API: {e}");
                None
            }
        }
    }

    /// Fetch the decrypted API key from the cloud.
    ///
    /// Returns `None` if no key is stored, unauthenticated, or on any error.
    pub fn fetch_api_key(&self) -> Option<String> {
        let url = format!("{}/api/v1/provider-settings/key", self.base_url);
        match self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
        {
            Ok(resp) if resp.status().is_success() => match resp.json::<CloudKeyResponse>() {
                Ok(key_resp) if !key_resp.api_key.is_empty() => Some(key_resp.api_key),
                Ok(_) => None,
                Err(e) => {
                    eprintln!("sicario: warning — failed to parse cloud API key response: {e}");
                    None
                }
            },
            Ok(resp) => {
                eprintln!(
                    "sicario: warning — cloud API key request returned {}",
                    resp.status()
                );
                None
            }
            Err(e) => {
                eprintln!("sicario: warning — could not reach cloud API for key: {e}");
                None
            }
        }
    }
}

/// Try to build a `CloudConfigFetcher` from the current auth state.
///
/// Returns `None` if the user is not authenticated (no cloud token stored).
pub fn try_cloud_fetcher() -> Option<CloudConfigFetcher> {
    let token_store = crate::auth::TokenStore::new().ok()?;
    let token = token_store.get_cloud_token().ok()?;
    if token.is_empty() {
        return None;
    }
    let base_url = std::env::var("SICARIO_CLOUD_URL")
        .unwrap_or_else(|_| "https://flexible-terrier-680.convex.site".to_string());
    Some(CloudConfigFetcher::new(&base_url, &token))
}

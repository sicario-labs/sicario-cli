//! Secure token storage using system keychain

use anyhow::{Context, Result};
use keyring::Entry;

/// Helpful error message shown when keychain operations fail (e.g. headless CI).
const KEYCHAIN_ERROR_HINT: &str =
    "Could not access system keychain. If running in CI, use SICARIO_API_TOKEN environment variable instead.";

/// Maximum reasonable token length — anything larger is almost certainly corrupted.
const MAX_TOKEN_LEN: usize = 10_000;

/// Validate that a retrieved token is non-empty and within a reasonable size.
fn validate_token(token: &str, label: &str) -> Result<()> {
    if token.is_empty() {
        anyhow::bail!("{label} retrieved from keychain is empty — it may be corrupted. Try re-authenticating with `sicario login`.");
    }
    if token.len() > MAX_TOKEN_LEN {
        anyhow::bail!(
            "{label} retrieved from keychain is unreasonably large ({} chars) — it may be corrupted. Try re-authenticating with `sicario login`.",
            token.len()
        );
    }
    Ok(())
}

/// Secure token storage
pub struct TokenStore {
    service_name: String,
    /// Optional in-memory override used exclusively in tests to avoid
    /// touching the system keychain.
    #[cfg(test)]
    memory: Option<std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>>,
}

impl TokenStore {
    /// Create a new token store using the default "sicario-cli" service name.
    pub fn new() -> Result<Self> {
        Ok(Self {
            service_name: "sicario-cli".to_string(),
            #[cfg(test)]
            memory: None,
        })
    }

    /// Create a token store with a custom service name.
    pub fn with_service_name(service_name: impl Into<String>) -> Result<Self> {
        Ok(Self {
            service_name: service_name.into(),
            #[cfg(test)]
            memory: None,
        })
    }

    /// Create an in-memory token store that never touches the system keychain.
    ///
    /// Intended for property-based tests where we want to validate the
    /// round-trip contract without depending on platform keychain availability.
    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self {
            service_name: "test".to_string(),
            memory: Some(std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            ))),
        }
    }

    /// Store an access token securely
    pub fn store_access_token(&self, token: &str) -> Result<()> {
        #[cfg(test)]
        if let Some(ref mem) = self.memory {
            mem.lock()
                .unwrap()
                .insert("access_token".to_string(), token.to_string());
            return Ok(());
        }
        let entry = Entry::new(&self.service_name, "access_token").context(KEYCHAIN_ERROR_HINT)?;
        entry.set_password(token).context(KEYCHAIN_ERROR_HINT)?;
        Ok(())
    }

    /// Retrieve the stored access token
    pub fn get_access_token(&self) -> Result<String> {
        #[cfg(test)]
        if let Some(ref mem) = self.memory {
            return mem
                .lock()
                .unwrap()
                .get("access_token")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("No access token in memory store"));
        }
        let entry = Entry::new(&self.service_name, "access_token").context(KEYCHAIN_ERROR_HINT)?;
        let token = entry.get_password().context(KEYCHAIN_ERROR_HINT)?;
        validate_token(&token, "Access token")?;
        Ok(token)
    }

    /// Store a refresh token securely
    pub fn store_refresh_token(&self, token: &str) -> Result<()> {
        #[cfg(test)]
        if let Some(ref mem) = self.memory {
            mem.lock()
                .unwrap()
                .insert("refresh_token".to_string(), token.to_string());
            return Ok(());
        }
        let entry = Entry::new(&self.service_name, "refresh_token").context(KEYCHAIN_ERROR_HINT)?;
        entry.set_password(token).context(KEYCHAIN_ERROR_HINT)?;
        Ok(())
    }

    /// Retrieve the stored refresh token
    pub fn get_refresh_token(&self) -> Result<String> {
        #[cfg(test)]
        if let Some(ref mem) = self.memory {
            return mem
                .lock()
                .unwrap()
                .get("refresh_token")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("No refresh token in memory store"));
        }
        let entry = Entry::new(&self.service_name, "refresh_token").context(KEYCHAIN_ERROR_HINT)?;
        let token = entry.get_password().context(KEYCHAIN_ERROR_HINT)?;
        validate_token(&token, "Refresh token")?;
        Ok(token)
    }

    /// Clear all stored tokens
    pub fn clear_tokens(&self) -> Result<()> {
        #[cfg(test)]
        if let Some(ref mem) = self.memory {
            mem.lock().unwrap().clear();
            return Ok(());
        }
        let access_entry =
            Entry::new(&self.service_name, "access_token").context(KEYCHAIN_ERROR_HINT)?;
        let refresh_entry =
            Entry::new(&self.service_name, "refresh_token").context(KEYCHAIN_ERROR_HINT)?;

        let _ = access_entry.delete_password();
        let _ = refresh_entry.delete_password();

        Ok(())
    }

    // ── Cloud API token methods ───────────────────────────────────────────

    /// Store a cloud API token securely.
    pub fn store_cloud_token(&self, token: &str) -> Result<()> {
        #[cfg(test)]
        if let Some(ref mem) = self.memory {
            mem.lock()
                .unwrap()
                .insert("cloud_api_token".to_string(), token.to_string());
            return Ok(());
        }
        let entry =
            Entry::new(&self.service_name, "cloud_api_token").context(KEYCHAIN_ERROR_HINT)?;
        entry.set_password(token).context(KEYCHAIN_ERROR_HINT)?;
        Ok(())
    }

    /// Retrieve the stored cloud API token.
    pub fn get_cloud_token(&self) -> Result<String> {
        #[cfg(test)]
        if let Some(ref mem) = self.memory {
            return mem
                .lock()
                .unwrap()
                .get("cloud_api_token")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("No cloud API token in memory store"));
        }
        let entry =
            Entry::new(&self.service_name, "cloud_api_token").context(KEYCHAIN_ERROR_HINT)?;
        let token = entry.get_password().context(KEYCHAIN_ERROR_HINT)?;
        validate_token(&token, "Cloud API token")?;
        Ok(token)
    }

    /// Remove the stored cloud API token.
    pub fn clear_cloud_token(&self) -> Result<()> {
        #[cfg(test)]
        if let Some(ref mem) = self.memory {
            mem.lock().unwrap().remove("cloud_api_token");
            return Ok(());
        }
        let entry =
            Entry::new(&self.service_name, "cloud_api_token").context(KEYCHAIN_ERROR_HINT)?;
        let _ = entry.delete_password();
        Ok(())
    }

    // ── Project API key methods ───────────────────────────────────────────

    /// Store a project API key securely.
    pub fn store_project_api_key(&self, key: &str) -> Result<()> {
        #[cfg(test)]
        if let Some(ref mem) = self.memory {
            mem.lock()
                .unwrap()
                .insert("project_api_key".to_string(), key.to_string());
            return Ok(());
        }
        let entry =
            Entry::new(&self.service_name, "project_api_key").context(KEYCHAIN_ERROR_HINT)?;
        entry.set_password(key).context(KEYCHAIN_ERROR_HINT)?;
        Ok(())
    }

    /// Retrieve the project API key.
    ///
    /// Checks the `SICARIO_PROJECT_API_KEY` environment variable first,
    /// falling back to the system keychain.
    pub fn get_project_api_key(&self) -> Result<String> {
        // Environment variable takes precedence
        if let Ok(key) = std::env::var("SICARIO_PROJECT_API_KEY") {
            if !key.is_empty() {
                return Ok(key);
            }
        }

        #[cfg(test)]
        if let Some(ref mem) = self.memory {
            return mem
                .lock()
                .unwrap()
                .get("project_api_key")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("No project API key in memory store"));
        }
        let entry =
            Entry::new(&self.service_name, "project_api_key").context(KEYCHAIN_ERROR_HINT)?;
        let key = entry.get_password().context(KEYCHAIN_ERROR_HINT)?;
        validate_token(&key, "Project API key")?;
        Ok(key)
    }

    /// Remove the stored project API key.
    pub fn clear_project_api_key(&self) -> Result<()> {
        #[cfg(test)]
        if let Some(ref mem) = self.memory {
            mem.lock().unwrap().remove("project_api_key");
            return Ok(());
        }
        let entry =
            Entry::new(&self.service_name, "project_api_key").context(KEYCHAIN_ERROR_HINT)?;
        let _ = entry.delete_password();
        Ok(())
    }
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new().expect("Failed to create token store")
    }
}

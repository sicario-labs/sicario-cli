//! Secure token storage using system keychain

use anyhow::Result;
use keyring::Entry;

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
        let entry = Entry::new(&self.service_name, "access_token")?;
        entry.set_password(token)?;
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
        let entry = Entry::new(&self.service_name, "access_token")?;
        Ok(entry.get_password()?)
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
        let entry = Entry::new(&self.service_name, "refresh_token")?;
        entry.set_password(token)?;
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
        let entry = Entry::new(&self.service_name, "refresh_token")?;
        Ok(entry.get_password()?)
    }

    /// Clear all stored tokens
    pub fn clear_tokens(&self) -> Result<()> {
        #[cfg(test)]
        if let Some(ref mem) = self.memory {
            mem.lock().unwrap().clear();
            return Ok(());
        }
        let access_entry = Entry::new(&self.service_name, "access_token")?;
        let refresh_entry = Entry::new(&self.service_name, "refresh_token")?;

        let _ = access_entry.delete_password();
        let _ = refresh_entry.delete_password();

        Ok(())
    }
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new().expect("Failed to create token store")
    }
}

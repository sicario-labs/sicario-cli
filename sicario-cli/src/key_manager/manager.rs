//! API key resolution with layered precedence.
//!
//! Resolution order:
//!   1. `SICARIO_LLM_API_KEY` env var (highest priority — explicit Sicario config)
//!   2. OS keyring via `keyring` crate (set by `sicario config set-key`)
//!   3. `OPENAI_API_KEY` env var (de facto standard — most devs already have this)
//!   4. `CEREBRAS_API_KEY` env var (backward compatibility)
//!   5. `.sicario/config.yaml` (local config file)
//!   6. Cloud config (authenticated users only — lowest-priority remote source)
//!
//! Requirements: 20.1–20.8, 1.1–1.7, 9.1–9.8

use anyhow::{anyhow, Result};

use super::cloud_config::try_cloud_fetcher;
use super::config_file::load_config_file;

const KEYRING_SERVICE: &str = "sicario-cli";
const KEYRING_USER: &str = "llm-api-key";

/// Describes where a resolved configuration value came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    EnvVar(String),
    Keyring,
    ConfigFile,
    CloudConfig,
    Default,
}

impl ConfigSource {
    pub fn label(&self) -> &str {
        match self {
            Self::EnvVar(name) => name.as_str(),
            Self::Keyring => "OS keyring",
            Self::ConfigFile => ".sicario/config.yaml",
            Self::CloudConfig => "cloud",
            Self::Default => "default",
        }
    }
}

/// A resolved value together with its source.
#[derive(Debug, Clone)]
pub struct ResolvedValue {
    pub value: String,
    pub source: ConfigSource,
}

/// Describes where the resolved key came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    EnvSicario,
    Keyring,
    EnvOpenAi,
    EnvCerebras,
    ConfigFile,
    CloudConfig,
    None,
}

impl KeySource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::EnvSicario => "SICARIO_LLM_API_KEY",
            Self::Keyring => "OS keyring",
            Self::EnvOpenAi => "OPENAI_API_KEY",
            Self::EnvCerebras => "CEREBRAS_API_KEY",
            Self::ConfigFile => ".sicario/config.yaml",
            Self::CloudConfig => "cloud",
            Self::None => "not configured",
        }
    }
}

/// Result of key resolution — the key value and where it came from.
#[derive(Debug, Clone)]
pub struct ResolvedKey {
    pub key: String,
    pub source: KeySource,
}

/// Resolve the LLM API key using the precedence chain.
pub fn resolve_api_key() -> Option<ResolvedKey> {
    // 1. SICARIO_LLM_API_KEY
    if let Ok(key) = std::env::var("SICARIO_LLM_API_KEY") {
        if !key.is_empty() {
            return Some(ResolvedKey {
                key,
                source: KeySource::EnvSicario,
            });
        }
    }

    // 2. OS keyring
    if let Some(key) = read_keyring() {
        return Some(ResolvedKey {
            key,
            source: KeySource::Keyring,
        });
    }

    // 3. OPENAI_API_KEY (de facto standard)
    if let Ok(key) = std::env::var("OPENAI_API_KEY") {
        if !key.is_empty() {
            return Some(ResolvedKey {
                key,
                source: KeySource::EnvOpenAi,
            });
        }
    }

    // 4. CEREBRAS_API_KEY (backward compat)
    if let Ok(key) = std::env::var("CEREBRAS_API_KEY") {
        if !key.is_empty() {
            return Some(ResolvedKey {
                key,
                source: KeySource::EnvCerebras,
            });
        }
    }

    // 5. Config file
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    if let Some(cfg) = load_config_file(&cwd) {
        if let Some(key) = cfg.key {
            if !key.is_empty() {
                return Some(ResolvedKey {
                    key,
                    source: KeySource::ConfigFile,
                });
            }
        }
    }

    // 6. Cloud config (authenticated users only)
    if let Some(fetcher) = try_cloud_fetcher() {
        if let Some(key) = fetcher.fetch_api_key() {
            return Some(ResolvedKey {
                key,
                source: KeySource::CloudConfig,
            });
        }
    }

    None
}

/// Resolve the LLM endpoint URL.
///
/// Precedence:
///   1. `SICARIO_LLM_ENDPOINT` env var
///   2. `OPENAI_BASE_URL` env var (standard for OpenAI-compatible tools)
///   3. `CEREBRAS_ENDPOINT` env var (backward compat)
///   4. `.sicario/config.yaml` → `endpoint`
///   5. Default: OpenAI API
pub fn resolve_endpoint() -> String {
    resolve_endpoint_with_source().value
}

/// Resolve the LLM endpoint URL, returning both the value and its source.
pub fn resolve_endpoint_with_source() -> ResolvedValue {
    if let Ok(ep) = std::env::var("SICARIO_LLM_ENDPOINT") {
        if !ep.is_empty() {
            return ResolvedValue {
                value: ep,
                source: ConfigSource::EnvVar("SICARIO_LLM_ENDPOINT".into()),
            };
        }
    }
    if let Ok(ep) = std::env::var("OPENAI_BASE_URL") {
        if !ep.is_empty() {
            let value = if ep.ends_with("/chat/completions") {
                ep
            } else {
                format!("{}/chat/completions", ep.trim_end_matches('/'))
            };
            return ResolvedValue {
                value,
                source: ConfigSource::EnvVar("OPENAI_BASE_URL".into()),
            };
        }
    }
    if let Ok(ep) = std::env::var("CEREBRAS_ENDPOINT") {
        if !ep.is_empty() {
            return ResolvedValue {
                value: ep,
                source: ConfigSource::EnvVar("CEREBRAS_ENDPOINT".into()),
            };
        }
    }

    // 4. Config file
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    if let Some(cfg) = load_config_file(&cwd) {
        if let Some(ep) = cfg.endpoint {
            if !ep.is_empty() {
                return ResolvedValue {
                    value: ep,
                    source: ConfigSource::ConfigFile,
                };
            }
        }
    }

    // 5. Cloud config (authenticated users only)
    if let Some(fetcher) = try_cloud_fetcher() {
        if let Some(settings) = fetcher.fetch_settings() {
            if !settings.endpoint.is_empty() {
                return ResolvedValue {
                    value: settings.endpoint,
                    source: ConfigSource::CloudConfig,
                };
            }
        }
    }

    ResolvedValue {
        value: "https://api.openai.com/v1/chat/completions".to_string(),
        source: ConfigSource::Default,
    }
}

/// Resolve the LLM model name.
///
/// Precedence:
///   1. `SICARIO_LLM_MODEL` env var
///   2. `CEREBRAS_MODEL` env var (backward compat)
///   3. `.sicario/config.yaml` → `model`
///   4. Default: `gpt-4o-mini`
pub fn resolve_model() -> String {
    resolve_model_with_source().value
}

/// Resolve the LLM model name, returning both the value and its source.
pub fn resolve_model_with_source() -> ResolvedValue {
    if let Ok(m) = std::env::var("SICARIO_LLM_MODEL") {
        if !m.is_empty() {
            return ResolvedValue {
                value: m,
                source: ConfigSource::EnvVar("SICARIO_LLM_MODEL".into()),
            };
        }
    }
    if let Ok(m) = std::env::var("CEREBRAS_MODEL") {
        if !m.is_empty() {
            return ResolvedValue {
                value: m,
                source: ConfigSource::EnvVar("CEREBRAS_MODEL".into()),
            };
        }
    }

    // 3. Config file
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    if let Some(cfg) = load_config_file(&cwd) {
        if let Some(m) = cfg.model {
            if !m.is_empty() {
                return ResolvedValue {
                    value: m,
                    source: ConfigSource::ConfigFile,
                };
            }
        }
    }

    // 4. Cloud config (authenticated users only)
    if let Some(fetcher) = try_cloud_fetcher() {
        if let Some(settings) = fetcher.fetch_settings() {
            if !settings.model.is_empty() {
                return ResolvedValue {
                    value: settings.model,
                    source: ConfigSource::CloudConfig,
                };
            }
        }
    }

    ResolvedValue {
        value: "gpt-4o-mini".to_string(),
        source: ConfigSource::Default,
    }
}

// ── Keyring operations ────────────────────────────────────────────────────────

fn read_keyring() -> Option<String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER).ok()?;
    entry.get_password().ok()
}

/// Store an API key in the OS keyring.
pub fn store_key_in_keyring(key: &str) -> Result<()> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| anyhow!("Failed to access keyring: {e}"))?;
    entry
        .set_password(key)
        .map_err(|e| anyhow!("Failed to store key in keyring: {e}"))
}

/// Delete the API key from the OS keyring.
pub fn delete_key_from_keyring() -> Result<()> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| anyhow!("Failed to access keyring: {e}"))?;
    entry
        .delete_password()
        .map_err(|e| anyhow!("Failed to delete key from keyring: {e}"))
}

/// Check whether a key exists in the OS keyring (without revealing it).
pub fn keyring_has_key() -> bool {
    read_keyring().is_some()
}

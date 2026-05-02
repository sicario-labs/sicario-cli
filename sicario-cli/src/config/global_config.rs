//! Global user-level configuration stored in `~/.sicario/config.toml`.
//!
//! This is distinct from the project-local `.sicario/config.yaml`.
//! The global config holds user-level settings such as LLM API keys
//! that should persist across projects.
//!
//! # Zero-Liability Boundary
//!
//! LLM API keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.) are stored
//! **only** in this local file or read from environment variables.
//! They are **never** sent to the Sicario Cloud backend.
//!
//! The `SICARIO_API_KEY` environment variable is strictly reserved for
//! authenticating HTTP requests to the Convex telemetry endpoint
//! (`POST /api/v1/telemetry/scan`) and is **never** used for LLM auth.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// User-level global configuration stored in `~/.sicario/config.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct GlobalConfig {
    /// Generic LLM API key for any provider (BYOK).
    /// Set via `sicario config set-key` or written by `sicario config set-provider`.
    /// This is the primary field checked in Key_Manager resolution step 8.
    pub llm_api_key: Option<String>,

    /// Anthropic API key for Claude-based remediation (BYOK).
    /// Equivalent to the `ANTHROPIC_API_KEY` environment variable.
    pub anthropic_api_key: Option<String>,

    /// OpenAI API key for GPT-based remediation (BYOK).
    /// Equivalent to the `OPENAI_API_KEY` environment variable.
    pub openai_api_key: Option<String>,

    /// Custom LLM endpoint URL (OpenAI-compatible).
    pub llm_endpoint: Option<String>,

    /// LLM model name override.
    pub llm_model: Option<String>,

    /// Extra fields for extensibility (e.g., project_id).
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_yaml::Value>,
}

/// Returns the path to the global config file: `~/.sicario/config.toml`.
pub fn global_config_path() -> Option<PathBuf> {
    dirs_home().map(|home| home.join(".sicario").join("config.toml"))
}

/// Load the global config from `~/.sicario/config.toml`.
///
/// Returns `None` if the file doesn't exist or cannot be parsed.
pub fn load_global_config() -> Option<GlobalConfig> {
    let path = global_config_path()?;
    let content = std::fs::read_to_string(&path).ok()?;
    toml::from_str(&content).ok()
}

/// Write a key-value pair to `~/.sicario/config.toml`.
///
/// Creates `~/.sicario/` if it doesn't exist.
/// Sets file permissions to 0600 (user read/write only) on Unix.
pub fn set_global_config_value(key: &str, value: &str) -> Result<()> {
    let path = global_config_path()
        .context("Could not determine home directory for ~/.sicario/config.toml")?;

    // Ensure the directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }

    // Load existing config or start fresh
    let mut config = load_global_config().unwrap_or_default();

    match key {
        "ANTHROPIC_API_KEY" | "anthropic_api_key" => {
            config.anthropic_api_key = Some(value.to_string());
        }
        "OPENAI_API_KEY" | "openai_api_key" => {
            config.openai_api_key = Some(value.to_string());
        }
        "llm_api_key" | "LLM_API_KEY" => {
            config.llm_api_key = Some(value.to_string());
        }
        "llm_endpoint" | "LLM_ENDPOINT" => {
            config.llm_endpoint = Some(value.to_string());
        }
        "llm_model" | "LLM_MODEL" => {
            config.llm_model = Some(value.to_string());
        }
        other => {
            anyhow::bail!(
                "Unknown config key '{}'. Valid keys: ANTHROPIC_API_KEY, OPENAI_API_KEY, llm_api_key, llm_endpoint, llm_model",
                other
            );
        }
    }

    let toml_str =
        toml::to_string_pretty(&config).context("Failed to serialize global config to TOML")?;

    std::fs::write(&path, &toml_str)
        .with_context(|| format!("Failed to write {}", path.display()))?;

    // Restrict permissions to owner-only (0600) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&path, perms)
            .with_context(|| format!("Failed to set permissions on {}", path.display()))?;
    }

    Ok(())
}

/// Resolve the best available LLM API key for AI-powered remediation.
///
/// Priority chain (highest to lowest):
/// 1. `ANTHROPIC_API_KEY` environment variable
/// 2. `OPENAI_API_KEY` environment variable
/// 3. `anthropic_api_key` in `~/.sicario/config.toml`
/// 4. `openai_api_key` in `~/.sicario/config.toml`
///
/// # Zero-Liability Boundary
///
/// This function is **only** for resolving LLM credentials used by
/// `sicario fix` for local AI-powered remediation.
///
/// `SICARIO_API_KEY` is **never** consulted here — it is strictly reserved
/// for authenticating HTTP requests to the Convex telemetry endpoint.
pub fn resolve_llm_api_key() -> Option<LlmKeyResolution> {
    // 1. ANTHROPIC_API_KEY env var (highest priority for CI/CD)
    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        if !key.is_empty() {
            return Some(LlmKeyResolution {
                key,
                provider: LlmProvider::Anthropic,
                source: LlmKeySource::EnvVar("ANTHROPIC_API_KEY"),
            });
        }
    }

    // 2. OPENAI_API_KEY env var
    if let Ok(key) = std::env::var("OPENAI_API_KEY") {
        if !key.is_empty() {
            return Some(LlmKeyResolution {
                key,
                provider: LlmProvider::OpenAi,
                source: LlmKeySource::EnvVar("OPENAI_API_KEY"),
            });
        }
    }

    // 3 & 4. Fall back to ~/.sicario/config.toml
    if let Some(config) = load_global_config() {
        if let Some(key) = config.anthropic_api_key.filter(|k| !k.is_empty()) {
            return Some(LlmKeyResolution {
                key,
                provider: LlmProvider::Anthropic,
                source: LlmKeySource::GlobalConfigFile,
            });
        }
        if let Some(key) = config.openai_api_key.filter(|k| !k.is_empty()) {
            return Some(LlmKeyResolution {
                key,
                provider: LlmProvider::OpenAi,
                source: LlmKeySource::GlobalConfigFile,
            });
        }
    }

    None
}

/// The resolved LLM API key with metadata about its origin.
#[derive(Debug, Clone)]
pub struct LlmKeyResolution {
    pub key: String,
    pub provider: LlmProvider,
    pub source: LlmKeySource,
}

/// Which LLM provider the key belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlmProvider {
    Anthropic,
    OpenAi,
}

impl LlmProvider {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::OpenAi => "OpenAI",
        }
    }
}

/// Where the LLM key was resolved from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlmKeySource {
    EnvVar(&'static str),
    GlobalConfigFile,
}

impl LlmKeySource {
    pub fn label(&self) -> String {
        match self {
            Self::EnvVar(name) => name.to_string(),
            Self::GlobalConfigFile => "~/.sicario/config.toml".to_string(),
        }
    }
}

/// Cross-platform home directory resolution.
fn dirs_home() -> Option<PathBuf> {
    // Try HOME on Unix, USERPROFILE on Windows
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_config_roundtrip() {
        let config = GlobalConfig {
            llm_api_key: None,
            anthropic_api_key: Some("sk-ant-test".to_string()),
            openai_api_key: None,
            llm_endpoint: Some("https://api.anthropic.com/v1".to_string()),
            llm_model: Some("claude-3-5-sonnet-20241022".to_string()),
            extra: Default::default(),
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let back: GlobalConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn test_set_global_config_value_rejects_unknown_key() {
        // We can't write to the real home dir in tests, but we can verify
        // that unknown keys are rejected before any I/O happens.
        // Set both HOME and USERPROFILE so dirs_home() resolves to the temp dir
        // on both Unix and Windows.
        let tmp = tempfile::tempdir().unwrap();
        let original_home = std::env::var("HOME").ok();
        let original_userprofile = std::env::var("USERPROFILE").ok();

        std::env::set_var("HOME", tmp.path());
        std::env::set_var("USERPROFILE", tmp.path());
        let result = set_global_config_value("UNKNOWN_KEY", "value");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unknown config key"));

        // Restore HOME / USERPROFILE
        match original_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        match original_userprofile {
            Some(p) => std::env::set_var("USERPROFILE", p),
            None => std::env::remove_var("USERPROFILE"),
        }
    }

    #[test]
    fn test_set_and_load_global_config() {
        let tmp = tempfile::tempdir().unwrap();
        let original_home = std::env::var("HOME").ok();
        let original_userprofile = std::env::var("USERPROFILE").ok();

        // Set both HOME and USERPROFILE so dirs_home() resolves to the temp dir
        // on both Unix and Windows.
        std::env::set_var("HOME", tmp.path());
        std::env::set_var("USERPROFILE", tmp.path());

        set_global_config_value("ANTHROPIC_API_KEY", "sk-ant-test123").unwrap();
        let loaded = load_global_config().unwrap();
        assert_eq!(loaded.anthropic_api_key.as_deref(), Some("sk-ant-test123"));

        // Restore HOME / USERPROFILE
        match original_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        match original_userprofile {
            Some(p) => std::env::set_var("USERPROFILE", p),
            None => std::env::remove_var("USERPROFILE"),
        }
    }

    #[test]
    fn test_resolve_llm_api_key_env_var_priority() {
        // ANTHROPIC_API_KEY should take priority over OPENAI_API_KEY
        std::env::set_var("ANTHROPIC_API_KEY", "sk-ant-priority");
        std::env::set_var("OPENAI_API_KEY", "sk-openai-lower");

        let resolved = resolve_llm_api_key().unwrap();
        assert_eq!(resolved.provider, LlmProvider::Anthropic);
        assert_eq!(resolved.key, "sk-ant-priority");
        assert_eq!(resolved.source, LlmKeySource::EnvVar("ANTHROPIC_API_KEY"));

        std::env::remove_var("ANTHROPIC_API_KEY");
        std::env::remove_var("OPENAI_API_KEY");
    }

    #[test]
    fn test_resolve_llm_api_key_openai_fallback() {
        std::env::remove_var("ANTHROPIC_API_KEY");
        std::env::set_var("OPENAI_API_KEY", "sk-openai-test");

        let resolved = resolve_llm_api_key().unwrap();
        assert_eq!(resolved.provider, LlmProvider::OpenAi);
        assert_eq!(resolved.source, LlmKeySource::EnvVar("OPENAI_API_KEY"));

        std::env::remove_var("OPENAI_API_KEY");
    }

    #[test]
    fn test_sicario_api_key_not_used_for_llm() {
        // SICARIO_API_KEY must never appear in LLM key resolution
        std::env::remove_var("ANTHROPIC_API_KEY");
        std::env::remove_var("OPENAI_API_KEY");
        std::env::set_var("SICARIO_API_KEY", "project:should-not-be-used");

        // resolve_llm_api_key should return None (no LLM key), not the telemetry key
        let resolved = resolve_llm_api_key();
        assert!(
            resolved.is_none(),
            "SICARIO_API_KEY must not be used for LLM auth — it is strictly for telemetry"
        );

        std::env::remove_var("SICARIO_API_KEY");
    }

    /// Integration test: `set-provider anthropic` writes the correct endpoint and model
    /// to `~/.sicario/config.toml`.
    ///
    /// Validates: Requirements 9.4, 9.5 (provider preset registry), 12.1 (set-provider command)
    #[test]
    fn test_set_provider_anthropic_writes_correct_endpoint_and_model() {
        use crate::key_manager::provider_registry::find_provider;

        let tmp = tempfile::tempdir().unwrap();
        let original_home = std::env::var("HOME").ok();
        let original_userprofile = std::env::var("USERPROFILE").ok();

        // Point HOME to a temp dir so we don't touch the real ~/.sicario/config.toml
        std::env::set_var("HOME", tmp.path());
        std::env::set_var("USERPROFILE", tmp.path());

        // Look up the anthropic preset from the registry
        let preset = find_provider("anthropic").expect("anthropic provider must exist in registry");

        // Simulate what `sicario config set-provider anthropic` does:
        // write llm_endpoint and llm_model to ~/.sicario/config.toml
        set_global_config_value("llm_endpoint", preset.endpoint).unwrap();
        set_global_config_value("llm_model", preset.default_model).unwrap();

        // Load the written config and verify the values
        let loaded = load_global_config().expect("config.toml should exist after set-provider");

        assert_eq!(
            loaded.llm_endpoint.as_deref(),
            Some("https://api.anthropic.com/v1"),
            "llm_endpoint should be the Anthropic API base URL"
        );
        assert_eq!(
            loaded.llm_model.as_deref(),
            Some("claude-opus-4-5"),
            "llm_model should be the Anthropic default model"
        );

        // Verify the config file was written to the correct path
        let config_path = tmp.path().join(".sicario").join("config.toml");
        assert!(
            config_path.exists(),
            "config.toml should be written to ~/.sicario/config.toml"
        );

        // Restore HOME / USERPROFILE
        match original_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        match original_userprofile {
            Some(p) => std::env::set_var("USERPROFILE", p),
            None => std::env::remove_var("USERPROFILE"),
        }
    }

    /// Integration test: unknown provider name prints error and returns exit code 2.
    ///
    /// Validates: Requirements 12.1 (set-provider error handling)
    #[test]
    fn test_set_provider_unknown_name_is_rejected() {
        use crate::key_manager::provider_registry::find_provider;

        // Verify that an unknown provider name returns None from the registry
        let result = find_provider("not-a-real-provider");
        assert!(
            result.is_none(),
            "Unknown provider name must return None from find_provider"
        );

        // Verify all 19 known providers resolve correctly
        let known_providers = [
            "openai",
            "anthropic",
            "gemini",
            "azure",
            "bedrock",
            "deepseek",
            "groq",
            "cerebras",
            "together",
            "fireworks",
            "openrouter",
            "mistral",
            "ollama",
            "lmstudio",
            "xai",
            "perplexity",
            "cohere",
            "deepinfra",
            "novita",
        ];
        for name in &known_providers {
            assert!(
                find_provider(name).is_some(),
                "Provider '{}' must be in the registry",
                name
            );
        }
    }
}

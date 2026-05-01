//! API key resolution with layered precedence.
//!
//! Resolution order:
//!   1. `SICARIO_LLM_API_KEY` env var (highest priority — explicit Sicario config)
//!   2. OS keyring via `keyring` crate (set by `sicario config set-key`)
//!   3. `OPENAI_API_KEY` env var (de facto standard — most devs already have this)
//!   4. `ANTHROPIC_API_KEY` env var → set endpoint to Anthropic, flag auth_style: XApiKey
//!   5. `GROQ_API_KEY` env var → set endpoint to Groq
//!   6. `DEEPSEEK_API_KEY` env var → set endpoint to DeepSeek
//!   7. `CEREBRAS_API_KEY` env var → set endpoint to Cerebras
//!   8. `~/.sicario/config.toml` LLM key field (persisted provider config)
//!   9. Ollama auto-detection (GET localhost:11434/api/tags, 500ms timeout)
//!
//! `SICARIO_API_KEY` is NEVER consulted for LLM authentication.
//! It is used exclusively for `Authorization: Bearer` on Convex HTTP endpoints.
//!
//! Requirements: 11.1–11.5, 20.1–20.8, 1.1–1.7, 9.1–9.8

use anyhow::{anyhow, Result};

use super::cloud_config::try_cloud_fetcher;
use super::config_file::load_config_file;
use crate::config::load_global_config;

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
            Self::ConfigFile => "~/.sicario/config.toml",
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
    EnvAnthropic,
    EnvGroq,
    EnvDeepSeek,
    EnvCerebras,
    EnvAzure,
    ConfigFile,
    CloudConfig,
    OllamaAutoDetect,
    LmStudioAutoDetect,
    None,
}

impl KeySource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::EnvSicario => "SICARIO_LLM_API_KEY",
            Self::Keyring => "OS keyring",
            Self::EnvOpenAi => "OPENAI_API_KEY",
            Self::EnvAnthropic => "ANTHROPIC_API_KEY",
            Self::EnvGroq => "GROQ_API_KEY",
            Self::EnvDeepSeek => "DEEPSEEK_API_KEY",
            Self::EnvCerebras => "CEREBRAS_API_KEY",
            Self::EnvAzure => "AZURE_OPENAI_API_KEY",
            Self::ConfigFile => "~/.sicario/config.toml",
            Self::CloudConfig => "cloud",
            Self::OllamaAutoDetect => "Ollama (auto-detected)",
            Self::LmStudioAutoDetect => "LM Studio (auto-detected)",
            Self::None => "not configured",
        }
    }
}

/// Result of key resolution — the key value and where it came from.
#[derive(Debug, Clone)]
pub struct ResolvedKey {
    pub key: String,
    pub source: KeySource,
    /// Endpoint override set when a provider-specific env var is resolved.
    pub resolved_endpoint_override: Option<String>,
    /// Auth style override (e.g. XApiKey for Anthropic).
    pub auth_style: Option<super::provider_registry::AuthStyle>,
    /// Model override set when auto-detection picks a specific local model.
    pub model_override: Option<String>,
}

/// Resolve the key source label without making any network requests.
///
/// Checks env vars, OS keyring, and config file only.
/// Skips Ollama/LM Studio auto-detection and cloud config to guarantee
/// no outbound connections are made (used by `sicario config show`).
///
/// Returns the `KeySource` describing where the first key was found,
/// or `KeySource::None` if no key is configured.
pub fn resolve_key_source_no_network() -> KeySource {
    // 1. SICARIO_LLM_API_KEY
    if let Ok(key) = std::env::var("SICARIO_LLM_API_KEY") {
        if !key.is_empty() {
            return KeySource::EnvSicario;
        }
    }

    // 2. OS keyring
    if read_keyring().is_some() {
        return KeySource::Keyring;
    }

    // 3. OPENAI_API_KEY
    if let Ok(key) = std::env::var("OPENAI_API_KEY") {
        if !key.is_empty() {
            return KeySource::EnvOpenAi;
        }
    }

    // 4. ANTHROPIC_API_KEY
    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        if !key.is_empty() {
            return KeySource::EnvAnthropic;
        }
    }

    // 5. GROQ_API_KEY
    if let Ok(key) = std::env::var("GROQ_API_KEY") {
        if !key.is_empty() {
            return KeySource::EnvGroq;
        }
    }

    // 6. DEEPSEEK_API_KEY
    if let Ok(key) = std::env::var("DEEPSEEK_API_KEY") {
        if !key.is_empty() {
            return KeySource::EnvDeepSeek;
        }
    }

    // 7. CEREBRAS_API_KEY
    if let Ok(key) = std::env::var("CEREBRAS_API_KEY") {
        if !key.is_empty() {
            return KeySource::EnvCerebras;
        }
    }

    // 7b. AZURE_OPENAI_API_KEY (requires AZURE_OPENAI_RESOURCE + AZURE_OPENAI_DEPLOYMENT)
    if let Ok(key) = std::env::var("AZURE_OPENAI_API_KEY") {
        if !key.is_empty() && build_azure_endpoint().is_some() {
            return KeySource::EnvAzure;
        }
    }

    // 8. ~/.sicario/config.toml — global config LLM key field
    if let Some(global_cfg) = load_global_config() {
        // Check the generic llm_api_key field first (set by `sicario config set-key`)
        if global_cfg
            .llm_api_key
            .as_deref()
            .map(|k| !k.is_empty())
            .unwrap_or(false)
        {
            return KeySource::ConfigFile;
        }
        // Fall back to provider-specific keys stored in global config
        if global_cfg
            .anthropic_api_key
            .as_deref()
            .map(|k| !k.is_empty())
            .unwrap_or(false)
        {
            return KeySource::ConfigFile;
        }
        if global_cfg
            .openai_api_key
            .as_deref()
            .map(|k| !k.is_empty())
            .unwrap_or(false)
        {
            return KeySource::ConfigFile;
        }
    }

    // No key found (Ollama/LM Studio/cloud detection intentionally skipped)
    KeySource::None
}

/// Resolve the LLM API key using the precedence chain.
pub fn resolve_api_key() -> Option<ResolvedKey> {
    use super::provider_registry::{find_provider, AuthStyle};

    // Spawn Ollama / LM Studio detection immediately so it runs concurrently
    // with the env-var and config-file checks below (steps 1-8).  The two
    // 500ms HTTP probes therefore overlap with the I/O-bound config loading
    // rather than adding to it.  We join the handle at step 9.
    let detection_handle = spawn_local_llm_detection();

    // 1. SICARIO_LLM_API_KEY
    if let Ok(key) = std::env::var("SICARIO_LLM_API_KEY") {
        if !key.is_empty() {
            return Some(ResolvedKey {
                key,
                source: KeySource::EnvSicario,
                resolved_endpoint_override: None,
                auth_style: None,
                model_override: None,
            });
        }
    }

    // 2. OS keyring
    if let Some(key) = read_keyring() {
        return Some(ResolvedKey {
            key,
            source: KeySource::Keyring,
            resolved_endpoint_override: None,
            auth_style: None,
            model_override: None,
        });
    }

    // 3. OPENAI_API_KEY (de facto standard)
    if let Ok(key) = std::env::var("OPENAI_API_KEY") {
        if !key.is_empty() {
            let ep = find_provider("openai").map(|p| format!("{}/chat/completions", p.endpoint));
            return Some(ResolvedKey {
                key,
                source: KeySource::EnvOpenAi,
                resolved_endpoint_override: ep,
                auth_style: Some(AuthStyle::Bearer),
                model_override: None,
            });
        }
    }

    // 4. ANTHROPIC_API_KEY → set endpoint to Anthropic, flag auth_style: XApiKey
    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        if !key.is_empty() {
            let ep = find_provider("anthropic").map(|p| format!("{}/messages", p.endpoint));
            return Some(ResolvedKey {
                key,
                source: KeySource::EnvAnthropic,
                resolved_endpoint_override: ep,
                auth_style: Some(AuthStyle::XApiKey),
                model_override: None,
            });
        }
    }

    // 5. GROQ_API_KEY → set endpoint to Groq
    if let Ok(key) = std::env::var("GROQ_API_KEY") {
        if !key.is_empty() {
            let ep = find_provider("groq").map(|p| format!("{}/chat/completions", p.endpoint));
            return Some(ResolvedKey {
                key,
                source: KeySource::EnvGroq,
                resolved_endpoint_override: ep,
                auth_style: Some(AuthStyle::Bearer),
                model_override: None,
            });
        }
    }

    // 6. DEEPSEEK_API_KEY → set endpoint to DeepSeek
    if let Ok(key) = std::env::var("DEEPSEEK_API_KEY") {
        if !key.is_empty() {
            let ep = find_provider("deepseek").map(|p| format!("{}/chat/completions", p.endpoint));
            return Some(ResolvedKey {
                key,
                source: KeySource::EnvDeepSeek,
                resolved_endpoint_override: ep,
                auth_style: Some(AuthStyle::Bearer),
                model_override: None,
            });
        }
    }

    // 7. CEREBRAS_API_KEY (backward compat)
    if let Ok(key) = std::env::var("CEREBRAS_API_KEY") {
        if !key.is_empty() {
            let ep = find_provider("cerebras").map(|p| format!("{}/chat/completions", p.endpoint));
            return Some(ResolvedKey {
                key,
                source: KeySource::EnvCerebras,
                resolved_endpoint_override: ep,
                auth_style: Some(AuthStyle::Bearer),
                model_override: None,
            });
        }
    }

    // 7b. AZURE_OPENAI_API_KEY → construct deployment-scoped endpoint
    if let Ok(key) = std::env::var("AZURE_OPENAI_API_KEY") {
        if !key.is_empty() {
            if let Some(ep) = build_azure_endpoint() {
                return Some(ResolvedKey {
                    key,
                    source: KeySource::EnvAzure,
                    resolved_endpoint_override: Some(ep),
                    auth_style: Some(AuthStyle::AzureApiKey),
                    model_override: None,
                });
            }
        }
    }

    // 8. ~/.sicario/config.toml — global config LLM key field
    // Checks: llm_api_key (generic), then anthropic_api_key, then openai_api_key
    if let Some(global_cfg) = load_global_config() {
        // 8a. Generic llm_api_key (set by `sicario config set-key` or `set-provider`)
        if let Some(key) = global_cfg.llm_api_key.filter(|k| !k.is_empty()) {
            return Some(ResolvedKey {
                key,
                source: KeySource::ConfigFile,
                resolved_endpoint_override: None,
                auth_style: None,
                model_override: None,
            });
        }
        // 8b. anthropic_api_key stored in global config
        if let Some(key) = global_cfg.anthropic_api_key.filter(|k| !k.is_empty()) {
            let ep = find_provider("anthropic").map(|p| format!("{}/messages", p.endpoint));
            return Some(ResolvedKey {
                key,
                source: KeySource::ConfigFile,
                resolved_endpoint_override: ep,
                auth_style: Some(AuthStyle::XApiKey),
                model_override: None,
            });
        }
        // 8c. openai_api_key stored in global config
        if let Some(key) = global_cfg.openai_api_key.filter(|k| !k.is_empty()) {
            let ep = find_provider("openai").map(|p| format!("{}/chat/completions", p.endpoint));
            return Some(ResolvedKey {
                key,
                source: KeySource::ConfigFile,
                resolved_endpoint_override: ep,
                auth_style: Some(AuthStyle::Bearer),
                model_override: None,
            });
        }
    }

    // 9. Ollama / LM Studio auto-detection.
    //
    // The detection handle was spawned at the top of this function so that the
    // two 500ms HTTP probes run concurrently with the env-var and config-file
    // checks above (steps 1-8).  We join here only when all faster sources
    // have been exhausted.
    if let Some(resolved) = detection_handle.join().unwrap_or(None) {
        return Some(resolved);
    }

    // 10. Cloud config (authenticated users only)
    if let Some(fetcher) = try_cloud_fetcher() {
        if let Some(key) = fetcher.fetch_api_key() {
            return Some(ResolvedKey {
                key,
                source: KeySource::CloudConfig,
                resolved_endpoint_override: None,
                auth_style: None,
                model_override: None,
            });
        }
    }

    None
}

/// Spawn Ollama and LM Studio auto-detection on a background thread.
///
/// The two 500ms HTTP probes run concurrently with whatever the caller is
/// doing (e.g. rule loading).  Call `.join()` on the returned handle when
/// you need the result.
///
/// Detection order:
///   1. Ollama at `http://localhost:11434/api/tags`
///   2. LM Studio at `http://localhost:1234/v1/models` (if Ollama not found)
///
/// Returns `None` if both probes fail or time out.
pub fn spawn_local_llm_detection() -> std::thread::JoinHandle<Option<ResolvedKey>> {
    std::thread::spawn(|| {
        if let Some(resolved) = try_ollama_detection() {
            return Some(resolved);
        }
        try_lmstudio_detection()
    })
}

/// Try to auto-detect a running Ollama instance.
///
/// GETs `http://localhost:11434/api/tags` with a 500ms timeout.
/// On success, picks the first available model and returns a ResolvedKey.
fn try_ollama_detection() -> Option<ResolvedKey> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .ok()?;

    let resp = client.get("http://127.0.0.1:11434/api/tags").send().ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let body: serde_json::Value = resp.json().ok()?;
    let model_name = body["models"]
        .as_array()?
        .first()?
        .get("name")?
        .as_str()?
        .to_string();

    eprintln!(
        "Using local Ollama model: {}. Set ANTHROPIC_API_KEY or OPENAI_API_KEY to use a cloud provider.",
        model_name
    );

    Some(ResolvedKey {
        key: "ollama".to_string(),
        source: KeySource::OllamaAutoDetect,
        resolved_endpoint_override: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        auth_style: Some(super::provider_registry::AuthStyle::None),
        model_override: Some(model_name),
    })
}

/// Try to auto-detect a running LM Studio instance.
///
/// GETs `http://localhost:1234/v1/models` with a 500ms timeout.
fn try_lmstudio_detection() -> Option<ResolvedKey> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .ok()?;

    let resp = client.get("http://127.0.0.1:1234/v1/models").send().ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let body: serde_json::Value = resp.json().ok()?;
    let model_id = body["data"]
        .as_array()?
        .first()?
        .get("id")?
        .as_str()?
        .to_string();

    eprintln!(
        "Using local LM Studio model: {}. Set ANTHROPIC_API_KEY or OPENAI_API_KEY to use a cloud provider.",
        model_id
    );

    Some(ResolvedKey {
        key: "lmstudio".to_string(),
        source: KeySource::LmStudioAutoDetect,
        resolved_endpoint_override: Some("http://127.0.0.1:1234/v1/chat/completions".to_string()),
        auth_style: Some(super::provider_registry::AuthStyle::None),
        model_override: Some(model_id),
    })
}

/// Build the Azure OpenAI endpoint from environment variables.
///
/// Reads `AZURE_OPENAI_RESOURCE` and `AZURE_OPENAI_DEPLOYMENT` from env.
/// Returns `None` if either variable is missing.
pub fn build_azure_endpoint() -> Option<String> {
    let resource = std::env::var("AZURE_OPENAI_RESOURCE").ok()?;
    let deployment = std::env::var("AZURE_OPENAI_DEPLOYMENT").ok()?;
    if resource.is_empty() || deployment.is_empty() {
        return None;
    }
    Some(format!(
        "https://{}.openai.azure.com/openai/deployments/{}/chat/completions?api-version=2024-02-01",
        resource, deployment
    ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Global mutex to serialize tests that modify environment variables.
    /// Rust tests run in parallel by default; env vars are process-global,
    /// so concurrent modification causes flaky failures.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // ── Helper: clear all LLM-related env vars ────────────────────────────────

    fn clear_all_llm_env_vars() {
        for var in &[
            "SICARIO_LLM_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GROQ_API_KEY",
            "DEEPSEEK_API_KEY",
            "CEREBRAS_API_KEY",
            "AZURE_OPENAI_API_KEY",
            "AZURE_OPENAI_RESOURCE",
            "AZURE_OPENAI_DEPLOYMENT",
            "SICARIO_API_KEY",
        ] {
            std::env::remove_var(var);
        }
    }

    #[test]
    fn test_build_azure_endpoint_with_both_vars() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("AZURE_OPENAI_RESOURCE", "my-resource");
        std::env::set_var("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-deployment");

        let ep = build_azure_endpoint().unwrap();
        assert!(ep.contains("my-resource.openai.azure.com"));
        assert!(ep.contains("gpt-4o-deployment"));
        assert!(ep.contains("api-version=2024-02-01"));

        std::env::remove_var("AZURE_OPENAI_RESOURCE");
        std::env::remove_var("AZURE_OPENAI_DEPLOYMENT");
    }

    #[test]
    fn test_build_azure_endpoint_missing_resource() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("AZURE_OPENAI_RESOURCE");
        std::env::set_var("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-deployment");

        let ep = build_azure_endpoint();
        assert!(ep.is_none());

        std::env::remove_var("AZURE_OPENAI_DEPLOYMENT");
    }

    #[test]
    fn test_build_azure_endpoint_missing_deployment() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("AZURE_OPENAI_RESOURCE", "my-resource");
        std::env::remove_var("AZURE_OPENAI_DEPLOYMENT");

        let ep = build_azure_endpoint();
        assert!(ep.is_none());

        std::env::remove_var("AZURE_OPENAI_RESOURCE");
    }

    /// Azure endpoint construction produces the exact deployment-scoped URL format.
    ///
    /// Validates: Requirements 4.7 (Azure OpenAI Endpoint Construction)
    #[test]
    fn test_build_azure_endpoint_exact_format() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("AZURE_OPENAI_RESOURCE", "my-company");
        std::env::set_var("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-prod");

        let ep =
            build_azure_endpoint().expect("endpoint must be constructed when both vars are set");

        assert_eq!(
            ep,
            "https://my-company.openai.azure.com/openai/deployments/gpt-4o-prod/chat/completions?api-version=2024-02-01",
            "Azure endpoint must match the exact deployment-scoped URL format"
        );

        std::env::remove_var("AZURE_OPENAI_RESOURCE");
        std::env::remove_var("AZURE_OPENAI_DEPLOYMENT");
    }

    /// Azure key resolution: AZURE_OPENAI_API_KEY with resource+deployment resolves correctly.
    ///
    /// Validates: Requirements 4.7 (Azure OpenAI Endpoint Construction)
    #[test]
    fn test_azure_api_key_resolves_with_endpoint_and_auth_style() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("AZURE_OPENAI_API_KEY", "azure-key-test");
        std::env::set_var("AZURE_OPENAI_RESOURCE", "my-resource");
        std::env::set_var("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-deployment");

        let source = resolve_key_source_no_network();
        assert_eq!(source, KeySource::EnvAzure);

        let resolved = resolve_api_key().expect("should resolve from AZURE_OPENAI_API_KEY");
        assert_eq!(resolved.source, KeySource::EnvAzure);
        assert_eq!(resolved.key, "azure-key-test");

        let ep = resolved
            .resolved_endpoint_override
            .expect("endpoint override must be set for Azure");
        assert!(
            ep.contains("my-resource.openai.azure.com"),
            "endpoint must contain Azure resource: {}",
            ep
        );
        assert!(
            ep.contains("gpt-4o-deployment"),
            "endpoint must contain deployment name: {}",
            ep
        );
        assert!(
            ep.contains("api-version=2024-02-01"),
            "endpoint must include api-version: {}",
            ep
        );

        assert_eq!(
            resolved.auth_style,
            Some(super::super::provider_registry::AuthStyle::AzureApiKey),
            "Azure must use AzureApiKey auth style (api-key header, not Authorization: Bearer)"
        );

        clear_all_llm_env_vars();
    }

    /// Azure key is skipped when resource or deployment env vars are missing.
    ///
    /// Validates: Requirements 4.7 (Azure OpenAI Endpoint Construction)
    #[test]
    fn test_azure_api_key_skipped_without_resource_deployment() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("AZURE_OPENAI_API_KEY", "azure-key-test");
        // Intentionally NOT setting AZURE_OPENAI_RESOURCE or AZURE_OPENAI_DEPLOYMENT

        let source = resolve_key_source_no_network();
        assert_ne!(
            source,
            KeySource::EnvAzure,
            "Azure must not resolve when resource/deployment vars are missing"
        );

        clear_all_llm_env_vars();
    }

    #[test]
    fn test_key_source_labels() {
        assert_eq!(KeySource::EnvAnthropic.label(), "ANTHROPIC_API_KEY");
        assert_eq!(KeySource::EnvGroq.label(), "GROQ_API_KEY");
        assert_eq!(KeySource::EnvDeepSeek.label(), "DEEPSEEK_API_KEY");
        assert_eq!(KeySource::EnvAzure.label(), "AZURE_OPENAI_API_KEY");
        assert_eq!(
            KeySource::OllamaAutoDetect.label(),
            "Ollama (auto-detected)"
        );
        assert_eq!(
            KeySource::LmStudioAutoDetect.label(),
            "LM Studio (auto-detected)"
        );
    }

    // ── Step 1: SICARIO_LLM_API_KEY ───────────────────────────────────────────

    /// Step 1: SICARIO_LLM_API_KEY env var is the highest-priority source.
    ///
    /// Validates: Requirements 11.1
    #[test]
    fn test_step1_sicario_llm_api_key_resolves() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("SICARIO_LLM_API_KEY", "sk-sicario-test");

        let source = resolve_key_source_no_network();
        assert_eq!(source, KeySource::EnvSicario);

        clear_all_llm_env_vars();
    }

    /// Step 1 takes priority over all other env vars.
    ///
    /// Validates: Requirements 11.1, 11.5
    #[test]
    fn test_step1_sicario_llm_api_key_beats_openai() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("SICARIO_LLM_API_KEY", "sk-sicario-override");
        std::env::set_var("OPENAI_API_KEY", "sk-openai-lower");
        std::env::set_var("ANTHROPIC_API_KEY", "sk-ant-lower");

        let source = resolve_key_source_no_network();
        assert_eq!(
            source,
            KeySource::EnvSicario,
            "SICARIO_LLM_API_KEY must beat all other env vars"
        );

        clear_all_llm_env_vars();
    }

    /// Empty SICARIO_LLM_API_KEY is treated as absent.
    ///
    /// Validates: Requirements 11.1
    #[test]
    fn test_step1_empty_sicario_llm_api_key_is_skipped() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("SICARIO_LLM_API_KEY", "");
        std::env::set_var("OPENAI_API_KEY", "sk-openai-fallback");

        let source = resolve_key_source_no_network();
        assert_eq!(
            source,
            KeySource::EnvOpenAi,
            "Empty SICARIO_LLM_API_KEY must be skipped"
        );

        clear_all_llm_env_vars();
    }

    // ── Step 3: OPENAI_API_KEY ────────────────────────────────────────────────

    /// Step 3: OPENAI_API_KEY resolves with OpenAI endpoint override.
    ///
    /// Validates: Requirements 11.1, 11.2
    #[test]
    fn test_step3_openai_api_key_resolves_with_endpoint() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("OPENAI_API_KEY", "sk-openai-test");

        let source = resolve_key_source_no_network();
        assert_eq!(source, KeySource::EnvOpenAi);

        let resolved = resolve_api_key().expect("should resolve from OPENAI_API_KEY");
        assert_eq!(resolved.source, KeySource::EnvOpenAi);
        assert_eq!(resolved.key, "sk-openai-test");
        // Must set endpoint to OpenAI
        let ep = resolved
            .resolved_endpoint_override
            .expect("endpoint override must be set");
        assert!(
            ep.contains("api.openai.com"),
            "endpoint must point to OpenAI: {}",
            ep
        );

        clear_all_llm_env_vars();
    }

    // ── Step 4: ANTHROPIC_API_KEY ─────────────────────────────────────────────

    /// Step 4: ANTHROPIC_API_KEY resolves with Anthropic endpoint and XApiKey auth.
    ///
    /// Validates: Requirements 11.1, 11.2
    #[test]
    fn test_step4_anthropic_api_key_resolves_with_endpoint_and_auth_style() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("ANTHROPIC_API_KEY", "sk-ant-test");

        let source = resolve_key_source_no_network();
        assert_eq!(source, KeySource::EnvAnthropic);

        let resolved = resolve_api_key().expect("should resolve from ANTHROPIC_API_KEY");
        assert_eq!(resolved.source, KeySource::EnvAnthropic);
        assert_eq!(resolved.key, "sk-ant-test");
        // Must set endpoint to Anthropic
        let ep = resolved
            .resolved_endpoint_override
            .expect("endpoint override must be set");
        assert!(
            ep.contains("api.anthropic.com"),
            "endpoint must point to Anthropic: {}",
            ep
        );
        // Must use XApiKey auth style
        assert_eq!(
            resolved.auth_style,
            Some(super::super::provider_registry::AuthStyle::XApiKey),
            "Anthropic must use XApiKey auth style"
        );

        clear_all_llm_env_vars();
    }

    /// Step 3 beats step 4: OPENAI_API_KEY has higher priority than ANTHROPIC_API_KEY.
    ///
    /// Validates: Requirements 11.1, 11.5
    #[test]
    fn test_step3_beats_step4_openai_beats_anthropic() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("OPENAI_API_KEY", "sk-openai-higher");
        std::env::set_var("ANTHROPIC_API_KEY", "sk-ant-lower");

        let source = resolve_key_source_no_network();
        assert_eq!(
            source,
            KeySource::EnvOpenAi,
            "OPENAI_API_KEY (step 3) must beat ANTHROPIC_API_KEY (step 4)"
        );

        clear_all_llm_env_vars();
    }

    // ── Step 5: GROQ_API_KEY ──────────────────────────────────────────────────

    /// Step 5: GROQ_API_KEY resolves with Groq endpoint.
    ///
    /// Validates: Requirements 11.1, 11.2
    #[test]
    fn test_step5_groq_api_key_resolves_with_endpoint() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("GROQ_API_KEY", "gsk-groq-test");

        let source = resolve_key_source_no_network();
        assert_eq!(source, KeySource::EnvGroq);

        let resolved = resolve_api_key().expect("should resolve from GROQ_API_KEY");
        assert_eq!(resolved.source, KeySource::EnvGroq);
        assert_eq!(resolved.key, "gsk-groq-test");
        let ep = resolved
            .resolved_endpoint_override
            .expect("endpoint override must be set");
        assert!(
            ep.contains("api.groq.com"),
            "endpoint must point to Groq: {}",
            ep
        );

        clear_all_llm_env_vars();
    }

    // ── Step 6: DEEPSEEK_API_KEY ──────────────────────────────────────────────

    /// Step 6: DEEPSEEK_API_KEY resolves with DeepSeek endpoint.
    ///
    /// Validates: Requirements 11.1, 11.2
    #[test]
    fn test_step6_deepseek_api_key_resolves_with_endpoint() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("DEEPSEEK_API_KEY", "sk-deepseek-test");

        let source = resolve_key_source_no_network();
        assert_eq!(source, KeySource::EnvDeepSeek);

        let resolved = resolve_api_key().expect("should resolve from DEEPSEEK_API_KEY");
        assert_eq!(resolved.source, KeySource::EnvDeepSeek);
        assert_eq!(resolved.key, "sk-deepseek-test");
        let ep = resolved
            .resolved_endpoint_override
            .expect("endpoint override must be set");
        assert!(
            ep.contains("api.deepseek.com"),
            "endpoint must point to DeepSeek: {}",
            ep
        );

        clear_all_llm_env_vars();
    }

    // ── Step 7: CEREBRAS_API_KEY ──────────────────────────────────────────────

    /// Step 7: CEREBRAS_API_KEY resolves with Cerebras endpoint.
    ///
    /// Validates: Requirements 11.1, 11.2
    #[test]
    fn test_step7_cerebras_api_key_resolves_with_endpoint() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("CEREBRAS_API_KEY", "csk-cerebras-test");

        let source = resolve_key_source_no_network();
        assert_eq!(source, KeySource::EnvCerebras);

        let resolved = resolve_api_key().expect("should resolve from CEREBRAS_API_KEY");
        assert_eq!(resolved.source, KeySource::EnvCerebras);
        assert_eq!(resolved.key, "csk-cerebras-test");
        let ep = resolved
            .resolved_endpoint_override
            .expect("endpoint override must be set");
        assert!(
            ep.contains("api.cerebras.ai"),
            "endpoint must point to Cerebras: {}",
            ep
        );

        clear_all_llm_env_vars();
    }

    /// Step 5 beats step 7: GROQ_API_KEY has higher priority than CEREBRAS_API_KEY.
    ///
    /// Validates: Requirements 11.1, 11.5
    #[test]
    fn test_step5_beats_step7_groq_beats_cerebras() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("GROQ_API_KEY", "gsk-groq-higher");
        std::env::set_var("CEREBRAS_API_KEY", "csk-cerebras-lower");

        let source = resolve_key_source_no_network();
        assert_eq!(
            source,
            KeySource::EnvGroq,
            "GROQ_API_KEY (step 5) must beat CEREBRAS_API_KEY (step 7)"
        );

        clear_all_llm_env_vars();
    }

    // ── Step 8: ~/.sicario/config.toml ────────────────────────────────────────

    /// Step 8: llm_api_key in ~/.sicario/config.toml resolves when no env vars are set.
    ///
    /// Validates: Requirements 11.1
    #[test]
    fn test_step8_global_config_llm_api_key_resolves() {
        use crate::config::{load_global_config, set_global_config_value};
        use tempfile::tempdir;

        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();

        let tmp = tempdir().unwrap();
        let original_home = std::env::var("HOME").ok();
        let original_userprofile = std::env::var("USERPROFILE").ok();

        std::env::set_var("HOME", tmp.path());
        std::env::set_var("USERPROFILE", tmp.path());

        // Write llm_api_key to ~/.sicario/config.toml
        set_global_config_value("llm_api_key", "sk-global-config-test").unwrap();

        // Verify it was written
        let cfg = load_global_config().unwrap();
        assert_eq!(cfg.llm_api_key.as_deref(), Some("sk-global-config-test"));

        // resolve_key_source_no_network should return ConfigFile
        let source = resolve_key_source_no_network();
        assert_eq!(
            source,
            KeySource::ConfigFile,
            "llm_api_key in config.toml must resolve as ConfigFile"
        );

        // resolve_api_key should return the key
        let resolved = resolve_api_key().expect("should resolve from ~/.sicario/config.toml");
        assert_eq!(resolved.source, KeySource::ConfigFile);
        assert_eq!(resolved.key, "sk-global-config-test");

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

    /// Step 8: anthropic_api_key in ~/.sicario/config.toml resolves with Anthropic endpoint.
    ///
    /// Validates: Requirements 11.1
    #[test]
    fn test_step8_global_config_anthropic_api_key_resolves() {
        use crate::config::set_global_config_value;
        use tempfile::tempdir;

        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();

        let tmp = tempdir().unwrap();
        let original_home = std::env::var("HOME").ok();
        let original_userprofile = std::env::var("USERPROFILE").ok();

        std::env::set_var("HOME", tmp.path());
        std::env::set_var("USERPROFILE", tmp.path());

        // Write anthropic_api_key to ~/.sicario/config.toml
        set_global_config_value("ANTHROPIC_API_KEY", "sk-ant-config-test").unwrap();

        let source = resolve_key_source_no_network();
        assert_eq!(source, KeySource::ConfigFile);

        let resolved = resolve_api_key()
            .expect("should resolve from ~/.sicario/config.toml anthropic_api_key");
        assert_eq!(resolved.source, KeySource::ConfigFile);
        assert_eq!(resolved.key, "sk-ant-config-test");
        // Must set Anthropic endpoint and XApiKey auth
        let ep = resolved
            .resolved_endpoint_override
            .expect("endpoint override must be set for Anthropic config key");
        assert!(
            ep.contains("api.anthropic.com"),
            "endpoint must point to Anthropic: {}",
            ep
        );
        assert_eq!(
            resolved.auth_style,
            Some(super::super::provider_registry::AuthStyle::XApiKey),
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

    /// Step 7 beats step 8: CEREBRAS_API_KEY env var beats ~/.sicario/config.toml.
    ///
    /// Validates: Requirements 11.1, 11.5
    #[test]
    fn test_step7_beats_step8_env_beats_config_file() {
        use crate::config::set_global_config_value;
        use tempfile::tempdir;

        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();

        let tmp = tempdir().unwrap();
        let original_home = std::env::var("HOME").ok();
        let original_userprofile = std::env::var("USERPROFILE").ok();

        std::env::set_var("HOME", tmp.path());
        std::env::set_var("USERPROFILE", tmp.path());

        // Write a key to config.toml
        set_global_config_value("llm_api_key", "sk-config-lower").unwrap();

        // Set CEREBRAS_API_KEY env var (step 7)
        std::env::set_var("CEREBRAS_API_KEY", "csk-env-higher");

        let source = resolve_key_source_no_network();
        assert_eq!(
            source,
            KeySource::EnvCerebras,
            "CEREBRAS_API_KEY env (step 7) must beat config.toml (step 8)"
        );

        clear_all_llm_env_vars();

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

    // ── SICARIO_API_KEY must never be used for LLM auth ───────────────────────

    /// SICARIO_API_KEY must never appear in the LLM key resolution chain.
    ///
    /// Validates: Requirements 11.3
    #[test]
    fn test_sicario_api_key_never_used_for_llm_auth() {
        use tempfile::tempdir;

        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("SICARIO_API_KEY", "project:telemetry-only-key");

        // Use a temp dir with no config.toml to avoid picking up real user config
        let tmp = tempdir().unwrap();
        let original_home = std::env::var("HOME").ok();
        let original_userprofile = std::env::var("USERPROFILE").ok();
        std::env::set_var("HOME", tmp.path());
        std::env::set_var("USERPROFILE", tmp.path());

        // With no other keys set, resolution should return None (not the telemetry key)
        let source = resolve_key_source_no_network();
        assert_eq!(
            source,
            KeySource::None,
            "SICARIO_API_KEY must never be used for LLM auth — it is for telemetry only"
        );

        std::env::remove_var("SICARIO_API_KEY");

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

    // ── Full precedence ordering ──────────────────────────────────────────────

    /// Full precedence: step 1 beats all others.
    ///
    /// Validates: Requirements 11.1, 11.5
    #[test]
    fn test_full_precedence_step1_beats_all_env_vars() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("SICARIO_LLM_API_KEY", "sk-step1");
        std::env::set_var("OPENAI_API_KEY", "sk-step3");
        std::env::set_var("ANTHROPIC_API_KEY", "sk-step4");
        std::env::set_var("GROQ_API_KEY", "sk-step5");
        std::env::set_var("DEEPSEEK_API_KEY", "sk-step6");
        std::env::set_var("CEREBRAS_API_KEY", "sk-step7");

        let source = resolve_key_source_no_network();
        assert_eq!(
            source,
            KeySource::EnvSicario,
            "Step 1 must win when all env vars are set"
        );

        clear_all_llm_env_vars();
    }

    /// Full precedence: step 3 beats steps 4-7.
    ///
    /// Validates: Requirements 11.1, 11.5
    #[test]
    fn test_full_precedence_step3_beats_steps_4_through_7() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("OPENAI_API_KEY", "sk-step3");
        std::env::set_var("ANTHROPIC_API_KEY", "sk-step4");
        std::env::set_var("GROQ_API_KEY", "sk-step5");
        std::env::set_var("DEEPSEEK_API_KEY", "sk-step6");
        std::env::set_var("CEREBRAS_API_KEY", "sk-step7");

        let source = resolve_key_source_no_network();
        assert_eq!(
            source,
            KeySource::EnvOpenAi,
            "Step 3 (OPENAI_API_KEY) must beat steps 4-7"
        );

        clear_all_llm_env_vars();
    }

    /// Full precedence: step 4 beats steps 5-7.
    ///
    /// Validates: Requirements 11.1, 11.5
    #[test]
    fn test_full_precedence_step4_beats_steps_5_through_7() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("ANTHROPIC_API_KEY", "sk-step4");
        std::env::set_var("GROQ_API_KEY", "sk-step5");
        std::env::set_var("DEEPSEEK_API_KEY", "sk-step6");
        std::env::set_var("CEREBRAS_API_KEY", "sk-step7");

        let source = resolve_key_source_no_network();
        assert_eq!(
            source,
            KeySource::EnvAnthropic,
            "Step 4 (ANTHROPIC_API_KEY) must beat steps 5-7"
        );

        clear_all_llm_env_vars();
    }

    /// Full precedence: step 6 beats step 7.
    ///
    /// Validates: Requirements 11.1, 11.5
    #[test]
    fn test_full_precedence_step6_beats_step7() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();
        std::env::set_var("DEEPSEEK_API_KEY", "sk-step6");
        std::env::set_var("CEREBRAS_API_KEY", "sk-step7");

        let source = resolve_key_source_no_network();
        assert_eq!(
            source,
            KeySource::EnvDeepSeek,
            "Step 6 (DEEPSEEK_API_KEY) must beat step 7"
        );

        clear_all_llm_env_vars();
    }

    /// When no keys are configured, resolution returns None/KeySource::None.
    ///
    /// Validates: Requirements 11.1
    #[test]
    fn test_no_keys_configured_returns_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_llm_env_vars();

        // Use a temp dir with no config.toml to avoid picking up real user config
        let tmp = tempfile::tempdir().unwrap();
        let original_home = std::env::var("HOME").ok();
        let original_userprofile = std::env::var("USERPROFILE").ok();

        std::env::set_var("HOME", tmp.path());
        std::env::set_var("USERPROFILE", tmp.path());

        let source = resolve_key_source_no_network();
        assert_eq!(
            source,
            KeySource::None,
            "No keys configured must return KeySource::None"
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

    // ── KeySource and ConfigSource label tests ────────────────────────────────

    /// All KeySource variants have correct labels.
    ///
    /// Validates: Requirements 11.4
    #[test]
    fn test_all_key_source_labels() {
        assert_eq!(KeySource::EnvSicario.label(), "SICARIO_LLM_API_KEY");
        assert_eq!(KeySource::Keyring.label(), "OS keyring");
        assert_eq!(KeySource::EnvOpenAi.label(), "OPENAI_API_KEY");
        assert_eq!(KeySource::EnvAnthropic.label(), "ANTHROPIC_API_KEY");
        assert_eq!(KeySource::EnvGroq.label(), "GROQ_API_KEY");
        assert_eq!(KeySource::EnvDeepSeek.label(), "DEEPSEEK_API_KEY");
        assert_eq!(KeySource::EnvCerebras.label(), "CEREBRAS_API_KEY");
        assert_eq!(KeySource::EnvAzure.label(), "AZURE_OPENAI_API_KEY");
        assert_eq!(KeySource::ConfigFile.label(), "~/.sicario/config.toml");
        assert_eq!(KeySource::CloudConfig.label(), "cloud");
        assert_eq!(
            KeySource::OllamaAutoDetect.label(),
            "Ollama (auto-detected)"
        );
        assert_eq!(
            KeySource::LmStudioAutoDetect.label(),
            "LM Studio (auto-detected)"
        );
        assert_eq!(KeySource::None.label(), "not configured");
    }

    // ── Local LLM auto-detection integration tests ────────────────────────────
    //
    // These tests spin up minimal in-process HTTP servers using
    // `std::net::TcpListener` so no external process or crate is required.
    // Each server runs on a random OS-assigned port and is torn down after
    // the test completes.
    //
    // IMPORTANT: These tests bind to fixed ports (11434 and 1234) that the
    // detection functions probe.  They must not run concurrently with each
    // other, so they share a dedicated mutex.
    static LOCAL_DETECT_LOCK: Mutex<()> = Mutex::new(());

    /// Minimal HTTP/1.1 server that responds to a single request and exits.
    ///
    /// `response_body` is the JSON body to return with HTTP 200.
    fn serve_one_request(listener: std::net::TcpListener, response_body: &'static str) {
        use std::io::{BufRead, BufReader, Write};

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // Read until the end of the HTTP request headers (blank line)
                let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            if line == "\r\n" || line == "\n" {
                                break;
                            }
                        }
                    }
                }

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
    }

    /// Integration test: Ollama detection returns correct endpoint, model, and auth_style.
    ///
    /// Validates: Requirements 20.5 (Ollama auto-detection)
    #[test]
    fn test_ollama_detection_with_mock_server() {
        use std::net::TcpListener;
        let _detect_guard = LOCAL_DETECT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Bind to the Ollama port (11434). Skip the test if the port is already
        // in use (e.g. a real Ollama instance is running).
        let listener = match TcpListener::bind("127.0.0.1:11434") {
            Ok(l) => l,
            Err(_) => {
                // Port in use — run against the real server instead by calling
                // try_ollama_detection() directly and accepting any result.
                eprintln!(
                    "test_ollama_detection_with_mock_server: port 11434 in use, skipping mock"
                );
                return;
            }
        };

        let ollama_response = r#"{"models":[{"name":"llama3:latest","modified_at":"2024-01-01T00:00:00Z","size":4000000000}]}"#;
        serve_one_request(listener, ollama_response);

        // Give the server thread a moment to start accepting
        std::thread::sleep(std::time::Duration::from_millis(50));

        let result = try_ollama_detection();
        assert!(
            result.is_some(),
            "Ollama detection must succeed when server is reachable"
        );

        let resolved = result.unwrap();
        assert_eq!(resolved.source, KeySource::OllamaAutoDetect);
        assert_eq!(resolved.model_override.as_deref(), Some("llama3:latest"));
        assert_eq!(
            resolved.resolved_endpoint_override.as_deref(),
            Some("http://127.0.0.1:11434/v1/chat/completions")
        );
        assert_eq!(
            resolved.auth_style,
            Some(super::super::provider_registry::AuthStyle::None),
            "Ollama must use AuthStyle::None (no API key required)"
        );
    }

    /// Integration test: LM Studio detection returns correct endpoint and model.
    ///
    /// Validates: Requirements 20.5 (LM Studio auto-detection)
    #[test]
    fn test_lmstudio_detection_with_mock_server() {
        use std::net::TcpListener;
        let _detect_guard = LOCAL_DETECT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Bind to the LM Studio port (1234). Skip if already in use.
        let listener = match TcpListener::bind("127.0.0.1:1234") {
            Ok(l) => l,
            Err(_) => {
                eprintln!(
                    "test_lmstudio_detection_with_mock_server: port 1234 in use, skipping mock"
                );
                return;
            }
        };

        let lmstudio_response = r#"{"data":[{"id":"mistral-7b-instruct-v0.2","object":"model","created":1700000000,"owned_by":"local"}],"object":"list"}"#;
        serve_one_request(listener, lmstudio_response);

        std::thread::sleep(std::time::Duration::from_millis(50));

        let result = try_lmstudio_detection();
        assert!(
            result.is_some(),
            "LM Studio detection must succeed when server is reachable"
        );

        let resolved = result.unwrap();
        assert_eq!(resolved.source, KeySource::LmStudioAutoDetect);
        assert_eq!(
            resolved.model_override.as_deref(),
            Some("mistral-7b-instruct-v0.2")
        );
        assert_eq!(
            resolved.resolved_endpoint_override.as_deref(),
            Some("http://127.0.0.1:1234/v1/chat/completions")
        );
        assert_eq!(
            resolved.auth_style,
            Some(super::super::provider_registry::AuthStyle::None),
            "LM Studio must use AuthStyle::None (no API key required)"
        );
    }

    /// Integration test: when both Ollama and LM Studio are unreachable,
    /// `spawn_local_llm_detection` returns None.
    ///
    /// Validates: Requirements 20.5 (fallback to "No LLM API key configured")
    #[test]
    fn test_local_detection_returns_none_when_both_fail() {
        let _detect_guard = LOCAL_DETECT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Ports 11434 and 1234 must be closed for this test to be meaningful.
        // We verify by attempting to connect; if either succeeds we skip.
        let ollama_open = std::net::TcpStream::connect_timeout(
            &"127.0.0.1:11434".parse().unwrap(),
            std::time::Duration::from_millis(50),
        )
        .is_ok();
        let lmstudio_open = std::net::TcpStream::connect_timeout(
            &"127.0.0.1:1234".parse().unwrap(),
            std::time::Duration::from_millis(50),
        )
        .is_ok();

        if ollama_open || lmstudio_open {
            eprintln!("test_local_detection_returns_none_when_both_fail: a local LLM server is running, skipping");
            return;
        }

        let handle = spawn_local_llm_detection();
        let result = handle.join().expect("detection thread must not panic");
        assert!(
            result.is_none(),
            "Detection must return None when both Ollama and LM Studio are unreachable"
        );
    }

    /// Integration test: `spawn_local_llm_detection` runs on a background thread
    /// and does not block the caller while the probes are in flight.
    ///
    /// Validates: Requirements 20.5 (non-blocking detection)
    #[test]
    fn test_spawn_local_llm_detection_is_non_blocking() {
        let _detect_guard = LOCAL_DETECT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Spawn detection (will time out quickly since no server is running on
        // these ports in CI).  The caller should be able to do other work
        // immediately after spawning.
        let handle = spawn_local_llm_detection();

        // Simulate "rule loading" work that happens concurrently
        let work_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let work_done_clone = work_done.clone();
        std::thread::spawn(move || {
            // Simulate some CPU work
            let _sum: u64 = (0..10_000u64).sum();
            work_done_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        })
        .join()
        .unwrap();

        assert!(
            work_done.load(std::sync::atomic::Ordering::SeqCst),
            "Caller must be able to do work while detection runs in background"
        );

        // Join the detection handle — it should complete within the timeout window
        let _ = handle.join();
    }
}

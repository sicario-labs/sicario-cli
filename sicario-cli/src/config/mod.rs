//! Global user-level configuration module.
//!
//! Manages `~/.sicario/config.toml` for user-level settings such as
//! LLM API keys (BYOK — Bring Your Own Key).
//!
//! # Key Separation
//!
//! - **LLM keys** (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`): Used locally by
//!   `sicario fix` for AI-powered remediation. Never sent to the cloud.
//!   Stored in `~/.sicario/config.toml` with 0600 permissions.
//!
//! - **Telemetry key** (`SICARIO_API_KEY`): Used exclusively to authenticate
//!   HTTP POST requests to `POST /api/v1/telemetry/scan`. Never used for LLM auth.

pub mod global_config;

pub use global_config::{
    global_config_path, load_global_config, resolve_llm_api_key, set_global_config_value,
    GlobalConfig, LlmKeyResolution, LlmKeySource, LlmProvider,
};

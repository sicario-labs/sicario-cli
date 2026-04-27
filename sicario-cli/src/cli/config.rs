//! Config subcommand arguments.

use clap::{Parser, Subcommand};

/// Manage Sicario configuration and API keys.
#[derive(Parser, Debug)]
pub struct ConfigCommand {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Set the LLM API key (stored in OS credential store)
    SetKey,
    /// Set the LLM provider endpoint and model
    SetProvider(SetProviderArgs),
    /// Set a configuration value in ~/.sicario/config.toml
    ///
    /// Valid keys: ANTHROPIC_API_KEY, OPENAI_API_KEY, llm_endpoint, llm_model
    ///
    /// Examples:
    ///   sicario config set ANTHROPIC_API_KEY sk-ant-...
    ///   sicario config set OPENAI_API_KEY sk-...
    ///   sicario config set llm_model claude-3-5-sonnet-20241022
    Set(SetArgs),
    /// Show current configuration
    Show,
    /// Delete the stored API key
    DeleteKey,
    /// Test connectivity to the configured LLM provider
    Test,
}

/// Arguments for `config set-provider`.
#[derive(Parser, Debug)]
pub struct SetProviderArgs {
    /// LLM API endpoint URL
    #[arg(long)]
    pub endpoint: String,

    /// LLM model name
    #[arg(long)]
    pub model: Option<String>,
}

/// Arguments for `config set <KEY> <VALUE>`.
#[derive(Parser, Debug)]
pub struct SetArgs {
    /// Configuration key to set.
    /// Valid keys: ANTHROPIC_API_KEY, OPENAI_API_KEY, llm_endpoint, llm_model
    pub key: String,

    /// Value to assign to the key.
    pub value: String,
}

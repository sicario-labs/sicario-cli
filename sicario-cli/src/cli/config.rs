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

//! BYOK key management — keyring integration and precedence resolution.
//!
//! Provides a layered key resolution chain so Sicario works with any
//! OpenAI-compatible LLM provider without hard-coding credentials.

pub mod cloud_config;
pub mod config_file;
pub mod manager;

pub use manager::{
    delete_key_from_keyring, keyring_has_key, resolve_api_key, resolve_endpoint, resolve_model,
    resolve_endpoint_with_source, resolve_model_with_source,
    store_key_in_keyring, ConfigSource, KeySource, ResolvedKey, ResolvedValue,
};

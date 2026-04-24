//! Local config file parser for `.sicario/config.yaml`.
//!
//! Provides typed access to provider settings stored in the project-local
//! config file written by `sicario config set-provider`.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Provider settings stored in `.sicario/config.yaml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LocalConfig {
    pub endpoint: Option<String>,
    pub model: Option<String>,
    pub key: Option<String>,
    /// Unknown fields are preserved on round-trip.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

/// Load config from `.sicario/config.yaml` relative to `project_root`.
///
/// Returns `None` if the file doesn't exist, is unreadable, or fails to parse.
pub fn load_config_file(project_root: &Path) -> Option<LocalConfig> {
    let path = project_root.join(".sicario").join("config.yaml");
    let content = std::fs::read_to_string(&path).ok()?;
    serde_yaml::from_str(&content).ok()
}

/// Write config to `.sicario/config.yaml` relative to `project_root`.
///
/// Creates the `.sicario` directory if it doesn't exist.
pub fn save_config_file(project_root: &Path, config: &LocalConfig) -> Result<()> {
    let dir = project_root.join(".sicario");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("config.yaml");
    let yaml = serde_yaml::to_string(config)?;
    std::fs::write(&path, yaml)?;
    Ok(())
}

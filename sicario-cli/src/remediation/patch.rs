//! Patch data structure

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Represents a code patch for fixing a vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    pub id: Uuid,
    pub file_path: PathBuf,
    pub original: String,
    pub fixed: String,
    pub diff: String,
    pub backup_path: PathBuf,
}

impl Patch {
    /// Create a new patch
    pub fn new(
        file_path: PathBuf,
        original: String,
        fixed: String,
        diff: String,
        backup_path: PathBuf,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            file_path,
            original,
            fixed,
            diff,
            backup_path,
        }
    }
}

//! Poison-Pill Interceptor — `sicario guard`
//!
//! Watches package installation directories for behavioral anomalies and
//! quarantines suspicious packages before they can execute.

pub mod behavioral_rules;
pub mod behavioral_scanner;
pub mod quarantine;
pub mod watcher;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::engine::vulnerability::Severity;

/// Signals that indicate a behavioral anomaly in a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalySignal {
    /// Package spawns child processes (e.g. `require('child_process')`)
    UnexpectedChildProcess,
    /// Package makes network connections (e.g. `require('net')` / `require('http')`)
    UnexpectedNetworkAccess,
    /// Package accesses the filesystem (e.g. `require('fs')`)
    UnexpectedFilesystemAccess,
    /// Package calls `eval()` with a non-literal argument
    ObfuscatedEval,
    /// Package decodes base64 and passes result to `eval()`
    Base64DecodedEval,
    /// Package harvests credentials in a post-install script
    PostInstallCredentialHarvest,
    /// Package contains a long hex-encoded string (potential payload)
    HexEncodedPayload,
    /// Package uses `require(variable)` — dynamic module loading
    DynamicRequire,
}

/// A single behavioral anomaly detected in a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnomaly {
    pub signal: AnomalySignal,
    pub severity: Severity,
    pub file: PathBuf,
    pub line: usize,
    pub snippet: String,
    pub description: String,
}

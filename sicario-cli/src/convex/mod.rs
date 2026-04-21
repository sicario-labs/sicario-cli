//! Convex backend client module
//!
//! Provides WebSocket-based connectivity to the Convex backend for:
//! - Telemetry push (detected, dismissed, and fixed vulnerabilities)
//! - Real-time ruleset subscription and updates
//!
//! Requirements: 8.1, 8.2, 8.4

pub mod client;
pub mod telemetry;
pub mod ruleset;

#[cfg(test)]
mod telemetry_property_tests;

pub use client::{ConvexClient, ConvexConfig, ConnectionState};
pub use telemetry::{TelemetryEvent, TelemetryAction};
pub use ruleset::RulesetUpdate;

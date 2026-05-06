//! Policy-as-Code enforcement module.
//!
//! Loads `.sicario/policy.yaml` and enforces organizational security policies
//! during scan invocations. Policy fields override all CLI flags.

pub mod loader;

pub use loader::{PolicyConfig, PolicyLoader};

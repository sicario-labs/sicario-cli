//! Trait-based template registry for deterministic vulnerability remediation.
//!
//! This module re-exports from the modular `template_registry` sub-module.
//! See `template_registry/mod.rs` for the full implementation.

pub use super::template_registry::MultiLinePatchTemplate;
pub use super::template_registry::PatchTemplate;
pub use super::template_registry::TemplateRegistry;

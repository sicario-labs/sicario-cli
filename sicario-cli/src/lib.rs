//! Sicario CLI - High-performance security scanning tool
//!
//! This library provides the core functionality for the Sicario CLI security scanner,
//! including tree-sitter parsing, SAST analysis, secret scanning, and more.

pub mod parser;
pub mod engine;
pub mod scanner;
pub mod tui;
pub mod auth;
pub mod remediation;
pub mod convex;
pub mod mcp;
pub mod onboarding;
pub mod cloud;
pub mod reporting;

// New modules added by CLI overhaul
pub mod cli;
pub mod output;
pub mod diff;
pub mod confidence;
pub mod baseline;
pub mod suppression_learner;
pub mod verification;
pub mod cache;
pub mod hook;
pub mod lsp;
pub mod benchmark;
pub mod rule_harness;
pub mod key_manager;
pub mod publish;

#[cfg(test)]
mod binary_portability_tests;

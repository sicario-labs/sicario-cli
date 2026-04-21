//! Sicario CLI - High-performance security scanning tool
//!
//! This library provides the core functionality for the Sicario CLI security scanner,
//! including tree-sitter parsing, SAST analysis, secret scanning, and more.

// Many modules are scaffolded ahead of wiring — suppress noise until fully integrated.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_doc_comments)]
#![allow(unused_mut)]

pub mod auth;
pub mod cloud;
pub mod convex;
pub mod engine;
pub mod mcp;
pub mod onboarding;
pub mod parser;
pub mod remediation;
pub mod reporting;
pub mod scanner;
pub mod tui;

// New modules added by CLI overhaul
pub mod baseline;
pub mod benchmark;
pub mod cache;
pub mod cli;
pub mod confidence;
pub mod diff;
pub mod hook;
pub mod key_manager;
pub mod lsp;
pub mod output;
pub mod publish;
pub mod rule_harness;
pub mod suppression_learner;
pub mod verification;

#[cfg(test)]
mod binary_portability_tests;

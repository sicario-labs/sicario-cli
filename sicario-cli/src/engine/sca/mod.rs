//! Software Composition Analysis (SCA) engine
//!
//! Provides CVE/GHSA vulnerability database management, manifest parsing,
//! and dependency vulnerability scanning with reachability-based false-positive
//! elimination.

pub mod known_vulnerability;
pub mod vuln_db;
pub mod osv_import;
pub mod ghsa_import;
pub mod manifest_parser;
#[cfg(test)]
mod sca_property_tests;

pub use known_vulnerability::KnownVulnerability;
pub use vuln_db::VulnerabilityDatabaseManager;
pub use manifest_parser::ManifestParser;

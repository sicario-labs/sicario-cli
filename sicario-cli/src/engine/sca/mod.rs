//! Software Composition Analysis (SCA) engine
//!
//! Provides CVE/GHSA vulnerability database management, manifest parsing,
//! and dependency vulnerability scanning with reachability-based false-positive
//! elimination.

pub mod ghsa_import;
pub mod known_vulnerability;
pub mod manifest_parser;
pub mod osv_import;
#[cfg(test)]
mod sca_property_tests;
pub mod vuln_db;

pub use known_vulnerability::KnownVulnerability;
pub use manifest_parser::ManifestParser;
pub use vuln_db::VulnerabilityDatabaseManager;

//! Zero-configuration onboarding module
//!
//! Provides auto-detection of programming languages, package managers, and
//! frameworks in a project directory, then configures optimal security rule
//! subsets for the detected technologies.
//!
//! Requirements: 10.1, 10.2, 10.3, 10.4, 10.5

pub mod detector;
pub mod onboarding_flow;
#[cfg(test)]
pub mod onboarding_property_tests;
pub mod rule_configurator;

pub use detector::{DetectedTechnologies, TechDetector};
pub use onboarding_flow::OnboardingFlow;
pub use rule_configurator::RuleConfigurator;

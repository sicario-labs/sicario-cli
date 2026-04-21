//! Cloud-to-code traceability module
//!
//! Integrates with Kubernetes configurations and CSPM data to determine
//! whether vulnerable services are publicly exposed, enabling priority
//! assignment based on runtime exposure.
//!
//! Requirements: 11.1, 11.2, 11.3, 11.4, 11.5

pub mod interfaces;
pub mod exposure;
pub mod priority;
pub mod priority_property_tests;

pub use interfaces::{
    CloudProvider, CspmFinding, CspmIngester, ExposureStatus, KubernetesConfig,
    KubernetesParser, ServiceExposure,
};
pub use exposure::CloudExposureAnalyzer;
pub use priority::assign_cloud_priority;

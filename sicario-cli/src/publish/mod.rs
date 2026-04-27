//! Cloud publish client module — authenticated upload to Sicario Cloud API.

pub mod client;
pub mod telemetry_client;

#[cfg(test)]
mod telemetry_property_tests;

pub use client::{
    collect_git_metadata, resolve_cloud_url, PublishClient, PublishResponse, ScanMetadata,
    ScanReport,
};
pub use telemetry_client::{TelemetryClient, TelemetryFinding, TelemetryPayload, TelemetryResponse};

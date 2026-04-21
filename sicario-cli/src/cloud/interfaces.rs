//! Cloud telemetry integration interfaces
//!
//! Defines the core traits and data models for Kubernetes config parsing
//! and CSPM (Cloud Security Posture Management) data ingestion.
//!
//! Requirements: 11.1

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// ── Exposure status ───────────────────────────────────────────────────────────

/// Whether a service is reachable from the public internet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExposureStatus {
    /// Service is directly reachable from the public internet.
    PubliclyExposed,
    /// Service is only reachable within the cluster / VPC.
    Internal,
    /// Exposure status could not be determined from available data.
    Unknown,
}

// ── Kubernetes interfaces ─────────────────────────────────────────────────────

/// Represents a parsed Kubernetes resource that describes a deployed service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfig {
    /// Kubernetes resource kind (e.g. "Service", "Ingress", "Deployment").
    pub kind: String,
    /// Namespace the resource belongs to.
    pub namespace: String,
    /// Resource name.
    pub name: String,
    /// Arbitrary labels attached to the resource.
    pub labels: HashMap<String, String>,
    /// Annotations attached to the resource.
    pub annotations: HashMap<String, String>,
    /// Service type when `kind == "Service"` (ClusterIP, NodePort, LoadBalancer, ExternalName).
    pub service_type: Option<String>,
    /// Ports exposed by the resource.
    pub ports: Vec<u16>,
    /// Whether an Ingress or LoadBalancer exposes this resource externally.
    pub has_external_ingress: bool,
    /// Source file path this config was parsed from.
    pub source_file: PathBuf,
}

impl KubernetesConfig {
    /// Returns `true` when the resource configuration indicates public exposure.
    pub fn is_publicly_exposed(&self) -> bool {
        if self.has_external_ingress {
            return true;
        }
        matches!(
            self.service_type.as_deref(),
            Some("LoadBalancer") | Some("NodePort") | Some("ExternalName")
        )
    }
}

/// Trait for parsing Kubernetes YAML/JSON manifests into `KubernetesConfig` structs.
///
/// Requirements: 11.1
pub trait KubernetesParser: Send + Sync {
    /// Parse all Kubernetes manifests found under `dir` and return the
    /// resulting configs.
    fn parse_directory(&self, dir: &std::path::Path) -> Result<Vec<KubernetesConfig>>;

    /// Parse a single Kubernetes manifest file.
    fn parse_file(&self, path: &std::path::Path) -> Result<Vec<KubernetesConfig>>;
}

// ── CSPM interfaces ───────────────────────────────────────────────────────────

/// Cloud provider identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
    Other,
}

/// A single finding from a Cloud Security Posture Management (CSPM) tool
/// describing the exposure status of a cloud resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CspmFinding {
    /// Cloud provider this finding originates from.
    pub provider: CloudProvider,
    /// Unique identifier for the cloud resource (e.g. ARN, resource ID).
    pub resource_id: String,
    /// Human-readable resource name.
    pub resource_name: String,
    /// Service or resource type (e.g. "EC2", "Lambda", "GKE").
    pub resource_type: String,
    /// Whether the resource is internet-facing.
    pub internet_facing: bool,
    /// Region or zone the resource is deployed in.
    pub region: String,
    /// Arbitrary tags attached to the resource.
    pub tags: HashMap<String, String>,
}

/// Trait for ingesting CSPM data from various sources (files, APIs, etc.).
///
/// Requirements: 11.1
pub trait CspmIngester: Send + Sync {
    /// Load CSPM findings from a JSON/YAML export file.
    fn ingest_file(&self, path: &std::path::Path) -> Result<Vec<CspmFinding>>;

    /// Load CSPM findings from a directory of export files.
    fn ingest_directory(&self, dir: &std::path::Path) -> Result<Vec<CspmFinding>>;
}

// ── Service exposure mapping ──────────────────────────────────────────────────

/// Maps a source-code file path to the cloud service that runs it, along with
/// the determined exposure status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceExposure {
    /// Source file path (relative to project root).
    pub file_path: PathBuf,
    /// Name of the service that deploys this file.
    pub service_name: String,
    /// Determined exposure status for the service.
    pub exposure: ExposureStatus,
    /// Cloud provider, if known.
    pub provider: Option<CloudProvider>,
    /// Additional context (e.g. Kubernetes namespace, AWS region).
    pub context: HashMap<String, String>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kubernetes_config_loadbalancer_is_public() {
        let cfg = KubernetesConfig {
            kind: "Service".to_string(),
            namespace: "default".to_string(),
            name: "web".to_string(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            service_type: Some("LoadBalancer".to_string()),
            ports: vec![80, 443],
            has_external_ingress: false,
            source_file: PathBuf::from("k8s/service.yaml"),
        };
        assert!(cfg.is_publicly_exposed());
    }

    #[test]
    fn test_kubernetes_config_clusterip_is_internal() {
        let cfg = KubernetesConfig {
            kind: "Service".to_string(),
            namespace: "default".to_string(),
            name: "db".to_string(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            service_type: Some("ClusterIP".to_string()),
            ports: vec![5432],
            has_external_ingress: false,
            source_file: PathBuf::from("k8s/db-service.yaml"),
        };
        assert!(!cfg.is_publicly_exposed());
    }

    #[test]
    fn test_kubernetes_config_ingress_is_public() {
        let cfg = KubernetesConfig {
            kind: "Ingress".to_string(),
            namespace: "default".to_string(),
            name: "api-ingress".to_string(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            service_type: None,
            ports: vec![443],
            has_external_ingress: true,
            source_file: PathBuf::from("k8s/ingress.yaml"),
        };
        assert!(cfg.is_publicly_exposed());
    }

    #[test]
    fn test_exposure_status_variants() {
        assert_ne!(ExposureStatus::PubliclyExposed, ExposureStatus::Internal);
        assert_ne!(ExposureStatus::Internal, ExposureStatus::Unknown);
    }

    #[test]
    fn test_cspm_finding_internet_facing() {
        let finding = CspmFinding {
            provider: CloudProvider::Aws,
            resource_id: "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123".to_string(),
            resource_name: "web-server".to_string(),
            resource_type: "EC2".to_string(),
            internet_facing: true,
            region: "us-east-1".to_string(),
            tags: HashMap::new(),
        };
        assert!(finding.internet_facing);
    }

    #[test]
    fn test_service_exposure_construction() {
        let se = ServiceExposure {
            file_path: PathBuf::from("src/api/handler.rs"),
            service_name: "api-service".to_string(),
            exposure: ExposureStatus::PubliclyExposed,
            provider: Some(CloudProvider::Aws),
            context: HashMap::new(),
        };
        assert_eq!(se.exposure, ExposureStatus::PubliclyExposed);
        assert_eq!(se.service_name, "api-service");
    }
}

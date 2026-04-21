//! Cloud exposure determination
//!
//! Queries Kubernetes configs and CSPM data to identify publicly exposed
//! services, then matches vulnerability file paths to those services.
//!
//! Requirements: 11.2

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::interfaces::{
    CloudProvider, CspmFinding, CspmIngester, ExposureStatus, KubernetesConfig, KubernetesParser,
    ServiceExposure,
};

// ── Kubernetes YAML parser ────────────────────────────────────────────────────

/// Minimal Kubernetes manifest representation for YAML deserialization.
#[derive(Debug, Deserialize)]
struct K8sManifest {
    kind: Option<String>,
    metadata: Option<K8sMetadata>,
    spec: Option<K8sSpec>,
}

#[derive(Debug, Deserialize)]
struct K8sMetadata {
    name: Option<String>,
    namespace: Option<String>,
    labels: Option<HashMap<String, String>>,
    annotations: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct K8sSpec {
    #[serde(rename = "type")]
    service_type: Option<String>,
    ports: Option<Vec<K8sPort>>,
    rules: Option<Vec<serde_yaml::Value>>, // Ingress rules
}

#[derive(Debug, Deserialize)]
struct K8sPort {
    port: Option<u16>,
    #[serde(rename = "targetPort")]
    target_port: Option<serde_yaml::Value>,
}

/// Default implementation of `KubernetesParser` that reads YAML manifests.
pub struct YamlKubernetesParser;

impl KubernetesParser for YamlKubernetesParser {
    fn parse_directory(&self, dir: &Path) -> Result<Vec<KubernetesConfig>> {
        let mut configs = Vec::new();
        for entry in walkdir_yaml(dir)? {
            match self.parse_file(&entry) {
                Ok(mut c) => configs.append(&mut c),
                Err(_) => continue, // skip unparseable files
            }
        }
        Ok(configs)
    }

    fn parse_file(&self, path: &Path) -> Result<Vec<KubernetesConfig>> {
        let content = std::fs::read_to_string(path)?;
        let mut configs = Vec::new();

        // A single YAML file may contain multiple documents separated by `---`
        for doc in content.split("\n---") {
            let trimmed = doc.trim();
            if trimmed.is_empty() {
                continue;
            }
            let manifest: K8sManifest = match serde_yaml::from_str(trimmed) {
                Ok(m) => m,
                Err(_) => continue,
            };

            let kind = manifest.kind.unwrap_or_default();
            if kind.is_empty() {
                continue;
            }

            let meta = manifest.metadata.unwrap_or(K8sMetadata {
                name: None,
                namespace: None,
                labels: None,
                annotations: None,
            });

            let name = meta.name.unwrap_or_default();
            let namespace = meta.namespace.unwrap_or_else(|| "default".to_string());
            let labels = meta.labels.unwrap_or_default();
            let annotations = meta.annotations.unwrap_or_default();

            let (service_type, ports, has_external_ingress) = if let Some(spec) = manifest.spec {
                let svc_type = spec.service_type;
                let port_list: Vec<u16> = spec
                    .ports
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|p| p.port)
                    .collect();
                // An Ingress resource with rules is externally accessible
                let has_ingress =
                    kind == "Ingress" && spec.rules.as_ref().is_some_and(|r| !r.is_empty());
                (svc_type, port_list, has_ingress)
            } else {
                (None, vec![], false)
            };

            configs.push(KubernetesConfig {
                kind,
                namespace,
                name,
                labels,
                annotations,
                service_type,
                ports,
                has_external_ingress,
                source_file: path.to_path_buf(),
            });
        }

        Ok(configs)
    }
}

// ── CSPM JSON ingester ────────────────────────────────────────────────────────

/// Minimal CSPM finding representation for JSON deserialization.
#[derive(Debug, Deserialize)]
struct CspmFindingRaw {
    provider: Option<String>,
    resource_id: Option<String>,
    resource_name: Option<String>,
    resource_type: Option<String>,
    internet_facing: Option<bool>,
    region: Option<String>,
    tags: Option<HashMap<String, String>>,
}

/// Default implementation of `CspmIngester` that reads JSON export files.
pub struct JsonCspmIngester;

impl CspmIngester for JsonCspmIngester {
    fn ingest_file(&self, path: &Path) -> Result<Vec<CspmFinding>> {
        let content = std::fs::read_to_string(path)?;
        let raw: Vec<CspmFindingRaw> = serde_json::from_str(&content)?;
        Ok(raw.into_iter().filter_map(raw_to_finding).collect())
    }

    fn ingest_directory(&self, dir: &Path) -> Result<Vec<CspmFinding>> {
        let mut findings = Vec::new();
        for entry in walkdir_json(dir)? {
            match self.ingest_file(&entry) {
                Ok(mut f) => findings.append(&mut f),
                Err(_) => continue,
            }
        }
        Ok(findings)
    }
}

fn raw_to_finding(raw: CspmFindingRaw) -> Option<CspmFinding> {
    Some(CspmFinding {
        provider: parse_provider(raw.provider.as_deref()),
        resource_id: raw.resource_id?,
        resource_name: raw.resource_name.unwrap_or_default(),
        resource_type: raw.resource_type.unwrap_or_default(),
        internet_facing: raw.internet_facing.unwrap_or(false),
        region: raw.region.unwrap_or_default(),
        tags: raw.tags.unwrap_or_default(),
    })
}

fn parse_provider(s: Option<&str>) -> CloudProvider {
    match s.map(|v| v.to_lowercase()).as_deref() {
        Some("aws") => CloudProvider::Aws,
        Some("gcp") | Some("google") => CloudProvider::Gcp,
        Some("azure") => CloudProvider::Azure,
        _ => CloudProvider::Other,
    }
}

// ── CloudExposureAnalyzer ─────────────────────────────────────────────────────

/// Determines whether source files are deployed in publicly exposed services
/// by correlating Kubernetes configs and CSPM findings with file paths.
///
/// Requirements: 11.2
pub struct CloudExposureAnalyzer {
    k8s_parser: Box<dyn KubernetesParser>,
    cspm_ingester: Box<dyn CspmIngester>,
    /// Cached exposure map: service_name → ExposureStatus
    exposure_cache: HashMap<String, ExposureStatus>,
    /// Cached service configs
    k8s_configs: Vec<KubernetesConfig>,
    /// Cached CSPM findings
    cspm_findings: Vec<CspmFinding>,
}

impl CloudExposureAnalyzer {
    /// Create a new analyzer with the default YAML/JSON parsers.
    pub fn new() -> Self {
        Self {
            k8s_parser: Box::new(YamlKubernetesParser),
            cspm_ingester: Box::new(JsonCspmIngester),
            exposure_cache: HashMap::new(),
            k8s_configs: Vec::new(),
            cspm_findings: Vec::new(),
        }
    }

    /// Create an analyzer with custom parser/ingester implementations (for testing).
    pub fn with_parsers(
        k8s_parser: Box<dyn KubernetesParser>,
        cspm_ingester: Box<dyn CspmIngester>,
    ) -> Self {
        Self {
            k8s_parser,
            cspm_ingester,
            exposure_cache: HashMap::new(),
            k8s_configs: Vec::new(),
            cspm_findings: Vec::new(),
        }
    }

    /// Load Kubernetes manifests from a directory.
    pub fn load_kubernetes_configs(&mut self, dir: &Path) -> Result<()> {
        let configs = self.k8s_parser.parse_directory(dir)?;
        self.k8s_configs.extend(configs);
        self.rebuild_exposure_cache();
        Ok(())
    }

    /// Load CSPM findings from a directory of JSON export files.
    pub fn load_cspm_findings(&mut self, dir: &Path) -> Result<()> {
        let findings = self.cspm_ingester.ingest_directory(dir)?;
        self.cspm_findings.extend(findings);
        self.rebuild_exposure_cache();
        Ok(())
    }

    /// Directly ingest pre-parsed Kubernetes configs (useful for testing).
    pub fn ingest_kubernetes_configs(&mut self, configs: Vec<KubernetesConfig>) {
        self.k8s_configs.extend(configs);
        self.rebuild_exposure_cache();
    }

    /// Directly ingest pre-parsed CSPM findings (useful for testing).
    pub fn ingest_cspm_findings(&mut self, findings: Vec<CspmFinding>) {
        self.cspm_findings.extend(findings);
        self.rebuild_exposure_cache();
    }

    /// Determine the exposure status for a given source file path.
    ///
    /// Matches the file path against known service names derived from
    /// Kubernetes configs and CSPM findings.
    ///
    /// Requirements: 11.2
    pub fn exposure_for_file(&self, file_path: &Path) -> ServiceExposure {
        // Derive a service name from the file path (best-effort heuristic)
        let service_name = infer_service_name(file_path);

        let exposure = self
            .exposure_cache
            .get(&service_name)
            .copied()
            .unwrap_or(ExposureStatus::Unknown);

        // Find provider context from CSPM findings
        let provider = self
            .cspm_findings
            .iter()
            .find(|f| {
                f.resource_name.to_lowercase().contains(&service_name)
                    || service_name.contains(&f.resource_name.to_lowercase())
            })
            .map(|f| f.provider);

        let mut context = HashMap::new();
        if let Some(cfg) = self.k8s_configs.iter().find(|c| {
            c.name.to_lowercase().contains(&service_name)
                || service_name.contains(&c.name.to_lowercase())
        }) {
            context.insert("namespace".to_string(), cfg.namespace.clone());
            context.insert("kind".to_string(), cfg.kind.clone());
        }

        ServiceExposure {
            file_path: file_path.to_path_buf(),
            service_name,
            exposure,
            provider,
            context,
        }
    }

    /// Return all service exposures for a list of file paths.
    pub fn exposures_for_files(&self, file_paths: &[PathBuf]) -> Vec<ServiceExposure> {
        file_paths
            .iter()
            .map(|p| self.exposure_for_file(p))
            .collect()
    }

    /// Return `true` if the given file is deployed in a publicly exposed service.
    pub fn is_publicly_exposed(&self, file_path: &Path) -> bool {
        self.exposure_for_file(file_path).exposure == ExposureStatus::PubliclyExposed
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Rebuild the service-name → ExposureStatus cache from loaded data.
    fn rebuild_exposure_cache(&mut self) {
        self.exposure_cache.clear();

        // From Kubernetes configs
        for cfg in &self.k8s_configs {
            let status = if cfg.is_publicly_exposed() {
                ExposureStatus::PubliclyExposed
            } else {
                ExposureStatus::Internal
            };
            // Normalise service name to lowercase for case-insensitive matching
            self.exposure_cache
                .entry(cfg.name.to_lowercase())
                .and_modify(|e| {
                    // PubliclyExposed wins over Internal
                    if status == ExposureStatus::PubliclyExposed {
                        *e = status;
                    }
                })
                .or_insert(status);
        }

        // From CSPM findings — internet_facing overrides k8s-derived status
        for finding in &self.cspm_findings {
            let status = if finding.internet_facing {
                ExposureStatus::PubliclyExposed
            } else {
                ExposureStatus::Internal
            };
            self.exposure_cache
                .entry(finding.resource_name.to_lowercase())
                .and_modify(|e| {
                    if status == ExposureStatus::PubliclyExposed {
                        *e = status;
                    }
                })
                .or_insert(status);
        }
    }
}

impl Default for CloudExposureAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Heuristic: infer service name from file path ──────────────────────────────

/// Infer a service name from a source file path using common project layout conventions.
///
/// Examples:
/// - `services/api/src/handler.rs` → `api`
/// - `src/auth/mod.rs` → `auth`
/// - `handler.rs` → `handler`
fn infer_service_name(path: &Path) -> String {
    let components: Vec<&str> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();

    // Look for well-known directory names that indicate a service boundary
    let service_dirs = ["services", "apps", "microservices", "packages", "modules"];
    for (i, component) in components.iter().enumerate() {
        if service_dirs.contains(component) {
            if let Some(service) = components.get(i + 1) {
                return service.to_lowercase();
            }
        }
    }

    // Fall back to the first meaningful directory component (skip "src", "lib", etc.)
    let skip = ["src", "lib", "pkg", "internal", "cmd", "app"];
    for component in &components {
        let lower = component.to_lowercase();
        if !skip.contains(&lower.as_str()) && !lower.contains('.') {
            return lower;
        }
    }

    // Last resort: use the file stem
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_lowercase()
}

// ── Directory walking helpers ─────────────────────────────────────────────────

fn walkdir_yaml(dir: &Path) -> Result<Vec<PathBuf>> {
    walkdir_ext(dir, &["yaml", "yml"])
}

fn walkdir_json(dir: &Path) -> Result<Vec<PathBuf>> {
    walkdir_ext(dir, &["json"])
}

fn walkdir_ext(dir: &Path, extensions: &[&str]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    if !dir.is_dir() {
        return Ok(paths);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            paths.extend(walkdir_ext(&path, extensions)?);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if extensions.contains(&ext) {
                paths.push(path);
            }
        }
    }
    Ok(paths)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_k8s_service(name: &str, svc_type: &str) -> KubernetesConfig {
        KubernetesConfig {
            kind: "Service".to_string(),
            namespace: "default".to_string(),
            name: name.to_string(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            service_type: Some(svc_type.to_string()),
            ports: vec![80],
            has_external_ingress: false,
            source_file: PathBuf::from("k8s/service.yaml"),
        }
    }

    fn make_cspm_finding(name: &str, internet_facing: bool) -> CspmFinding {
        CspmFinding {
            provider: CloudProvider::Aws,
            resource_id: format!("arn:aws:ec2:us-east-1:123456789012:instance/{}", name),
            resource_name: name.to_string(),
            resource_type: "EC2".to_string(),
            internet_facing,
            region: "us-east-1".to_string(),
            tags: HashMap::new(),
        }
    }

    #[test]
    fn test_loadbalancer_service_is_public() {
        let mut analyzer = CloudExposureAnalyzer::new();
        analyzer.ingest_kubernetes_configs(vec![make_k8s_service("api", "LoadBalancer")]);

        let exposure = analyzer.exposure_for_file(Path::new("services/api/src/handler.rs"));
        assert_eq!(exposure.exposure, ExposureStatus::PubliclyExposed);
    }

    #[test]
    fn test_clusterip_service_is_internal() {
        let mut analyzer = CloudExposureAnalyzer::new();
        analyzer.ingest_kubernetes_configs(vec![make_k8s_service("db", "ClusterIP")]);

        let exposure = analyzer.exposure_for_file(Path::new("services/db/src/queries.rs"));
        assert_eq!(exposure.exposure, ExposureStatus::Internal);
    }

    #[test]
    fn test_unknown_file_returns_unknown() {
        let analyzer = CloudExposureAnalyzer::new();
        let exposure = analyzer.exposure_for_file(Path::new("src/utils.rs"));
        assert_eq!(exposure.exposure, ExposureStatus::Unknown);
    }

    #[test]
    fn test_cspm_internet_facing_overrides() {
        let mut analyzer = CloudExposureAnalyzer::new();
        // K8s says internal, CSPM says public
        analyzer.ingest_kubernetes_configs(vec![make_k8s_service("web", "ClusterIP")]);
        analyzer.ingest_cspm_findings(vec![make_cspm_finding("web", true)]);

        let exposure = analyzer.exposure_for_file(Path::new("services/web/handler.rs"));
        assert_eq!(exposure.exposure, ExposureStatus::PubliclyExposed);
    }

    #[test]
    fn test_is_publicly_exposed_helper() {
        let mut analyzer = CloudExposureAnalyzer::new();
        analyzer.ingest_kubernetes_configs(vec![make_k8s_service("api", "LoadBalancer")]);

        assert!(analyzer.is_publicly_exposed(Path::new("services/api/main.rs")));
        assert!(!analyzer.is_publicly_exposed(Path::new("services/internal/main.rs")));
    }

    #[test]
    fn test_infer_service_name_services_dir() {
        assert_eq!(
            infer_service_name(Path::new("services/api/src/handler.rs")),
            "api"
        );
    }

    #[test]
    fn test_infer_service_name_apps_dir() {
        assert_eq!(infer_service_name(Path::new("apps/auth/mod.rs")), "auth");
    }

    #[test]
    fn test_infer_service_name_fallback() {
        assert_eq!(infer_service_name(Path::new("handler.rs")), "handler");
    }

    #[test]
    fn test_parse_kubernetes_yaml() {
        let temp = TempDir::new().unwrap();
        let yaml = r#"
apiVersion: v1
kind: Service
metadata:
  name: web-api
  namespace: production
spec:
  type: LoadBalancer
  ports:
    - port: 443
"#;
        let path = temp.path().join("service.yaml");
        fs::write(&path, yaml).unwrap();

        let parser = YamlKubernetesParser;
        let configs = parser.parse_file(&path).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "web-api");
        assert_eq!(configs[0].namespace, "production");
        assert_eq!(configs[0].service_type.as_deref(), Some("LoadBalancer"));
        assert!(configs[0].is_publicly_exposed());
    }

    #[test]
    fn test_parse_kubernetes_yaml_ingress() {
        let temp = TempDir::new().unwrap();
        let yaml = r#"
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
spec:
  rules:
    - host: api.example.com
"#;
        let path = temp.path().join("ingress.yaml");
        fs::write(&path, yaml).unwrap();

        let parser = YamlKubernetesParser;
        let configs = parser.parse_file(&path).unwrap();
        assert_eq!(configs.len(), 1);
        assert!(configs[0].has_external_ingress);
        assert!(configs[0].is_publicly_exposed());
    }

    #[test]
    fn test_parse_cspm_json() {
        let temp = TempDir::new().unwrap();
        let json = r#"[
  {
    "provider": "aws",
    "resource_id": "arn:aws:ec2:us-east-1:123:instance/i-abc",
    "resource_name": "web-server",
    "resource_type": "EC2",
    "internet_facing": true,
    "region": "us-east-1",
    "tags": {}
  }
]"#;
        let path = temp.path().join("findings.json");
        fs::write(&path, json).unwrap();

        let ingester = JsonCspmIngester;
        let findings = ingester.ingest_file(&path).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].resource_name, "web-server");
        assert!(findings[0].internet_facing);
        assert_eq!(findings[0].provider, CloudProvider::Aws);
    }

    #[test]
    fn test_exposures_for_files() {
        let mut analyzer = CloudExposureAnalyzer::new();
        analyzer.ingest_kubernetes_configs(vec![
            make_k8s_service("api", "LoadBalancer"),
            make_k8s_service("db", "ClusterIP"),
        ]);

        let files = vec![
            PathBuf::from("services/api/handler.rs"),
            PathBuf::from("services/db/queries.rs"),
        ];
        let exposures = analyzer.exposures_for_files(&files);
        assert_eq!(exposures.len(), 2);
        assert_eq!(exposures[0].exposure, ExposureStatus::PubliclyExposed);
        assert_eq!(exposures[1].exposure, ExposureStatus::Internal);
    }
}

//! SARIF v2.1.0 emitter.
//!
//! Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9

use serde::{Deserialize, Serialize};

use crate::engine::vulnerability::{Severity, Vulnerability};

// ─── SARIF Data Model ─────────────────────────────────────────────────────────

/// Top-level SARIF v2.1.0 document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDocument {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

/// A single SARIF run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

/// Tool metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

/// Tool driver with rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "semanticVersion")]
    pub semantic_version: String,
    pub rules: Vec<SarifRule>,
}

/// A SARIF rule descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifRuleConfig,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
}

/// Rule default configuration (severity level).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRuleConfig {
    pub level: String,
}

/// A SARIF result (one per finding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub message: SarifMessage,
    pub level: String,
    pub locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taxa: Option<Vec<SarifTaxon>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifPropertyBag>,
}

/// A text message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

/// Physical location of a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

/// Physical location details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

/// Artifact (file) location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

/// Code region (line/column).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
    #[serde(rename = "startColumn")]
    pub start_column: usize,
}

/// CWE taxon reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTaxon {
    pub id: String,
    #[serde(rename = "toolComponent")]
    pub tool_component: SarifToolComponentRef,
}

/// Reference to a tool component (for taxa).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifToolComponentRef {
    pub name: String,
}

/// Property bag for extra metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPropertyBag {
    /// Confidence rank on 0–100 scale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<f64>,
}

// ─── Severity Mapping ─────────────────────────────────────────────────────────

/// Map Sicario severity to SARIF level string.
pub fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

// ─── SarifEmitter Trait + Implementation ──────────────────────────────────────

/// Trait for emitting SARIF documents from findings.
pub trait SarifEmitter {
    fn emit(&self, findings: &[Vulnerability], tool_version: &str) -> SarifDocument;
}

/// Default SARIF emitter implementation.
pub struct DefaultSarifEmitter;

impl SarifEmitter for DefaultSarifEmitter {
    fn emit(&self, findings: &[Vulnerability], tool_version: &str) -> SarifDocument {
        emit_sarif(findings, tool_version)
    }
}

/// Build a complete SARIF document from a list of vulnerabilities.
pub fn emit_sarif(vulns: &[Vulnerability], tool_version: &str) -> SarifDocument {
    // Collect unique rules
    let mut seen_rules = std::collections::HashSet::new();
    let mut rules = Vec::new();

    for v in vulns {
        if seen_rules.insert(v.rule_id.clone()) {
            rules.push(SarifRule {
                id: v.rule_id.clone(),
                short_description: SarifMessage {
                    text: v.rule_id.clone(),
                },
                default_configuration: SarifRuleConfig {
                    level: severity_to_sarif_level(&v.severity).to_string(),
                },
                help_uri: None,
            });
        }
    }

    let results: Vec<SarifResult> = vulns.iter().map(|v| {
        let taxa = v.cwe_id.as_ref().map(|cwe| {
            vec![SarifTaxon {
                id: cwe.clone(),
                tool_component: SarifToolComponentRef {
                    name: "CWE".to_string(),
                },
            }]
        });

        // Confidence score: use 1.0 (100) as default since confidence scoring
        // is not yet wired; the rank field is always present per spec.
        let confidence_score = 1.0_f64;

        SarifResult {
            rule_id: v.rule_id.clone(),
            message: SarifMessage {
                text: format!(
                    "{} at {}:{}",
                    v.rule_id,
                    v.file_path.display(),
                    v.line
                ),
            },
            level: severity_to_sarif_level(&v.severity).to_string(),
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: v.file_path.display().to_string(),
                    },
                    region: SarifRegion {
                        start_line: v.line,
                        start_column: v.column,
                    },
                },
            }],
            taxa,
            properties: Some(SarifPropertyBag {
                rank: Some(confidence_score * 100.0),
            }),
        }
    }).collect();

    SarifDocument {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "Sicario".to_string(),
                    version: tool_version.to_string(),
                    semantic_version: tool_version.to_string(),
                    rules,
                },
            },
            results,
        }],
    }
}

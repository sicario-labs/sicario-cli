//! Agent selection for the `--agent` flag.
//!
//! Parses the `--agent` CLI flag and returns an `AgentConfig` that controls
//! which remediation backend is used.  Valid flag values are:
//!
//! - `local`           — use the local Ollama instance (auto-selects model)
//! - `local-<model>`   — use the local Ollama instance with a specific model
//! - `cloud`           — use the configured cloud LLM provider
//!
//! When `None` is passed (flag absent), `AgentConfig::Auto` is returned,
//! which preserves the existing behaviour.
//!
//! Requirements: eta-engine 1.1

use anyhow::{bail, Result};

/// The remediation agent to use for a `sicario fix` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentConfig {
    /// Use the local Ollama instance.
    ///
    /// When `model_override` is `Some`, the probe step is skipped and the
    /// provided model name is used directly.  When `None`, the probe selects
    /// the best available model by priority.
    ///
    /// Implicitly sets `allow_ai = true` — no consent prompt is shown for
    /// localhost calls.
    Local { model_override: Option<String> },

    /// Use the configured cloud LLM provider.
    Cloud,

    /// Default: preserve existing behaviour (no `--agent` flag was passed).
    Auto,
}

/// Parses the `--agent` flag value into an `AgentConfig`.
pub struct AgentSelector;

impl AgentSelector {
    /// Parse the optional `--agent` flag value.
    ///
    /// Returns:
    /// - `Ok(AgentConfig::Auto)`                        when `flag` is `None`
    /// - `Ok(AgentConfig::Local { model_override: None })` for `"local"`
    /// - `Ok(AgentConfig::Local { model_override: Some(m) })` for `"local-<model>"`
    /// - `Ok(AgentConfig::Cloud)`                       for `"cloud"`
    /// - `Err(...)` for any other value, with a descriptive message listing
    ///   valid values
    pub fn parse(flag: Option<&str>) -> Result<AgentConfig> {
        match flag {
            None => Ok(AgentConfig::Auto),
            Some("local") => Ok(AgentConfig::Local {
                model_override: None,
            }),
            Some("cloud") => Ok(AgentConfig::Cloud),
            Some(value) if value.starts_with("local-") => {
                let model = value["local-".len()..].to_string();
                if model.is_empty() {
                    bail!(
                        "Invalid --agent value: '{}'. \
                         Valid values are: 'local', 'local-<model>' (e.g. 'local-qwen2.5-coder:7b'), 'cloud'.",
                        value
                    );
                }
                Ok(AgentConfig::Local {
                    model_override: Some(model),
                })
            }
            Some(value) => {
                bail!(
                    "Invalid --agent value: '{}'. \
                     Valid values are: 'local', 'local-<model>' (e.g. 'local-qwen2.5-coder:7b'), 'cloud'.",
                    value
                );
            }
        }
    }

    /// Returns `true` when the config implies `allow_ai = true` implicitly.
    ///
    /// For `AgentConfig::Local`, AI consent is granted without an interactive
    /// prompt because all calls go to `127.0.0.1:11434` — no code leaves the
    /// machine.
    pub fn implicit_allow_ai(config: &AgentConfig) -> bool {
        matches!(config, AgentConfig::Local { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_none_returns_auto() {
        let result = AgentSelector::parse(None).unwrap();
        assert_eq!(result, AgentConfig::Auto);
    }

    #[test]
    fn test_parse_local_returns_local_no_model() {
        let result = AgentSelector::parse(Some("local")).unwrap();
        assert_eq!(
            result,
            AgentConfig::Local {
                model_override: None
            }
        );
    }

    #[test]
    fn test_parse_local_with_model_returns_local_with_model() {
        let result = AgentSelector::parse(Some("local-qwen2.5-coder:7b")).unwrap();
        assert_eq!(
            result,
            AgentConfig::Local {
                model_override: Some("qwen2.5-coder:7b".to_string())
            }
        );
    }

    #[test]
    fn test_parse_cloud_returns_cloud() {
        let result = AgentSelector::parse(Some("cloud")).unwrap();
        assert_eq!(result, AgentConfig::Cloud);
    }

    #[test]
    fn test_parse_invalid_returns_err() {
        let result = AgentSelector::parse(Some("invalid"));
        assert!(result.is_err(), "Expected Err for invalid value");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Invalid --agent value"),
            "Error should mention invalid value: {err_msg}"
        );
        assert!(
            err_msg.contains("local"),
            "Error should list valid values: {err_msg}"
        );
        assert!(
            err_msg.contains("cloud"),
            "Error should list valid values: {err_msg}"
        );
    }

    #[test]
    fn test_parse_local_dash_empty_returns_err() {
        // "local-" with no model name is invalid
        let result = AgentSelector::parse(Some("local-"));
        assert!(result.is_err(), "Expected Err for 'local-' with no model");
    }

    #[test]
    fn test_parse_local_with_deepseek_model() {
        let result = AgentSelector::parse(Some("local-deepseek-coder-v2")).unwrap();
        assert_eq!(
            result,
            AgentConfig::Local {
                model_override: Some("deepseek-coder-v2".to_string())
            }
        );
    }

    #[test]
    fn test_implicit_allow_ai_local_is_true() {
        let config = AgentConfig::Local {
            model_override: None,
        };
        assert!(AgentSelector::implicit_allow_ai(&config));
    }

    #[test]
    fn test_implicit_allow_ai_local_with_model_is_true() {
        let config = AgentConfig::Local {
            model_override: Some("qwen2.5-coder:7b".to_string()),
        };
        assert!(AgentSelector::implicit_allow_ai(&config));
    }

    #[test]
    fn test_implicit_allow_ai_cloud_is_false() {
        assert!(!AgentSelector::implicit_allow_ai(&AgentConfig::Cloud));
    }

    #[test]
    fn test_implicit_allow_ai_auto_is_false() {
        assert!(!AgentSelector::implicit_allow_ai(&AgentConfig::Auto));
    }
}

//! Provider-agnostic LLM client for AI-powered code remediation.
//!
//! Speaks the OpenAI chat completions protocol, which is supported by:
//! OpenAI, Anthropic (via proxy), Cerebras, Groq, Together, Ollama,
//! vLLM, LM Studio, OpenRouter, Azure OpenAI, and many others.
//!
//! Configuration is resolved via the `key_manager` module:
//!   - Endpoint: SICARIO_LLM_ENDPOINT > OPENAI_BASE_URL > CEREBRAS_ENDPOINT > default
//!   - Model:    SICARIO_LLM_MODEL > CEREBRAS_MODEL > default
//!   - API Key:  SICARIO_LLM_API_KEY > keyring > OPENAI_API_KEY > CEREBRAS_API_KEY
//!
//! Requirements: 11.1, 11.2, 11.3, 11.4

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::FixContext;
use crate::key_manager;

// ── OpenAI-compatible request/response types ──────────────────────────────────

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: ChatMessageResponse,
}

#[derive(Debug, Deserialize)]
struct ChatMessageResponse {
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

// ── System prompt ─────────────────────────────────────────────────────────────

const SECURITY_FIX_SYSTEM_PROMPT: &str = r#"You are an expert security engineer specializing in code remediation.
Your task is to generate a minimal, correct security fix for the provided vulnerability.

Rules:
1. Return ONLY the fixed code — no explanations, no markdown fences, no commentary.
2. Preserve the original code style, indentation, and surrounding logic.
3. Make the smallest change necessary to eliminate the vulnerability.
4. The fix must be syntactically valid for the specified language.
5. Do not introduce new dependencies unless absolutely necessary.
6. If the fix requires a parameterized query, use the idiomatic approach for the language/framework."#;

// ── Provider-agnostic client ──────────────────────────────────────────────────

/// Resolved provider configuration (for display/diagnostics).
#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub endpoint: String,
    pub model: String,
    pub key_source: key_manager::KeySource,
    pub has_key: bool,
}

/// Provider-agnostic LLM client that speaks the OpenAI chat completions protocol.
///
/// Works with any provider that exposes a `/v1/chat/completions` endpoint:
/// OpenAI, Cerebras, Groq, Together, Ollama, vLLM, LM Studio, OpenRouter, etc.
pub struct LlmClient {
    api_key: Option<String>,
    endpoint: String,
    model: String,
    key_source: key_manager::KeySource,
    client: Client,
}

impl LlmClient {
    /// Create a new LLM client with configuration resolved from env/keyring/global config.
    ///
    /// Resolution order for LLM API key:
    /// 1. `SICARIO_LLM_API_KEY` env var
    /// 2. OS keyring (set via `sicario config set-key`)
    /// 3. `OPENAI_API_KEY` env var
    /// 4. `CEREBRAS_API_KEY` env var
    /// 5. `.sicario/config.yaml` (project-local)
    /// 6. `~/.sicario/config.toml` via `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` (global BYOK)
    /// 7. Cloud config (authenticated users only)
    ///
    /// Note: `SICARIO_API_KEY` is **never** used here — it is strictly reserved
    /// for authenticating HTTP requests to the Convex telemetry endpoint.
    pub fn new() -> Result<Self> {
        let resolved = key_manager::resolve_api_key();
        let (api_key, key_source) = match resolved {
            Some(r) => (Some(r.key), r.source),
            None => {
                // Fallback: check ~/.sicario/config.toml for BYOK LLM keys
                if let Some(llm_res) = crate::config::resolve_llm_api_key() {
                    (Some(llm_res.key), key_manager::KeySource::ConfigFile)
                } else {
                    (None, key_manager::KeySource::None)
                }
            }
        };

        let endpoint = key_manager::resolve_endpoint();
        let model = key_manager::resolve_model();

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            api_key,
            endpoint,
            model,
            key_source,
            client,
        })
    }

    /// Return the resolved configuration (for `sicario config show`).
    pub fn config(&self) -> LlmConfig {
        LlmConfig {
            endpoint: self.endpoint.clone(),
            model: self.model.clone(),
            key_source: self.key_source.clone(),
            has_key: self.api_key.is_some(),
        }
    }

    /// Generate a security fix for the given context using the LLM.
    ///
    /// Returns the raw fixed code string as returned by the model.
    /// Callers are responsible for syntax validation before applying.
    pub async fn generate_fix(&self, context: &FixContext) -> Result<String> {
        let api_key = self.api_key.as_deref().ok_or_else(|| {
            anyhow!(
                "No LLM API key configured.\n\n\
                 Set one of the following:\n  \
                 • ANTHROPIC_API_KEY env var (recommended)\n  \
                 • OPENAI_API_KEY env var\n  \
                 • sicario config set ANTHROPIC_API_KEY <key>  (saves to ~/.sicario/config.toml)\n  \
                 • sicario config set OPENAI_API_KEY <key>\n  \
                 • SICARIO_LLM_API_KEY env var\n  \
                 • sicario config set-key (stores in OS keyring)\n\n\
                 Or use a local model (no key needed):\n  \
                 • SICARIO_LLM_ENDPOINT=http://localhost:11434/v1/chat/completions\n  \
                 • SICARIO_LLM_MODEL=llama3.1\n\n\
                 Note: SICARIO_API_KEY is for telemetry uploads only, not LLM auth."
            )
        })?;

        let user_prompt = build_user_prompt(context);

        let request = ChatRequest {
            model: self.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: SECURITY_FIX_SYSTEM_PROMPT.to_string(),
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: user_prompt,
                },
            ],
            max_tokens: 1024,
            temperature: 0.1,
        };

        let mut req_builder = self.client.post(&self.endpoint).json(&request);

        // Only send auth header if we have a key (Ollama/local models don't need one,
        // but we still need to handle the case where endpoint doesn't require auth)
        if !api_key.is_empty() {
            req_builder = req_builder.bearer_auth(api_key);
        }

        let response = req_builder
            .send()
            .await
            .context("Failed to send request to LLM endpoint")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "LLM API returned error {} from {}: {}",
                status,
                self.endpoint,
                body
            ));
        }

        let chat_response: ChatResponse = response
            .json()
            .await
            .context("Failed to parse LLM API response")?;

        chat_response
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content.trim().to_string())
            .ok_or_else(|| anyhow!("LLM API returned no choices"))
    }
}

impl Default for LlmClient {
    fn default() -> Self {
        Self::new().expect("Failed to create LLM client")
    }
}

// ── Prompt construction ───────────────────────────────────────────────────────

fn build_user_prompt(context: &FixContext) -> String {
    let mut prompt = String::new();

    prompt.push_str(&format!("Language: {}\n", context.file_language));

    if let Some(fw) = &context.framework {
        prompt.push_str(&format!("Framework: {}\n", fw));
    }

    if let Some(cwe) = &context.cwe_id {
        prompt.push_str(&format!("CWE: {}\n", cwe));
    }

    prompt.push_str(&format!(
        "Vulnerability: {}\n\n",
        context.vulnerability_description
    ));

    prompt.push_str("Vulnerable code:\n```\n");
    prompt.push_str(&context.code_snippet);
    prompt.push_str("\n```\n\n");
    prompt.push_str("Provide the fixed code:");

    prompt
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context() -> FixContext {
        FixContext {
            vulnerability_description: "SQL Injection via string concatenation".to_string(),
            code_snippet: r#"query = "SELECT * FROM users WHERE id = " + user_id"#.to_string(),
            file_language: "Python".to_string(),
            framework: Some("Django".to_string()),
            cwe_id: Some("CWE-89".to_string()),
        }
    }

    #[test]
    fn test_client_construction() {
        let client = LlmClient::new();
        assert!(client.is_ok());
    }

    #[test]
    fn test_config_reports_key_source() {
        let client = LlmClient::new().unwrap();
        let config = client.config();
        // Should always have an endpoint and model, even without a key
        assert!(!config.endpoint.is_empty());
        assert!(!config.model.is_empty());
    }

    #[test]
    fn test_build_user_prompt_contains_language() {
        let ctx = make_context();
        let prompt = build_user_prompt(&ctx);
        assert!(prompt.contains("Python"));
    }

    #[test]
    fn test_build_user_prompt_contains_framework() {
        let ctx = make_context();
        let prompt = build_user_prompt(&ctx);
        assert!(prompt.contains("Django"));
    }

    #[test]
    fn test_build_user_prompt_contains_cwe() {
        let ctx = make_context();
        let prompt = build_user_prompt(&ctx);
        assert!(prompt.contains("CWE-89"));
    }

    #[test]
    fn test_build_user_prompt_contains_snippet() {
        let ctx = make_context();
        let prompt = build_user_prompt(&ctx);
        assert!(prompt.contains("SELECT * FROM users"));
    }

    #[test]
    fn test_build_user_prompt_no_framework() {
        let ctx = FixContext {
            vulnerability_description: "XSS".to_string(),
            code_snippet: "innerHTML = userInput".to_string(),
            file_language: "JavaScript".to_string(),
            framework: None,
            cwe_id: None,
        };
        let prompt = build_user_prompt(&ctx);
        assert!(!prompt.contains("Framework:"));
        assert!(!prompt.contains("CWE:"));
    }

    #[tokio::test]
    async fn test_generate_fix_fails_without_api_key() {
        // Clear all possible key sources
        std::env::remove_var("SICARIO_LLM_API_KEY");
        std::env::remove_var("OPENAI_API_KEY");
        std::env::remove_var("CEREBRAS_API_KEY");

        // Build client with no key
        let client = LlmClient {
            api_key: None,
            endpoint: "https://example.com".to_string(),
            model: "test".to_string(),
            key_source: key_manager::KeySource::None,
            client: Client::new(),
        };

        let ctx = make_context();
        let result = client.generate_fix(&ctx).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("No LLM API key configured"));
    }

    #[test]
    fn test_default_endpoint_is_openai() {
        // When no env vars are set, should default to OpenAI
        std::env::remove_var("SICARIO_LLM_ENDPOINT");
        std::env::remove_var("OPENAI_BASE_URL");
        std::env::remove_var("CEREBRAS_ENDPOINT");
        let ep = key_manager::resolve_endpoint();
        assert!(ep.contains("openai.com"));
    }

    #[test]
    fn test_default_model() {
        std::env::remove_var("SICARIO_LLM_MODEL");
        std::env::remove_var("CEREBRAS_MODEL");
        let model = key_manager::resolve_model();
        assert_eq!(model, "gpt-4o-mini");
    }
}

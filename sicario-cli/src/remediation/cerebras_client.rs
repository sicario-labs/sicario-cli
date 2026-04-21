//! Cerebras API client for AI-powered code generation
//!
//! Implements async HTTP communication with the Cerebras LLM API to generate
//! security fix suggestions. Handles API errors, timeouts, and fallback logic.
//!
//! Requirements: 13.1, 13.2, 13.3

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::FixContext;

// ── Request / response types ──────────────────────────────────────────────────

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

// ── Client ────────────────────────────────────────────────────────────────────

/// Client for the Cerebras LLM API (or any OpenAI-compatible endpoint).
///
/// Reads `CEREBRAS_API_KEY` from the environment. If the key is absent the
/// client is still constructed but `generate_fix` will return an error.
pub struct CerebrasClient {
    api_key: String,
    endpoint: String,
    model: String,
    client: Client,
}

impl CerebrasClient {
    /// Create a new Cerebras client.
    ///
    /// The API key is read from the `CEREBRAS_API_KEY` environment variable.
    /// The endpoint defaults to the Cerebras chat-completions URL but can be
    /// overridden via `CEREBRAS_ENDPOINT` for testing or alternative providers.
    pub fn new() -> Result<Self> {
        let api_key = std::env::var("CEREBRAS_API_KEY").unwrap_or_default();
        let endpoint = std::env::var("CEREBRAS_ENDPOINT")
            .unwrap_or_else(|_| "https://api.cerebras.ai/v1/chat/completions".to_string());
        let model = std::env::var("CEREBRAS_MODEL")
            .unwrap_or_else(|_| "llama3.1-8b".to_string());

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            api_key,
            endpoint,
            model,
            client,
        })
    }

    /// Generate a security fix for the given context using the LLM.
    ///
    /// Returns the raw fixed code string as returned by the model.
    /// Callers are responsible for syntax validation before presenting to users.
    pub async fn generate_fix(&self, context: &FixContext) -> Result<String> {
        if self.api_key.is_empty() {
            return Err(anyhow!(
                "CEREBRAS_API_KEY is not set — cannot generate AI fix"
            ));
        }

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
            temperature: 0.1, // Low temperature for deterministic security fixes
        };

        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.api_key)
            .json(&request)
            .send()
            .await
            .context("Failed to send request to Cerebras API")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Cerebras API returned error {}: {}",
                status,
                body
            ));
        }

        let chat_response: ChatResponse = response
            .json()
            .await
            .context("Failed to parse Cerebras API response")?;

        chat_response
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content.trim().to_string())
            .ok_or_else(|| anyhow!("Cerebras API returned no choices"))
    }
}

impl Default for CerebrasClient {
    fn default() -> Self {
        Self::new().expect("Failed to create Cerebras client")
    }
}

// ── Prompt construction ───────────────────────────────────────────────────────

/// Build the user-facing prompt from a `FixContext`.
fn build_user_prompt(context: &FixContext) -> String {
    let mut prompt = String::new();

    prompt.push_str(&format!(
        "Language: {}\n",
        context.file_language
    ));

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
        // Should succeed even without an API key set
        let client = CerebrasClient::new();
        assert!(client.is_ok());
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
        // Ensure no key is set for this test
        std::env::remove_var("CEREBRAS_API_KEY");
        let client = CerebrasClient::new().unwrap();
        let ctx = make_context();
        let result = client.generate_fix(&ctx).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("CEREBRAS_API_KEY"));
    }
}

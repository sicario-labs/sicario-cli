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

// ── System prompt (XML protocol) ──────────────────────────────────────────────

/// System prompt that enforces the XML output protocol.
///
/// The model MUST wrap its reasoning in <scratchpad> and the exact replacement
/// code in <sicario_patch>. This makes extraction deterministic regardless of
/// how the model formats prose or commentary.
const SECURITY_FIX_SYSTEM_PROMPT: &str = r#"You are an expert security engineer specializing in minimal, surgical code remediation.

OUTPUT FORMAT — MANDATORY:
You MUST respond using EXACTLY this XML structure and nothing else outside it:

<scratchpad>
Brief analysis: what the vulnerability is and what the minimal fix is.
</scratchpad>
<sicario_patch>
EXACT replacement code here — raw source only, no markdown, no fences, no commentary
</sicario_patch>

RULES:
1. The <sicario_patch> block contains ONLY the raw replacement lines for the vulnerable code shown.
2. Do NOT wrap code in backticks or markdown fences inside <sicario_patch>.
3. Do NOT include the entire file — only the lines that replace the vulnerable snippet.
4. Preserve original indentation exactly.
5. Make the smallest change that eliminates the vulnerability.
6. The replacement must be syntactically valid for the specified language.
7. Do not introduce new dependencies unless absolutely necessary."#;

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

    /// Generate a security fix using the XML protocol.
    ///
    /// Returns the raw LLM response string. Callers must call
    /// `extract_patch()` to pull the code out of `<sicario_patch>` tags.
    ///
    /// Accepts an optional `extra_context` string that is appended to the
    /// user prompt — used by the retry loop to feed back syntax/security
    /// errors from previous attempts.
    pub async fn generate_fix_xml(
        &self,
        context: &FixContext,
        extra_context: Option<&str>,
    ) -> Result<String> {
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

        let user_prompt = build_user_prompt(context, extra_context);

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

    /// Legacy method kept for backward compatibility with existing tests.
    /// New code should use `generate_fix_xml` + `extract_patch`.
    pub async fn generate_fix(&self, context: &FixContext) -> Result<String> {
        let raw = self.generate_fix_xml(context, None).await?;
        // Try to extract a patch; fall back to the raw response so old callers
        // still get something usable.
        Ok(extract_patch(&raw).unwrap_or(raw))
    }
}

impl Default for LlmClient {
    fn default() -> Self {
        Self::new().expect("Failed to create LLM client")
    }
}

// ── XML patch extraction ──────────────────────────────────────────────────────

/// Extract the code between `<sicario_patch>` and `</sicario_patch>` tags.
///
/// Returns `Err` if the tags are missing or malformed, so the retry loop
/// can treat a missing tag as a protocol violation and ask the LLM to retry.
pub fn extract_patch(llm_response: &str) -> Result<String> {
    let open_tag = "<sicario_patch>";
    let close_tag = "</sicario_patch>";

    let start = llm_response
        .find(open_tag)
        .ok_or_else(|| anyhow!("LLM response missing <sicario_patch> tag"))?;

    let content_start = start + open_tag.len();

    let end = llm_response[content_start..]
        .find(close_tag)
        .ok_or_else(|| anyhow!("LLM response missing </sicario_patch> closing tag"))?;

    let patch = llm_response[content_start..content_start + end].trim();

    if patch.is_empty() {
        return Err(anyhow!("<sicario_patch> block is empty"));
    }

    Ok(patch.to_string())
}

// ── Prompt construction ───────────────────────────────────────────────────────

fn build_user_prompt(context: &FixContext, extra_context: Option<&str>) -> String {
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

    prompt.push_str("Vulnerable code window (replace ONLY the vulnerable lines):\n");
    prompt.push_str(&context.code_snippet);
    prompt.push('\n');

    if let Some(extra) = extra_context {
        prompt.push('\n');
        prompt.push_str(extra);
        prompt.push('\n');
    }

    prompt.push_str(
        "\nRespond using the required XML format with <scratchpad> and <sicario_patch> tags.",
    );

    prompt
}

// ── Response post-processing ──────────────────────────────────────────────────

/// Strip markdown code fences from a string.
///
/// Used as a last-resort cleanup if the model wraps content inside
/// `<sicario_patch>` in backtick fences despite instructions.
pub fn strip_markdown_fences(s: &str) -> String {
    let trimmed = s.trim();
    if let Some(fence_start) = trimmed.find("```") {
        let after_fence = &trimmed[fence_start + 3..];
        let code_start = after_fence
            .find('\n')
            .map(|i| i + 1)
            .unwrap_or(after_fence.len());
        let code_body = &after_fence[code_start..];
        if let Some(close) = code_body.find("```") {
            return code_body[..close].trim_end().to_string();
        }
        return code_body.trim_end().to_string();
    }
    trimmed.to_string()
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
        assert!(!config.endpoint.is_empty());
        assert!(!config.model.is_empty());
    }

    #[test]
    fn test_build_user_prompt_contains_language() {
        let ctx = make_context();
        let prompt = build_user_prompt(&ctx, None);
        assert!(prompt.contains("Python"));
    }

    #[test]
    fn test_build_user_prompt_contains_framework() {
        let ctx = make_context();
        let prompt = build_user_prompt(&ctx, None);
        assert!(prompt.contains("Django"));
    }

    #[test]
    fn test_build_user_prompt_contains_cwe() {
        let ctx = make_context();
        let prompt = build_user_prompt(&ctx, None);
        assert!(prompt.contains("CWE-89"));
    }

    #[test]
    fn test_build_user_prompt_contains_snippet() {
        let ctx = make_context();
        let prompt = build_user_prompt(&ctx, None);
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
        let prompt = build_user_prompt(&ctx, None);
        assert!(!prompt.contains("Framework:"));
        assert!(!prompt.contains("CWE:"));
    }

    #[test]
    fn test_build_user_prompt_with_extra_context() {
        let ctx = make_context();
        let prompt = build_user_prompt(
            &ctx,
            Some("Previous attempt had a syntax error: missing semicolon"),
        );
        assert!(prompt.contains("syntax error"));
    }

    #[test]
    fn test_extract_patch_valid() {
        let response = "<scratchpad>analysis</scratchpad>\n<sicario_patch>\ncursor.execute(query, (user_id,))\n</sicario_patch>";
        let patch = extract_patch(response).unwrap();
        assert_eq!(patch, "cursor.execute(query, (user_id,))");
    }

    #[test]
    fn test_extract_patch_missing_open_tag() {
        let response = "cursor.execute(query, (user_id,))";
        assert!(extract_patch(response).is_err());
        assert!(extract_patch(response)
            .unwrap_err()
            .to_string()
            .contains("<sicario_patch>"));
    }

    #[test]
    fn test_extract_patch_missing_close_tag() {
        let response = "<sicario_patch>cursor.execute(query, (user_id,))";
        assert!(extract_patch(response).is_err());
        assert!(extract_patch(response)
            .unwrap_err()
            .to_string()
            .contains("</sicario_patch>"));
    }

    #[test]
    fn test_extract_patch_empty_block() {
        let response = "<sicario_patch>   </sicario_patch>";
        assert!(extract_patch(response).is_err());
    }

    #[test]
    fn test_extract_patch_strips_surrounding_whitespace() {
        let response = "<sicario_patch>\n\n  const x = safe(input);\n\n</sicario_patch>";
        let patch = extract_patch(response).unwrap();
        assert_eq!(patch, "const x = safe(input);");
    }

    #[test]
    fn test_extract_patch_multiline() {
        let response = "<scratchpad>fix</scratchpad>\n<sicario_patch>\nconst a = 1;\nconst b = 2;\n</sicario_patch>";
        let patch = extract_patch(response).unwrap();
        assert!(patch.contains("const a = 1;"));
        assert!(patch.contains("const b = 2;"));
    }

    #[test]
    fn test_strip_markdown_fences_with_lang() {
        let s = "```javascript\nconst x = 1;\n```";
        assert_eq!(strip_markdown_fences(s), "const x = 1;");
    }

    #[test]
    fn test_strip_markdown_fences_no_fences() {
        let s = "const x = 1;";
        assert_eq!(strip_markdown_fences(s), "const x = 1;");
    }

    #[tokio::test]
    async fn test_generate_fix_fails_without_api_key() {
        std::env::remove_var("SICARIO_LLM_API_KEY");
        std::env::remove_var("OPENAI_API_KEY");
        std::env::remove_var("CEREBRAS_API_KEY");

        let client = LlmClient {
            api_key: None,
            endpoint: "https://example.com".to_string(),
            model: "test".to_string(),
            key_source: key_manager::KeySource::None,
            client: Client::new(),
        };

        let ctx = make_context();
        let result = client.generate_fix_xml(&ctx, None).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("No LLM API key configured"));
    }

    #[test]
    fn test_default_endpoint_is_openai() {
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

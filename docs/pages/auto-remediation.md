---
sidebar:
  badge:
    text: Capabilities
---

# Auto-Remediation

> Sicario's auto-remediation engine is the industry's first security fix system to combine **deterministic AST template matching** with **zero-exfiltration local AI** and **BYOK cloud AI**. It analyzes vulnerabilities, generates verified patches, and can optionally create pull requests — all without exposing source code when using local agents.

## Overview

The auto-remediation engine (`RemediationEngine`) operates in three tiers:

| Tier | Method | Speed | LLM Required | Exfiltration Risk |
|---|---|---|---|---|
| 1 | Deterministic AST Templates | Instant | No | None |
| 2 | Local AI (Ollama / llama.cpp / LM Studio) | 2-10s | Yes (localhost) | None |
| 3 | BYOK Cloud AI (OpenAI, Anthropic, Groq, etc.) | 5-30s | Yes (cloud) | Configurable |

The engine always tries Tier 1 first. If no deterministic template matches, it escalates to AI — but only after explicit user consent (or `--allow-ai` for CI). This "human-in-the-loop" guardrail is a core design invariant.

## Deterministic Template Fixes

### How Templates Work

Each template is a Rust trait implementation that transforms vulnerable code patterns into safe alternatives. Templates operate at the **AST level** — they understand code structure, not just strings.

There are two types of templates:

**Single-line templates** (`PatchTemplate` trait) — operate on one vulnerable line:

```rust
pub trait PatchTemplate: Send + Sync {
    fn generate_patch(&self, vulnerable_line: &str, lang: Language) -> Option<String>;
    fn name(&self) -> &'static str;
}
```

**Multi-line templates** (`MultiLinePatchTemplate` trait) — operate on the full file content:

```rust
pub trait MultiLinePatchTemplate: Send + Sync {
    fn name(&self) -> &'static str;
    fn generate_multiline_patch(
        &self,
        file_content: &str,
        vulnerable_line: usize,
        lang: Language,
    ) -> Option<String>;
}
```

### Supported Deterministic Fixes (9+ categories)

| Vulnerability | CWE | Template Name | Example Fix |
|---|---|---|---|
| SQL Injection | CWE-89 | `SqlStringConcat` | String concat → parameterized query with comment |
| SQL Template Literal | CWE-89 | `SqlTemplateString` | Template literal → parameterized query comment |
| eval() Injection | CWE-95 | `InjectEval` | `eval(x)` → `JSON.parse(x)` (JS) or `ast.literal_eval(x)` (Python) |
| Command Injection | CWE-78 | `InjectOsExec` | `exec(cmd)` → `execFile(cmd, args)` |
| XSS (innerHTML) | CWE-79 | `InjectInnerHtml` | `innerHTML = x` → `textContent = x` |
| Path Traversal | CWE-22 | `InjectPathTraversal` | Unsanitized path → `path.resolve()` with validation |
| SSRF | CWE-918 | `InjectSsrf` | User URL fetch → URL validation + allowlist |
| Insecure Deserialization | CWE-502 | `InjectDeserial` | `pickle.loads(x)` → `json.loads(x)` |
| Hardcoded Credentials | CWE-798 | `InjectHardcodedCreds` | Hardcoded password → env var reference |
| Open Redirect | CWE-601 | `InjectOpenRedirect` | User-controlled redirect → URL allowlist |
| XXE | CWE-611 | `InjectXxe` | XML parser without XXE protection → disable external entities |

### Template Fix Process

```
Vulnerability detected
    ↓
Engine classifies by CWE ID (e.g. "CWE-89" → SqlInjection)
    ↓
TemplateRegistry.lookup_multi() — try multi-line template first
    ↓
  If match: generate_multiline_patch(file_content, line, lang)
    ↓
  Validate syntax with tree-sitter
    ↓
  If valid → apply
    ↓
  If invalid → fall through to single-line template
    ↓
TemplateRegistry.apply() — try single-line template
    ↓
  If match: generate_patch(line, lang)
    ↓
  Splice replacement into file
    ↓
  Validate syntax with tree-sitter
    ↓
  If valid → apply
    ↓
  If invalid → fall through to AI (with consent)
```

### Template Application Example (SQL Injection)

```javascript
// Before (vulnerable):
connection.query("SELECT * FROM users WHERE id = " + userInput);

// After (deterministic fix):
// SICARIO FIX (CWE-89): use parameterized query — replace string concat with $1 placeholder
connection.query("SELECT * FROM users WHERE id = " + userInput);
```

The template adds a comment marking the vulnerability and guidance. More sophisticated multi-line templates can rewrite the entire query construction.

### Template Application (eval → JSON.parse)

```javascript
// Before:
const data = eval(userInput);

// After:
const data = JSON.parse(userInput);
```

```python
# Before:
data = eval(user_input)

# After:
data = ast.literal_eval(user_input)
```

### Template Application (Command Injection)

```javascript
// Before:
const { exec } = require('child_process');
exec('ls -la ' + userInput);

// After:
const { execFile } = require('child_process');
execFile('ls', ['-la', userInput]);
```

## Backup and Rollback

Before any file modification, Sicario creates a backup. Backups are stored in `.sicario/backups/`:

```text
.sicario/
└── backups/
    ├── patch_history.json       ← record of all applied patches
    └── <patch-id>/
        └── src/
            └── controllers/
                └── user.js      ← original file content
```

### How Backup Works

```rust
// 1. Create backup before any modification
let backup_path = self.backup_manager.backup_file(&patch.file_path)?;

// 2. Write fixed content
fs::write(&patch.file_path, &patch.fixed)?;

// 3. Record in patch history log
let entry = PatchHistoryEntry {
    patch_id: patch.id.to_string(),
    applied_at: chrono::Utc::now().to_rfc3339(),
    file_path: patch.file_path.clone(),
    backup_path: backup_path.clone(),
    resolution_type: Some("fixed".to_string()),
};
self.backup_manager.record_patch(entry)?;
```

### Rolling Back

```bash
# List all applied patches
sicario fix --revert <patch-id>
```

Rollback restores the original file from the backup and records the reversion in the history:

```rust
pub fn revert_by_patch_id(&self, patch_id: &str) -> Result<()> {
    let history = self.backup_manager.load_history()?;
    let entry = history.iter()
        .find(|e| e.patch_id == patch_id)
        .ok_or_else(|| anyhow!("No patch found with ID: {}", patch_id))?;

    self.backup_manager.restore_file(&entry.backup_path, &entry.file_path)?;
    Ok(())
}
```

### Automatic Restore on Failure

If writing the fixed content fails (e.g., disk full, permissions error), the original is automatically restored:

```rust
if let Err(e) = fs::write(&patch.file_path, &patch.fixed) {
    let _ = self.backup_manager.restore_file(&backup_path, &patch.file_path);
    return Err(e);
}
```

## Using `sicario fix`

### Basic Usage

```bash
# Fix a specific file
sicario fix src/controllers/user.js

# Fix all findings in a project (scans first, then fixes)
sicario scan . --fix

# Fix a specific rule across all files
sicario fix . --rule sql-injection

# Fix with auto-approval (batch mode)
sicario fix . --yes
```

### Fix Categories

| Flag | Behavior | Exfiltration |
|---|---|---|
| (none) | Deterministic + AI fallback (with consent) | Zero-exfil by default |
| `--allow-ai` | + AI fallback (no consent prompt) | Transmits context |
| `--agent local` | + Local AI only | Zero-exfil |
| `--agent cloud` | + Cloud AI only | Transmits context |
| `--staged` | Deterministic only, staged files | Zero-exfil |

### Targeting Specific Files and Rules

```bash
# Fix a specific file
sicario fix src/db/queries.js

# Fix a specific rule
sicario fix . --rule js/sql-injection

# Fix multiple rules
sicario fix . --rule js/sql-injection,js/xss

# Fix staged files only (pre-commit compatible)
sicario fix --staged
```

### Output Formats

```bash
# Default: human-readable text with diffs
sicario fix src/app.js

# JSON output (machine-readable)
sicario fix src/app.js --format json

# With --staged, JSON outputs an array of results
sicario fix --staged --format json
```

## Local LLM AI Fixes

When deterministic templates don't match, the engine can use a local LLM via `--agent local`. This is the **zero-exfiltration** path — no code ever leaves your machine.

### Supported Providers

| Provider | Default Port | URL | Discovery |
|---|---|---|---|
| [Ollama](https://ollama.com) | `11434` | `http://127.0.0.1:11434` | Auto-probed |
| [llama.cpp](https://github.com/ggerganov/llama.cpp) | `8080` | `http://127.0.0.1:8080` | Manual config |
| [LM Studio](https://lmstudio.ai) | `1234` | `http://127.0.0.1:1234` | Manual config |

### Usage

```bash
# Auto-detect best local model
sicario fix src/app.js --agent local

# Use a specific model
sicario fix src/app.js --agent local-qwen2.5-coder:7b

# Use with scan (local agent only)
sicario scan . --fix --agent local
```

### How Local AI Works

```rust
pub enum AgentConfig {
    Local { model_override: Option<String> },
    Cloud,
    Auto,
}
```

When `--agent local` is specified:

1. **Probe phase** — the `OllamaClient` queries `http://127.0.0.1:11434/api/tags` to list available models and selects the best by priority
2. **Fix phase** — sends only the vulnerable code context (±10 lines) to the local model
3. **Verification phase** — the response goes through a three-stage `TreeSitterVerificationLoop`:
   - **Stage 1** — JSON parsing (the model must respond with `{"replacement": "..."}`)
   - **Stage 2** — Tree-sitter syntax check
   - **Stage 3** — Identifier scope validation (only uses variables from the provided scope)
4. **Retry loop** — up to 3 attempts with error feedback if verification fails

### Zero-Exfiltration Guarantee

When `AgentConfig::Local` is active, the following **structural invariants** ensure no data leaves your machine:

- `OLLAMA_TAGS_URL = "http://127.0.0.1:11434/api/tags"`
- `OLLAMA_CHAT_URL = "http://127.0.0.1:11434/v1/chat/completions"`
- No other URL constants exist in the Ollama client
- The `reqwest::blocking::Client` is constructed without a proxy
- No `Authorization` header is sent (local auth is not needed)
- `PatchReceipt::local_agent` enforces `lines_exfiltrated: 0` and `tokens_burned: 0` at the type level

```rust
// INVARIANT: ALL HTTP requests go ONLY to 127.0.0.1:11434
pub(crate) const OLLAMA_TAGS_URL: &str = "http://127.0.0.1:11434/api/tags";
pub(crate) const OLLAMA_CHAT_URL: &str = "http://127.0.0.1:11434/v1/chat/completions";
```

### Configuration

```bash
# Custom Ollama endpoint
export SICARIO_OLLAMA_ENDPOINT=http://localhost:11434

# Custom timeout (default: 120s)
export SICARIO_OLLAMA_TIMEOUT=300
```

## BYOK Cloud AI Fixes

### Supported Providers (19 total)

Sicario supports any OpenAI-compatible API endpoint. The built-in provider registry includes:

| Provider | Endpoint | Env Var | Default Model |
|---|---|---|---|
| OpenAI | `https://api.openai.com/v1` | `OPENAI_API_KEY` | `gpt-4o` |
| Anthropic | `https://api.anthropic.com/v1` | `ANTHROPIC_API_KEY` | `claude-opus-4-5` |
| Google Gemini | `https://generativelanguage.googleapis.com/v1beta/openai/` | `GEMINI_API_KEY` | `gemini-2.5-pro` |
| Azure OpenAI | `https://<resource>.openai.azure.com/` | `AZURE_OPENAI_API_KEY` | `gpt-4o` |
| AWS Bedrock | `https://bedrock-runtime.<region>.amazonaws.com` | `AWS_ACCESS_KEY_ID` | `claude-3-5-sonnet` |
| DeepSeek | `https://api.deepseek.com/v1` | `DEEPSEEK_API_KEY` | `deepseek-chat` |
| Groq | `https://api.groq.com/openai/v1` | `GROQ_API_KEY` | `llama-3.3-70b-versatile` |
| Cerebras | `https://api.cerebras.ai/v1` | `CEREBRAS_API_KEY` | `llama3.1-70b` |
| Together AI | `https://api.together.xyz/v1` | `TOGETHER_API_KEY` | `meta-llama/Llama-3-70b` |
| Fireworks AI | `https://api.fireworks.ai/inference/v1` | `FIREWORKS_API_KEY` | `llama-v3p1-70b-instruct` |
| OpenRouter | `https://openrouter.ai/api/v1` | `OPENROUTER_API_KEY` | `openai/gpt-4o` |
| Mistral | `https://api.mistral.ai/v1` | `MISTRAL_API_KEY` | `mistral-large-latest` |
| xAI | `https://api.x.ai/v1` | `XAI_API_KEY` | `grok-3` |
| Perplexity | `https://api.perplexity.ai` | `PERPLEXITY_API_KEY` | `llama-3.1-sonar-large` |
| Cohere | `https://api.cohere.ai/compatibility/v1` | `COHERE_API_KEY` | `command-r-plus` |
| DeepInfra | `https://api.deepinfra.com/v1/openai` | `DEEPINFRA_API_KEY` | `Meta-Llama-3.1-70B-Instruct` |
| Novita AI | `https://api.novita.ai/v3/openai` | `NOVITA_API_KEY` | `llama-3.1-70b-instruct` |
| Ollama | `http://localhost:11434/v1` | (none: local) | (probed) |
| LM Studio | `http://localhost:1234/v1` | (none: local) | (probed) |

### Setting API Keys

```bash
# Via environment variable
export OPENAI_API_KEY=sk-...
export SICARIO_LLM_MODEL=gpt-4o
sicario fix . --agent cloud

# Via config (stored in system keyring)
sicario config set llm.provider openai
sicario config set llm.api-key sk-...

# Via Sicario Cloud API key
sicario login --token=sic_proj_...
```

### Resolution Chain

API key resolution follows this priority:

1. `SICARIO_LLM_API_KEY` env var
2. System keyring (`keyring` crate)
3. Provider-specific env var (e.g., `OPENAI_API_KEY`)
4. Sicario config file

### Usage

```bash
# Use cloud AI fix
sicario fix src/app.js --agent cloud

# Scan and fix with cloud AI
sicario scan . --fix --agent cloud --allow-ai

# Scan, fix with specific provider
export SICARIO_LLM_ENDPOINT=https://api.anthropic.com/v1
export ANTHROPIC_API_KEY=sk-ant-...
sicario fix . --agent cloud
```

## The `--auto-pr` Workflow

The `--auto-pr` flag automates the entire fix → commit → PR workflow.

### How It Works

1. Scan the project for vulnerabilities
2. Apply all deterministic fixes
3. Create a branch `sicario/autofix-<timestamp>` (idempotent — appends counter suffix if exists)
4. Commit all fixes with a descriptive message
5. Push the branch
6. Open a PR/MR on GitHub or GitLab

```bash
# Full auto-PR workflow
sicario scan . --fix --publish --auto-pr
```

### Requirements

- `GITHUB_TOKEN` (for GitHub) or `GITLAB_TOKEN` (for GitLab) must be set
- Provider is auto-detected from `git remote get-url origin`
- The repository must have a configured remote

### Output

```text
[sicario] Creating PR for branch sicario/autofix-20260520-143022...
[sicario] PR created: https://github.com/myorg/myapp/pull/1427
```

### Optional Flags

```bash
# Publish all findings (not just Medium+)
sicario scan . --fix --publish --publish-all --auto-pr

# Publish with code snippets (opt-in to snippet upload)
sicario scan . --fix --publish --publish-with-snippet --auto-pr
```

## AI Disclaimer & Mandatory Human Review

> **IMPORTANT:** AI-generated patches are **suggestions**, not verified fixes. Always review AI patches before deploying to production. Sicario provides syntax validation and security re-verification, but semantic correctness is the developer's responsibility.

When AI is used, a disclaimer is printed:

```text
[sicario] ╔══ AI DISCLAIMER ═══════════════════════════════╗
[sicario] ║ The following patch was generated by an AI      ║
[sicario] ║ language model. Review carefully before          ║
[sicario] ║ deploying to production.                        ║
[sicario] ╚══════════════════════════════════════════════════╝
```

## AI Consent Guardrail

Sicario **never** silently sends code to an LLM. The AI Fallback Guardrail ensures:

1. When no deterministic template matches, execution halts
2. The user is prompted: "Opt-in to AI Fallback? [y/N]"
3. Only explicit consent (or `--allow-ai`) triggers the LLM call

```rust
pub fn check_ai_fallback_consent(rule_id, file, line, allow_ai) -> AiFallbackDecision {
    if allow_ai {
        // CI mode: print notice, proceed
        return AiFallbackDecision::Proceed;
    }
    // Interactive mode: print prompt, wait for input
    print("[sicario] Opt-in to AI Fallback? [y/N]: ");
    let input = read_line();
    if input == "y" || input == "yes" {
        AiFallbackDecision::Proceed
    } else {
        AiFallbackDecision::Declined
    }
}
```

```bash
# CI mode: pre-approve AI
sicario fix . --allow-ai

# CI mode with local agent (implied consent)
sicario fix . --agent local
```

## Template Fallback Behavior

The engine uses a ordered fallback chain:

```
1. MultiLinePatchTemplate (AST-level, full file)
    ↓ if None or syntax invalid
2. PatchTemplate (single line)
    ↓ if None or syntax invalid
3. AI LLM (with consent/--allow-ai)
    ↓ if LLM unavailable or all retries exhausted
4. Classification-based template (fallback)
    ↓ if no rewrite possible
5. Skip with error message
```

This ensures that even when the LLM is unavailable, the engine always produces **some** useful output — even if it's just a comment marking the vulnerability.

## Best Practices

### When to Use AI vs Deterministic

| Scenario | Recommended Approach |
|---|---|
| CI/CD pipeline | `--staged` or `--fix` (deterministic only, zero-exfil) |
| Pre-commit hook | `--staged` (fast, deterministic, no network) |
| Local development | `--agent local` (fast, zero-exfil) |
| Complex vulnerability | `--agent cloud` (more capable model) |
| Automated PR generation | `--auto-pr` with `--allow-ai` |
| Air-gapped environment | `--agent local` (100% offline) |

### Reviewing Patches

1. **Always review the diff** — Sicario shows a unified diff before applying
2. **Run tests after fixing** — AI patches may break edge cases
3. **Verify with `--no-verify`** — skip post-fix verification if it's too slow
4. **Use `--max-iterations`** — default 3 retries; increase for complex fixes

```bash
# Show diff without applying
sicario fix src/app.js --dry-run

# Apply without verification scan
sicario fix . --yes --no-verify

# Increase retry attempts to 5
sicario fix . --max-iterations 5
```

### Setting Up Ollama for Local Fixing

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a code-specialized model
ollama pull qwen2.5-coder:7b

# Verify it's running
curl http://localhost:11434/api/tags

# Use with Sicario
sicario fix src/app.js --agent local-qwen2.5-coder:7b
```

## Troubleshooting

### LLM Connection Issues

| Error | Likely Cause | Solution |
|---|---|---|
| `Ollama error: connection refused` | Ollama not running | Start Ollama: `ollama serve` |
| `Ollama error: model not found` | Model not pulled | `ollama pull <model-name>` |
| `LLM error: timed out` | Network or model too slow | Increase timeout via env var |
| `JSON extraction failed` | Model returned invalid format | Usually recovers on retry |
| `HTTP 401` | Invalid API key | Check `SICARIO_LLM_API_KEY` or provider env var |

### Invalid Patches

If the AI returns a patch that is syntactically invalid:

1. The engine retries (up to 3 times by default)
2. Each retry sends the syntax error back as feedback
3. After all retries, falls back to deterministic template
4. If no template matches, the finding is skipped with a warning

```text
[sicario] attempt 1/3 — patch has syntax errors
[sicario] attempt 2/3 — patch has syntax errors
[sicario] attempt 3/3 — patch has syntax errors
[sicario] warning: LLM remediation failed after 3 attempt(s): syntax error
         Falling back to deterministic template...
```

### Template Not Found

```text
[sicario] Deterministic engine: no template found for rule 'js/custom-xss' at src/app.js:42
[sicario] Opt-in to AI Fallback? This will securely transmit the file context to the LLM. [y/N]:
```

To fix: either consent to AI, add a custom template, or skip.

### Patch Verification Fails

After applying a fix, the engine re-runs the SAST rule on the patched file. If the vulnerability is still present, the fix is reverted:

```text
[sicario] warning: sql-injection still present, reverting
[sicario] Reverted patch <patch-id> for src/db/queries.js
```

## Comparison: Sicario Auto-Remediation vs Alternatives

| Feature | Sicario | GitHub Copilot | CodeWhisperer | CodeQL Autofix |
|---|---|---|---|---|
| Deterministic templates | ✅ 9+ categories | ❌ | ❌ | ❌ |
| Local AI (zero-exfil) | ✅ Ollama/llama.cpp/LM Studio | ❌ (cloud only) | ❌ (cloud only) | ❌ (CL only) |
| BYOK cloud AI | ✅ 19 providers | ❌ (MS only) | ❌ (AWS only) | ❌ |
| AST verification | ✅ Tree-sitter | ❌ | ❌ | ✅ |
| Security re-verification | ✅ Re-scans patched code | ❌ | ❌ | ❌ |
| Backup/rollback | ✅ SQLite history | ❌ | ❌ | ❌ |
| PR automation | ✅ `--auto-pr` | ❌ | ❌ | ❌ |
| Human-in-the-loop guardrail | ✅ Always | ❌ | ❌ | ❌ |
| Open source | ✅ FSL-1.1 | ❌ | ❌ | ❌ |

## Related

- [SAST Scanning](sast-scanning.md) — vulnerabilities that `sicario fix` resolves
- [SCA Scanning](sca-scanning.md) — dependency fix recommendations
- [Secret Detection](secrets-detection.md) — credential remediation
- [Reporting](reporting.md) — remediation audit logs and MTTR metrics

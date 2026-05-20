> **Integration**

# Configuration

Sicario offers a layered configuration system that resolves settings from multiple sources with a clear priority order. This allows you to set global defaults, override them per-project, and further override them per-invocation.

---

## Configuration Layers and Priority

Settings are resolved from highest to lowest priority:

```
Highest Priority
    │
    ├── 1. CLI Flags           (e.g., --fail-on High, --format sarif)
    ├── 2. Environment Variables  (e.g., SICARIO_LLM_ENDPOINT)
    ├── 3. Project Config         (.sicario/config.yaml)
    └── 4. Global Config          (~/.sicario/config.toml)
Lowest Priority
```

Each layer overrides the layers below it. If a setting is not present in a higher layer, the next layer is consulted.

> **Example**: If `llm_endpoint` is set in both `~/.sicario/config.toml` and `SICARIO_LLM_ENDPOINT`, the environment variable wins. If the `--fail-on` flag is passed, it wins over everything including the policy file.

---

## Global Configuration (`~/.sicario/config.toml`)

The global configuration file is stored at `~/.sicario/config.toml` and holds user-level settings such as LLM API keys, model preferences, and telemetry opt-out. These settings persist across all projects.

### Managing via `sicario config`

The `sicario config` command provides a CLI interface for reading and writing global settings.

#### `sicario config set <key> <value>`

Set a configuration key-value pair:

```bash
sicario config set llm_endpoint "http://localhost:1234/v1/chat/completions"
sicario config set llm_model "claude-3-5-sonnet-20241022"
sicario config set no_telemetry true
```

Valid keys:

| Key | Type | Description |
|-----|------|-------------|
| `llm_api_key` | string | Generic LLM API key (BYOK — Bring Your Own Key). Equivalent to `SICARIO_LLM_API_KEY` env var. |
| `anthropic_api_key` | string | Anthropic API key for Claude-based remediation. Equivalent to `ANTHROPIC_API_KEY` env var. |
| `openai_api_key` | string | OpenAI API key for GPT-based remediation. Equivalent to `OPENAI_API_KEY` env var. |
| `llm_endpoint` | string | Custom LLM endpoint URL (OpenAI-compatible). Equivalent to `SICARIO_LLM_ENDPOINT` env var. |
| `llm_model` | string | LLM model name override. Equivalent to `SICARIO_LLM_MODEL` env var. |
| `no_telemetry` | boolean | Opt-out of anonymous usage telemetry. Accepts `true` or `false`. |

#### `sicario config set-provider <name>`

Configure a provider preset. This automatically sets the correct `llm_endpoint` and `llm_model` for the named provider:

```bash
# Use Anthropic Claude
sicario config set-provider anthropic

# Use OpenAI GPT
sicario config set-provider openai

# Use a local Ollama instance
sicario config set-provider ollama

# Use Groq
sicario config set-provider groq
```

Available providers (19 total):

| Provider | Name | Default Endpoint | Default Model |
|----------|------|-----------------|---------------|
| OpenAI | `openai` | `https://api.openai.com/v1` | `gpt-4o` |
| Anthropic | `anthropic` | `https://api.anthropic.com/v1` | `claude-opus-4-5` |
| Google Gemini | `gemini` | (provider-specific) | (provider-specific) |
| Azure OpenAI | `azure` | (configured per-deployment) | (configured per-deployment) |
| AWS Bedrock | `bedrock` | (AWS region-dependent) | (AWS region-dependent) |
| DeepSeek | `deepseek` | (provider-specific) | (provider-specific) |
| Groq | `groq` | (provider-specific) | (provider-specific) |
| Cerebras | `cerebras` | (provider-specific) | (provider-specific) |
| Together AI | `together` | (provider-specific) | (provider-specific) |
| Fireworks AI | `fireworks` | (provider-specific) | (provider-specific) |
| OpenRouter | `openrouter` | (provider-specific) | (provider-specific) |
| Mistral | `mistral` | (provider-specific) | (provider-specific) |
| Ollama | `ollama` | `http://localhost:11434` | `llama3.2` |
| LM Studio | `lmstudio` | `http://localhost:1234/v1` | `local-model` |
| xAI | `xai` | (provider-specific) | (provider-specific) |
| Perplexity | `perplexity` | (provider-specific) | (provider-specific) |
| Cohere | `cohere` | (provider-specific) | (provider-specific) |
| DeepInfra | `deepinfra` | (provider-specific) | (provider-specific) |
| Novita | `novita` | (provider-specific) | (provider-specific) |

Custom endpoint override:

```bash
# Use a provider preset but override the endpoint
sicario config set-provider ollama --endpoint http://192.168.1.100:11434

# Use a provider preset but override the model
sicario config set-provider anthropic --model claude-3-haiku-20240307
```

#### `sicario config show`

Display the current configuration and all supported providers:

```bash
sicario config show
```

Example output:

```
Global Configuration (~/.sicario/config.toml):
  llm_endpoint: https://api.anthropic.com/v1
  llm_model: claude-sonnet-4-20250514
  no_telemetry: false

Supported Providers (19):
  openai, anthropic, gemini, azure, bedrock, deepseek, groq,
  cerebras, together, fireworks, openrouter, mistral, ollama,
  lmstudio, xai, perplexity, cohere, deepinfra, novita
```

#### `sicario config test`

Test connectivity to the configured LLM provider:

```bash
sicario config test
```

If successful:

```
✓ LLM provider reachable: anthropic (claude-sonnet-4-20250514)
```

If unsuccessful, the error message will indicate whether it's a network issue, authentication failure, or configuration problem.

### Direct File Access

The global config file is plain TOML at `~/.sicario/config.toml`:

```toml
# ~/.sicario/config.toml
llm_api_key = "sk-ant-..."
anthropic_api_key = "sk-ant-..."
openai_api_key = "sk-..."
llm_endpoint = "https://api.anthropic.com/v1"
llm_model = "claude-sonnet-4-20250514"
no_telemetry = false
```

> **Security**: The config file is created with `0600` permissions (user read/write only) on Unix systems. This protects API keys from other users on the same machine.

---

## Project-Level Configuration (`.sicario/config.yaml`)

For project-specific settings, create a `.sicario/config.yaml` file in your project root.

### Full Annotated Example

```yaml
# .sicario/config.yaml
version: 1

scanner:
  # Paths to exclude from scanning (glob patterns)
  ignore_paths:
    - "tests/**"
    - "vendor/**"
    - "**/*.min.js"
    - "**/dist/**"
    - "**/node_modules/**"

  # Minimum severity level to report
  severity_threshold: medium

  # Enable or disable scan types
  secrets: true
  sca: true
  taint: false

  # Diff scanning: only scan files changed against a branch
  diff: main

  # Focus mode: high severity only, top 10 findings
  focus: false

  # Number of parallel workers (0 = auto)
  jobs: 4

rules:
  # Rules to completely disable
  disable:
    - js/console-log
    - py/debug-assert

  # Rules with severity overrides
  overrides:
    - rule: js/sql-injection
      severity: critical
    - rule: py/eval-use
      severity: medium

  # Custom rules directory (relative to project root)
  custom_rules_dir: .sicario/custom-rules

ignore:
  # File patterns to ignore (gitignore syntax)
  patterns:
    - "*.generated.*"
    - "**/__pycache__/**"
    - "*.snap"
    - "coverage/**"

  # Specific findings to ignore by rule ID
  findings:
    - rule: js/no-console
      paths:
        - "src/cli/**"
        - "scripts/**"
```

### Configuration Sections

#### `version`

The configuration schema version. Currently must be `1`.

#### `scanner`

Controls the scanning behavior:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ignore_paths` | list of strings | `[]` | Glob patterns for files/directories to exclude from scanning |
| `severity_threshold` | string | `low` | Minimum severity to report: `info`, `low`, `medium`, `high`, `critical` |
| `secrets` | boolean | `false` | Enable secrets detection |
| `sca` | boolean | `false` | Enable SCA dependency scanning |
| `taint` | boolean | `false` | Enable interprocedural taint analysis |
| `diff` | string | — | Git reference to diff against (e.g., `main`) |
| `focus` | boolean | `false` | Focus mode: only High+ findings, top 10 |
| `jobs` | integer | `0` | Parallel worker threads (0 = auto) |

#### `rules`

Controls rule behavior:

| Field | Type | Description |
|-------|------|-------------|
| `disable` | list of strings | Rule IDs to completely disable |
| `overrides` | list of objects | Severity overrides per rule (`rule` + `severity`) |
| `custom_rules_dir` | string | Path to directory containing custom YAML rule files |

#### `ignore`

Controls finding-level suppressions:

| Field | Type | Description |
|-------|------|-------------|
| `patterns` | list of strings | Glob patterns for files to ignore entirely |
| `findings` | list of objects | Rule-specific ignores by path |

---

## The `.sicarioignore` File

For simple path exclusions, drop a `.sicarioignore` file in your project root. It uses standard `.gitignore`-syntax patterns.

### Example

```
# .sicarioignore

# Ignore test directories
tests/**
**/__tests__/**
**/*.test.*

# Ignore generated files
dist/**
build/**
*.generated.*

# Ignore vendored dependencies
vendor/**
third_party/**

# Ignore specific files that trigger false positives
src/legacy/monolithic.js
docs/examples/hacky_example.py
```

### Priority

The `.sicarioignore` file has equal priority to project config's `ignore_paths`. Both are combined when the scanner collects files.

**Priority order for file inclusion/exclusion**:

1. First, `.gitignore` patterns are applied (to exclude files not tracked by git)
2. Then, `.sicarioignore` patterns are applied
3. Then, project config `ignore_paths` are applied
4. Finally, CLI `--exclude` flags are applied

A file is excluded if **any** of these sources matches it.

---

## Environment Variables Reference

The following environment variables can be used to configure Sicario behavior.

### LLM Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `SICARIO_LLM_ENDPOINT` | Custom LLM endpoint URL (OpenAI-compatible) | `http://localhost:1234/v1/chat/completions` |
| `SICARIO_LLM_MODEL` | LLM model name override | `claude-3-5-sonnet-20241022` |
| `SICARIO_LLM_API_KEY` | Generic LLM API key (BYOK) | `sk-ant-...` |
| `OPENAI_API_KEY` | OpenAI API key (specific provider) | `sk-...` |
| `OPENAI_BASE_URL` | Custom OpenAI-compatible base URL | `http://localhost:11434/v1` |
| `ANTHROPIC_API_KEY` | Anthropic API key | `sk-ant-...` |

### CI/CD & Pipeline

| Variable | Description | Example |
|----------|-------------|---------|
| `SICARIO_FAIL_ON` | Default `--fail-on` severity level | `High` |
| `SICARIO_API_KEY` | API key for Sicario Cloud telemetry (NOT for LLM) | `project:key` |
| `SICARIO_ORG_ID` | Organization ID for cloud dashboard | `org_abc123` |
| `SICARIO_MAX_ITERATIONS` | Max iterations for AI fix analysis | `5` |

### Provider-Specific API Keys

| Variable | Provider |
|----------|----------|
| `ANTHROPIC_API_KEY` | Anthropic (Claude) |
| `OPENAI_API_KEY` | OpenAI (GPT) |
| `GOOGLE_API_KEY` | Google (Gemini) |
| `GROQ_API_KEY` | Groq |
| `CEREBRAS_API_KEY` | Cerebras |
| `TOGETHER_API_KEY` | Together AI |
| `FIREWORKS_API_KEY` | Fireworks AI |
| `OPENROUTER_API_KEY` | OpenRouter |
| `MISTRAL_API_KEY` | Mistral |
| `DEEPSEEK_API_KEY` | DeepSeek |
| `XAI_API_KEY` | xAI (Grok) |
| `PERPLEXITY_API_KEY` | Perplexity |
| `COHERE_API_KEY` | Cohere |

### Key Resolution Priority

When Sicario needs an LLM API key for AI-powered remediation (`sicario fix`), it resolves in this order:

1. `ANTHROPIC_API_KEY` environment variable
2. `OPENAI_API_KEY` environment variable
3. `anthropic_api_key` in `~/.sicario/config.toml`
4. `openai_api_key` in `~/.sicario/config.toml`
5. `SICARIO_LLM_API_KEY` environment variable
6. `llm_api_key` in `~/.sicario/config.toml`

> **Critical Design Constraint**: `SICARIO_API_KEY` is **never** consulted during LLM key resolution. It is strictly reserved for authenticating HTTP requests to the Convex telemetry endpoint. This is enforced by a zero-liability boundary in the code and validated by a dedicated test (`test_sicario_api_key_not_used_for_llm`).

---

## Best Practices

### When to Use Each Layer

| Layer | Use Case |
|-------|----------|
| **Global config** | API keys, default LLM preferences, telemetry opt-out |
| **Project config** | Rule overrides, ignore paths, custom rules, severity thresholds |
| **Environment variables** | CI/CD overrides, temporary settings, secret injection |
| **CLI flags** | Ad-hoc overrides, debugging, per-invocation customization |

### API Key Security

1. **Never commit API keys to version control**. Use environment variables or the global config file (which has `0600` permissions).
2. **Use provider-specific env vars** over generic `llm_api_key` when possible.
3. **CI/CD pipelines**: Inject API keys via your CI/CD platform's secret management (GitHub Secrets, GitLab CI Variables, etc.).

### Configuration as Code

For teams, commit the project-level `.sicario/config.yaml` to version control. This ensures consistent scanning behavior across all contributors and CI/CD pipelines.

```yaml
# .sicario/config.yaml (committed to repo)
version: 1
scanner:
  severity_threshold: medium
  secrets: true
  sca: true
rules:
  overrides:
    - rule: js/console-log
      severity: low
```

**Do NOT commit** `.sicario/config.toml` (global config) — it contains API keys.

### Telemetry Opt-Out

To disable anonymous usage telemetry:

```bash
sicario config set no_telemetry true
```

Verify:

```bash
cat ~/.sicario/config.toml
# Should contain: no_telemetry = true
```

---

## Troubleshooting

### Configuration Not Applying

**Problem**: Changes to `.sicario/config.yaml` seem to have no effect.

**Solutions**:

1. **Check the file location**: The config must be at `<project-root>/.sicario/config.yaml`, not in a subdirectory.

2. **Verify YAML syntax**:
   ```bash
   python3 -c "import yaml; yaml.safe_load(open('.sicario/config.yaml'))"
   ```

3. **Check for override**: A CLI flag is overriding your config. Run with `--verbose` to see resolved settings:
   ```bash
   sicario scan . --verbose
   ```

4. **Check the version field**: Ensure `version: 1` is present at the top of the file.

### Wrong Provider Selected

**Problem**: The wrong LLM provider is being used for auto-remediation.

**Solutions**:

1. **Check all layers**:
   ```bash
   # What does the config say?
   sicario config show
   
   # What env vars are set?
   echo $SICARIO_LLM_ENDPOINT
   echo $SICARIO_LLM_MODEL
   ```

2. **Override explicitly**: Use the `--agent` flag on `sicario fix`:
   ```bash
   sicario fix src/db.js --agent cloud
   ```

3. **Test connectivity**:
   ```bash
   sicario config test
   ```

### Global Config Not Found

**Problem**: `~/.sicario/config.toml` doesn't exist or isn't being read.

**Sicario creates the file on first `config set` command**. If you haven't run one, the file won't exist and defaults will be used.

```bash
# Initialize the config
sicario config set llm_endpoint "http://localhost:11434"
```

### Permission Denied on Config File

**Problem**: `Permission denied` when running `sicario config` commands.

**Solutions**:

- On Unix, the config file is owned by your user. Check permissions:
  ```bash
  ls -la ~/.sicario/config.toml
  # Should be -rw------- (0600)
  ```

- On Windows, check that you have write access to `%USERPROFILE%\.sicario\config.toml`.

---

## Related

- [CI/CD Integration](./ci-cd) — Using configuration in pipeline environments
- [CLI Reference](./cli-reference) — Full command reference
- [Suppressions](./suppressions) — Inline suppression directives
- [Baseline Management](./baseline) — Managing security debt across versions

---

## Next Steps

1. [Configure global settings](./#sicario-config-set-key-value) for your preferred LLM provider
2. Create a [project config](./#project-configuration) for your repository
3. Add a [`.sicarioignore` file](./#the-sicarioignore-file) to exclude noisy paths
4. Set up [environment variables](./#environment-variables-reference) in CI/CD
5. Review the [CLI Reference](./cli-reference) for all available flags and subcommands

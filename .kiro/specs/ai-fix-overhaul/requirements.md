# Requirements Document

## Introduction

This specification covers a comprehensive overhaul of the AI-powered code remediation system in Sicario CLI, plus a new cloud-synced provider settings feature. The work is split into two phases: Phase 1 fixes all local bugs and gaps (config.yaml reading, progress indicator, batch mode, expanded template fixes, syntax validation), and Phase 2 adds cloud-synced provider settings (dashboard UI, Convex backend, CLI integration). Both phases share a unified configuration resolution architecture so that local and cloud settings compose cleanly.

## Glossary

- **Remediation_Engine**: The Rust module (`remediation_engine.rs`) that orchestrates fix generation (LLM → template fallback), patch application, revert, and verification.
- **LLM_Client**: The provider-agnostic HTTP client (`llm_client.rs`) that speaks the OpenAI chat completions protocol to generate security fixes.
- **Config_Resolver**: The configuration resolution subsystem (`key_manager/manager.rs`) that determines endpoint, model, and API key from multiple sources.
- **Config_File**: The local YAML configuration file at `.sicario/config.yaml` written by `sicario config set-provider`.
- **Template_Engine**: The fallback fix generator inside `Remediation_Engine` that applies rule-based code transformations when the LLM is unavailable or returns invalid code.
- **Syntax_Validator**: The tree-sitter-based syntax checker inside `Remediation_Engine` that validates generated code before application.
- **Verification_Scanner**: The post-fix scanner (`verification/scanner.rs`) that re-scans patched files to confirm vulnerability resolution.
- **Cloud_Config**: Provider settings (endpoint, model, encrypted API key) stored in the Convex backend and synced to the CLI for authenticated users.
- **Provider_Settings_API**: The Convex HTTP endpoints that allow reading and writing Cloud_Config records.
- **Provider_Settings_Page**: The React dashboard page where users manage their LLM provider configuration.
- **Resolution_Chain**: The ordered precedence for resolving configuration values: local env vars → Config_File → Cloud_Config.
- **Batch_Mode**: A CLI mode where multiple vulnerabilities are fixed in sequence without per-finding confirmation prompts.
- **Progress_Indicator**: A terminal spinner or status line displayed during long-running LLM API calls.

## Requirements

### Requirement 1: Config File Reading

**User Story:** As a developer, I want `sicario config set-provider` settings to actually be used when I run `sicario fix`, so that my local provider configuration works as documented.

#### Acceptance Criteria

1. WHEN the Config_Resolver resolves the LLM endpoint, THE Config_Resolver SHALL check the Config_File for an `endpoint` value after checking environment variables and before returning the default.
2. WHEN the Config_Resolver resolves the LLM model, THE Config_Resolver SHALL check the Config_File for a `model` value after checking environment variables and before returning the default.
3. WHEN the Config_Resolver resolves the API key, THE Config_Resolver SHALL check the Config_File for a `key` value after checking environment variables and the OS keyring and before returning None.
4. WHEN the Config_File does not exist or is unreadable, THE Config_Resolver SHALL skip the Config_File layer and continue to the next source in the Resolution_Chain without error.
5. WHEN an environment variable is set, THE Config_Resolver SHALL use the environment variable value regardless of what the Config_File contains.
6. WHEN `sicario config show` is executed, THE Config_Resolver SHALL display the active source for each resolved value (env var name, config file, or default).
7. FOR ALL valid Config_File YAML documents containing endpoint and model fields, parsing then serializing then parsing the Config_File SHALL produce equivalent configuration values (round-trip property).

### Requirement 2: Progress Indicator During LLM Calls

**User Story:** As a developer, I want to see a progress indicator while the LLM generates a fix, so that I know the CLI has not frozen.

#### Acceptance Criteria

1. WHEN the LLM_Client sends a request to the LLM endpoint, THE Remediation_Engine SHALL display a terminal spinner with a status message within 100 milliseconds of the request starting.
2. WHILE the LLM API call is in progress, THE Progress_Indicator SHALL update the spinner animation at a regular interval.
3. WHEN the LLM API call completes successfully, THE Remediation_Engine SHALL stop the spinner and display a success status message.
4. WHEN the LLM API call fails, THE Remediation_Engine SHALL stop the spinner and display the error reason.
5. WHEN the LLM API call exceeds the 30-second timeout, THE Remediation_Engine SHALL stop the spinner and display a timeout message before falling back to the Template_Engine.

### Requirement 3: Expanded Template Fixes

**User Story:** As a developer, I want template-based fallback fixes for more vulnerability types beyond SQL injection, XSS, and command injection, so that the CLI provides useful fixes even without an LLM.

#### Acceptance Criteria

1. WHEN a path traversal vulnerability (CWE-22) is detected and the LLM is unavailable, THE Template_Engine SHALL generate a fix that canonicalizes the file path and validates it against an allowed base directory.
2. WHEN an SSRF vulnerability (CWE-918) is detected and the LLM is unavailable, THE Template_Engine SHALL generate a fix that validates the target URL against an allowlist of permitted hosts.
3. WHEN an insecure deserialization vulnerability (CWE-502) is detected and the LLM is unavailable, THE Template_Engine SHALL generate a fix that replaces the unsafe deserialization call with a safe alternative for the detected language.
4. WHEN a hardcoded credentials vulnerability (CWE-798) is detected and the LLM is unavailable, THE Template_Engine SHALL generate a fix that replaces the hardcoded value with an environment variable lookup.
5. WHEN an open redirect vulnerability (CWE-601) is detected and the LLM is unavailable, THE Template_Engine SHALL generate a fix that validates the redirect URL against an allowlist of permitted domains.
6. WHEN an XML external entity (XXE) vulnerability (CWE-611) is detected and the LLM is unavailable, THE Template_Engine SHALL generate a fix that disables external entity processing in the XML parser configuration.
7. THE Template_Engine SHALL produce a fix that differs from the original source code for every supported vulnerability type.

### Requirement 4: Syntax Validation for All Supported Languages

**User Story:** As a developer, I want the syntax validator to reject invalid code for all languages Sicario scans, so that broken fixes are never applied to my files.

#### Acceptance Criteria

1. WHEN the Syntax_Validator receives code in a language that Sicario supports for scanning (JavaScript, TypeScript, Python, Rust, Go, Java), THE Syntax_Validator SHALL parse the code using tree-sitter and return false if any error nodes are present.
2. WHEN the Syntax_Validator receives code in Ruby, THE Syntax_Validator SHALL parse the code using tree-sitter and return false if any error nodes are present.
3. WHEN the Syntax_Validator receives code in PHP, THE Syntax_Validator SHALL parse the code using tree-sitter and return false if any error nodes are present.
4. WHEN the Syntax_Validator receives code in a language for which no tree-sitter grammar is available, THE Syntax_Validator SHALL return false and log a warning indicating the language is unsupported for validation.
5. WHEN the Syntax_Validator returns false for LLM-generated code, THE Remediation_Engine SHALL fall back to the Template_Engine instead of applying the invalid code.

### Requirement 5: Batch Mode

**User Story:** As a developer, I want to fix all vulnerabilities in a file (or across files) in one command without confirming each fix individually, so that I can remediate large scan results efficiently.

#### Acceptance Criteria

1. WHEN the `--yes` flag is passed to `sicario fix`, THE Remediation_Engine SHALL apply all generated fixes without prompting for confirmation.
2. WHEN the `--auto` flag is passed to `sicario fix`, THE Remediation_Engine SHALL apply all generated fixes without prompting for confirmation (alias for `--yes`).
3. WHEN batch mode is active, THE Remediation_Engine SHALL process each vulnerability sequentially, applying one fix at a time and verifying each before proceeding to the next.
4. WHEN a fix fails verification in batch mode, THE Remediation_Engine SHALL revert that specific fix, log a warning, and continue processing the remaining vulnerabilities.
5. WHEN batch mode completes, THE Remediation_Engine SHALL print a summary showing the count of fixes applied, fixes reverted, and fixes skipped.
6. WHEN no flags are passed, THE Remediation_Engine SHALL prompt for confirmation before each fix (preserving current behavior).

### Requirement 6: Dead Code Removal

**User Story:** As a maintainer, I want the dead `CerebrasClient` re-export removed, so that the codebase is clean and new contributors are not confused.

#### Acceptance Criteria

1. THE codebase SHALL NOT contain the file `cerebras_client.rs` or any re-export alias mapping `CerebrasClient` to `LlmClient`.
2. WHEN any module references `CerebrasClient`, THE build SHALL fail, confirming all references have been migrated to `LlmClient`.

### Requirement 7: Cloud-Synced Provider Settings — Backend

**User Story:** As a developer, I want my LLM provider settings stored in the cloud, so that my configuration follows me across machines when I am logged in.

#### Acceptance Criteria

1. THE Provider_Settings_API SHALL expose a `GET /api/v1/provider-settings` endpoint that returns the authenticated user's Cloud_Config (endpoint, model, and a boolean indicating whether an encrypted API key is stored).
2. THE Provider_Settings_API SHALL expose a `PUT /api/v1/provider-settings` endpoint that creates or updates the authenticated user's Cloud_Config.
3. WHEN a `PUT` request includes an `api_key` field, THE Provider_Settings_API SHALL encrypt the API key before storing it in the database.
4. WHEN a `GET` request is made, THE Provider_Settings_API SHALL return the endpoint and model in plaintext but SHALL NOT return the raw API key.
5. THE Provider_Settings_API SHALL expose a `DELETE /api/v1/provider-settings` endpoint that removes the authenticated user's Cloud_Config.
6. WHEN an unauthenticated request is made to any Provider_Settings_API endpoint, THE Provider_Settings_API SHALL return HTTP 401.
7. THE Convex schema SHALL include a `providerSettings` table with fields for userId, endpoint, model, encryptedApiKey, provider name, and timestamps.

### Requirement 8: Cloud-Synced Provider Settings — Dashboard UI

**User Story:** As a developer, I want a settings page in the Sicario dashboard where I can configure my LLM provider, so that I can manage my AI fix settings from the browser.

#### Acceptance Criteria

1. THE Provider_Settings_Page SHALL display a form with fields for provider name, endpoint URL, model name, and API key.
2. THE Provider_Settings_Page SHALL pre-populate the form with the user's existing Cloud_Config when one exists.
3. WHEN the user submits the form, THE Provider_Settings_Page SHALL call the `PUT /api/v1/provider-settings` endpoint and display a success or error notification.
4. THE Provider_Settings_Page SHALL provide a dropdown of common providers (OpenAI, Cerebras, Groq, Ollama, OpenRouter) that auto-fills the endpoint URL when selected.
5. WHEN the user selects a provider from the dropdown, THE Provider_Settings_Page SHALL set the endpoint URL to the provider's standard chat completions endpoint.
6. THE Provider_Settings_Page SHALL mask the API key input field and provide a "reveal" toggle.
7. THE Provider_Settings_Page SHALL include a "Test Connection" button that sends a minimal request to the configured endpoint and displays the result.
8. THE Provider_Settings_Page SHALL include a "Delete Settings" button that calls the `DELETE /api/v1/provider-settings` endpoint and clears the form.
9. THE Provider_Settings_Page SHALL be accessible as a new tab within the existing Settings page.

### Requirement 9: Cloud-Synced Provider Settings — CLI Integration

**User Story:** As a developer, I want the CLI to automatically use my cloud-synced provider settings when I am logged in, so that I do not need to reconfigure on every machine.

#### Acceptance Criteria

1. WHEN the user is authenticated and no local env var or Config_File overrides are present, THE Config_Resolver SHALL fetch Cloud_Config from the Provider_Settings_API and use the cloud endpoint and model values.
2. WHEN the user is authenticated and a local env var is set, THE Config_Resolver SHALL use the local env var value and ignore the Cloud_Config for that field.
3. WHEN the user is authenticated and the Config_File contains a value, THE Config_Resolver SHALL use the Config_File value and ignore the Cloud_Config for that field.
4. WHEN the user is not authenticated, THE Config_Resolver SHALL skip the Cloud_Config layer without error and resolve from local sources only.
5. WHEN the Cloud_Config includes an encrypted API key, THE Config_Resolver SHALL request the decrypted key from the Provider_Settings_API using the authenticated session.
6. WHEN `sicario config show` is executed and Cloud_Config is active, THE Config_Resolver SHALL display "cloud" as the source for any value resolved from Cloud_Config.
7. WHEN the Provider_Settings_API is unreachable, THE Config_Resolver SHALL fall back to local sources and log a warning.
8. FOR ALL combinations of local env vars, Config_File values, and Cloud_Config values, THE Config_Resolver SHALL apply the Resolution_Chain precedence (env var > Config_File > Cloud_Config > default) consistently.

### Requirement 10: Config File Serialization

**User Story:** As a developer, I want the config file format to be reliable and parseable, so that my settings are never corrupted.

#### Acceptance Criteria

1. THE Config_Resolver SHALL parse the Config_File as YAML with fields: `endpoint` (string), `model` (string), `key` (optional string).
2. WHEN `sicario config set-provider` is executed, THE CLI SHALL write a valid YAML Config_File containing the provided endpoint and model values.
3. FOR ALL valid Config_File YAML documents, parsing the document and then serializing it back to YAML and then parsing again SHALL produce an equivalent configuration object (round-trip property).
4. WHEN the Config_File contains unknown fields, THE Config_Resolver SHALL ignore the unknown fields and parse the known fields without error.

# Implementation Plan: AI Fix Overhaul & Cloud-Synced Provider Settings

## Overview

This plan implements the AI fix overhaul in two phases. Phase 1 fixes all local bugs and gaps in the remediation system. Phase 2 adds cloud-synced provider settings across the Convex backend, React dashboard, and CLI. Tasks are ordered so foundational config changes land first, enabling all downstream work.

## Tasks

- [x] 1. Config File Reading — Make `set-provider` config actually work
  - [x] 1.1 Create `sicario-cli/src/key_manager/config_file.rs` with `LocalConfig` struct and YAML parser
    - Define `LocalConfig` with `endpoint: Option<String>`, `model: Option<String>`, `key: Option<String>`, and `#[serde(flatten)] extra: HashMap<String, serde_yaml::Value>`
    - Implement `load_config_file(project_root: &Path) -> Option<LocalConfig>` that reads `.sicario/config.yaml` and returns `None` on missing file or parse error
    - Implement `save_config_file(project_root: &Path, config: &LocalConfig) -> Result<()>` that writes valid YAML
    - Add `pub mod config_file;` to `sicario-cli/src/key_manager/mod.rs`
    - _Requirements: 1.4, 10.1, 10.2, 10.4_

  - [x] 1.2 Extend `resolve_endpoint()` in `key_manager/manager.rs` to read Config_File
    - After checking `SICARIO_LLM_ENDPOINT`, `OPENAI_BASE_URL`, and `CEREBRAS_ENDPOINT` env vars, call `load_config_file()` and check for `endpoint` field
    - Add `resolve_endpoint_with_source() -> ResolvedValue` that returns both the value and its `ConfigSource` enum variant
    - Preserve existing env var precedence — Config_File is checked only if all env vars are absent/empty
    - _Requirements: 1.1, 1.5, 1.6_

  - [x] 1.3 Extend `resolve_model()` in `key_manager/manager.rs` to read Config_File
    - After checking `SICARIO_LLM_MODEL` and `CEREBRAS_MODEL` env vars, call `load_config_file()` and check for `model` field
    - Add `resolve_model_with_source() -> ResolvedValue` that returns both the value and its `ConfigSource`
    - _Requirements: 1.2, 1.5, 1.6_

  - [x] 1.4 Extend `resolve_api_key()` in `key_manager/manager.rs` to read Config_File
    - After checking env vars and OS keyring, call `load_config_file()` and check for `key` field
    - Update `KeySource` enum to include `ConfigFile` variant
    - _Requirements: 1.3, 1.5_

  - [x] 1.5 Update `cmd_config` in `main.rs` to use `resolve_*_with_source()` for `config show`
    - Display the source of each resolved value (e.g., "Endpoint: https://... (from .sicario/config.yaml)")
    - Update `SetProvider` handler to use `save_config_file()` instead of raw `fs::write`
    - _Requirements: 1.6, 10.2_

  - [ ]* 1.6 Write property test for config file round-trip
    - Generate arbitrary `LocalConfig` structs with random endpoint, model, and key values (including None variants)
    - Serialize via `save_config_file`, parse back via `load_config_file`, assert endpoint/model/key fields match
    - **Property 2: Config File Round-Trip**
    - _Requirements: 1.7, 10.3_

  - [ ]* 1.7 Write property test for resolution chain precedence
    - Generate random combinations of env var presence/absence and Config_File presence/absence
    - For each combination, assert the resolver returns the value from the highest-priority source
    - **Property 1: Config Resolution Chain Precedence (Phase 1 subset — env vars + Config_File + defaults)**
    - _Requirements: 1.1, 1.2, 1.3, 1.5_

- [x] 2. Dead Code Removal — Delete `cerebras_client.rs`
  - [x] 2.1 Remove `sicario-cli/src/remediation/cerebras_client.rs`
    - Delete the file entirely
    - Remove `pub mod cerebras_client;` from `sicario-cli/src/remediation/mod.rs`
    - Search for any remaining `CerebrasClient` references and replace with `LlmClient`
    - Verify `cargo build` succeeds with no `CerebrasClient` references
    - _Requirements: 6.1, 6.2_

- [x] 3. Progress Indicator — Terminal spinner during LLM calls
  - [x] 3.1 Create `sicario-cli/src/remediation/progress.rs` with `LlmProgressSpinner`
    - Use `indicatif::ProgressBar::new_spinner()` with cyan spinner style
    - Implement `start(message: &str) -> Self`, `finish_success(message: &str)`, `finish_error(message: &str)`, `finish_timeout()`
    - Spinner ticks every 80ms via `enable_steady_tick`
    - Add `pub mod progress;` to `sicario-cli/src/remediation/mod.rs`
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

  - [x] 3.2 Integrate spinner into `RemediationEngine::generate_fixed_content()`
    - Start spinner with "Generating AI fix..." before the tokio runtime block
    - Call `finish_success` on successful LLM response
    - Call `finish_error` on LLM error (before template fallback)
    - Call `finish_timeout` when the 30-second timeout is hit
    - _Requirements: 2.1, 2.3, 2.4, 2.5_

- [x] 4. Expanded Template Fixes — 6 new vulnerability types
  - [x] 4.1 Create `sicario-cli/src/remediation/templates.rs` and extract existing template logic
    - Move `VulnType` enum, `classify_vulnerability()`, `apply_sql_injection_template()`, `apply_xss_template()`, `apply_command_injection_template()`, `apply_unknown_template()`, and helper functions from `remediation_engine.rs` into `templates.rs`
    - Add `pub mod templates;` to `sicario-cli/src/remediation/mod.rs`
    - Update `remediation_engine.rs` to call `templates::apply_template_fix()` instead of local functions
    - Extend `VulnType` enum with `PathTraversal`, `Ssrf`, `InsecureDeserial`, `HardcodedCreds`, `OpenRedirect`, `Xxe`
    - Extend `classify_vulnerability()` to detect CWE-22, CWE-918, CWE-502, CWE-798, CWE-601, CWE-611
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

  - [x] 4.2 Implement path traversal template fix (CWE-22)
    - Python: `os.path.realpath()` + `startswith(base_dir)` check
    - JavaScript/TypeScript: `path.resolve()` + prefix validation
    - Rust: `canonicalize()` + `starts_with()` check
    - Go: `filepath.Clean()` + `strings.HasPrefix()` check
    - Java: `Paths.get().normalize().toRealPath()` + `startsWith()` check
    - _Requirements: 3.1_

  - [x] 4.3 Implement SSRF template fix (CWE-918)
    - Python: `urllib.parse.urlparse()` + host allowlist check
    - JavaScript/TypeScript: `new URL()` + host allowlist check
    - Go: `url.Parse()` + host allowlist check
    - Java: `new URI()` + host allowlist check
    - _Requirements: 3.2_

  - [x] 4.4 Implement insecure deserialization template fix (CWE-502)
    - Python: Replace `yaml.load()` with `yaml.safe_load()`, replace `pickle.loads()` with `json.loads()`
    - JavaScript: Add JSON schema validation after `JSON.parse()`
    - Java: Replace `ObjectInputStream` with allowlist-based deserialization
    - _Requirements: 3.3_

  - [x] 4.5 Implement hardcoded credentials template fix (CWE-798)
    - Python: Replace string literal with `os.environ.get("SECRET_NAME")`
    - JavaScript/TypeScript: Replace with `process.env.SECRET_NAME`
    - Rust: Replace with `std::env::var("SECRET_NAME")`
    - Go: Replace with `os.Getenv("SECRET_NAME")`
    - Java: Replace with `System.getenv("SECRET_NAME")`
    - _Requirements: 3.4_

  - [x] 4.6 Implement open redirect template fix (CWE-601) and XXE template fix (CWE-611)
    - Open redirect: Validate redirect URL against allowlist of permitted domains for each language
    - XXE: Disable external entity processing — Python: `defusedxml`, Java: `setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`, JS: parser config with `noent: false`
    - _Requirements: 3.5, 3.6_

  - [ ]* 4.7 Write property test for template fix differs from original
    - For each supported VulnType (9 types), generate a vulnerability with the matching CWE and a source code string
    - Assert `apply_template_fix(original, vuln) != original` for every case
    - **Property 3: Template Fix Differs From Original**
    - _Requirements: 3.7_

- [x] 5. Strict Syntax Validation — Reject unknown languages
  - [x] 5.1 Add Ruby and PHP to the `Language` enum in `parser/mod.rs`
    - Add `Ruby` and `Php` variants to the `Language` enum
    - Add `tree-sitter-ruby` and `tree-sitter-php` to `Cargo.toml`
    - Implement `parse_source()` support for Ruby and PHP in `TreeSitterEngine`
    - _Requirements: 4.2, 4.3_

  - [x] 5.2 Change `validate_syntax` to return `false` for unknown languages
    - In `remediation_engine.rs`, change the `_ => return true` arm to `_ => { eprintln!("sicario: warning — no syntax validator for {language}"); return false; }`
    - This ensures LLM-generated code for unsupported languages falls back to template fixes
    - _Requirements: 4.1, 4.4, 4.5_

- [x] 6. Batch Mode — `--yes`/`--auto` flags
  - [x] 6.1 Add `--yes` and `--auto` flags to `FixArgs` in `cli/fix.rs`
    - Add `#[arg(long, alias = "auto")] pub yes: bool` to `FixArgs`
    - _Requirements: 5.1, 5.2_

  - [x] 6.2 Implement batch processing in `RemediationEngine`
    - Add `BatchResult`, `BatchFixDetail`, and `BatchFixOutcome` structs to `remediation_engine.rs`
    - Add `generate_and_apply_batch()` method that processes vulnerabilities sequentially
    - When `auto_confirm` is true, skip `display_diff_and_confirm()` for each fix
    - On verification failure, revert the specific fix, log warning, continue to next
    - Return `BatchResult` with counts of applied, reverted, and skipped fixes
    - _Requirements: 5.3, 5.4, 5.5_

  - [x] 6.3 Update `cmd_fix` in `main.rs` to use batch mode
    - When `args.yes` is true, call `generate_and_apply_batch()` with `auto_confirm: true`
    - When `args.yes` is false, preserve current per-fix confirmation behavior
    - After batch completes, print summary: "N applied, M reverted, K skipped"
    - _Requirements: 5.1, 5.5, 5.6_

- [-] 7. Checkpoint — Phase 1 complete, all local fixes verified
  - Verify `cargo build` succeeds
  - Verify `cargo test` passes
  - Verify `sicario config set-provider` → `sicario config show` displays the config file values
  - Verify `sicario fix --yes` processes multiple findings without prompts

- [x] 8. Cloud Provider Settings — Convex Backend (Phase 2)
  - [x] 8.1 Add `providerSettings` table to `convex/convex/schema.ts`
    - Add table with fields: `userId`, `providerName`, `endpoint`, `model`, `encryptedApiKey` (optional), `createdAt`, `updatedAt`
    - Add index `by_userId` on `["userId"]`
    - _Requirements: 7.7_

  - [x] 8.2 Create `convex/convex/providerSettings.ts` with CRUD mutations and queries
    - `getForUser` query: returns provider settings for authenticated user (without raw key)
    - `upsert` mutation: creates or updates provider settings, encrypts API key if provided
    - `remove` mutation: deletes provider settings for authenticated user
    - `getDecryptedKey` query: returns decrypted API key for authenticated user (CLI-only endpoint)
    - Use AES-256-GCM encryption with `PROVIDER_KEY_ENCRYPTION_SECRET` env var
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [x] 8.3 Add HTTP routes to `convex/convex/http.ts`
    - `GET /api/v1/provider-settings` → calls `getForUser`, returns `{ provider_name, endpoint, model, has_api_key }`
    - `PUT /api/v1/provider-settings` → calls `upsert` with request body
    - `DELETE /api/v1/provider-settings` → calls `remove`
    - `GET /api/v1/provider-settings/key` → calls `getDecryptedKey`, returns `{ api_key }`
    - All routes require Bearer token auth, return 401 if unauthenticated
    - Add OPTIONS preflight handlers for all new routes
    - _Requirements: 7.1, 7.2, 7.5, 7.6_

  - [ ]* 8.4 Write property test for encrypted key never in GET response
    - Store provider settings with various API key values via PUT
    - Call GET and assert the response body does not contain the raw key string
    - Assert `has_api_key` is true when a key was stored
    - **Property 4: Encrypted API Key Never Returned in GET**
    - _Requirements: 7.3, 7.4_

- [x] 9. Cloud Provider Settings — Dashboard UI (Phase 2)
  - [x] 9.1 Create `ProviderTab` component in `SettingsPage.tsx`
    - Add `{ id: 'provider', label: 'Provider' }` to `TAB_DEFS` array
    - Create `ProviderTab` component with form fields: provider dropdown, endpoint input, model input, API key input (masked with reveal toggle)
    - Define `PROVIDER_PRESETS` map with auto-fill values for OpenAI, Cerebras, Groq, Ollama, OpenRouter
    - Pre-populate form from existing cloud config via `GET /api/v1/provider-settings`
    - _Requirements: 8.1, 8.2, 8.4, 8.5, 8.6, 8.9_

  - [x] 9.2 Implement form submission, test connection, and delete
    - "Save" button calls `PUT /api/v1/provider-settings` and shows success/error toast
    - "Test Connection" button sends a minimal chat completion request to the configured endpoint and displays result
    - "Delete Settings" button calls `DELETE /api/v1/provider-settings`, clears form, shows toast
    - _Requirements: 8.3, 8.7, 8.8_

- [x] 10. Cloud Provider Settings — CLI Integration (Phase 2)
  - [x] 10.1 Create `sicario-cli/src/key_manager/cloud_config.rs` with `CloudConfigFetcher`
    - Implement `CloudConfigFetcher::new(base_url, token)` using `reqwest::blocking::Client` with 5-second timeout
    - Implement `fetch_settings() -> Option<CloudProviderSettings>` calling `GET /api/v1/provider-settings`
    - Implement `fetch_api_key() -> Option<String>` calling `GET /api/v1/provider-settings/key`
    - On any error (network, auth, parse), return `None` and log warning via `eprintln!`
    - Add `pub mod cloud_config;` to `sicario-cli/src/key_manager/mod.rs`
    - _Requirements: 9.4, 9.7_

  - [x] 10.2 Extend resolution chain to include Cloud_Config
    - In `resolve_endpoint_with_source()`, after Config_File check, attempt `CloudConfigFetcher::fetch_settings()` if user is authenticated
    - In `resolve_model_with_source()`, same pattern
    - In `resolve_api_key()`, after Config_File check, attempt `CloudConfigFetcher::fetch_api_key()` if user is authenticated
    - Add `CloudConfig` variant to `ConfigSource` enum
    - Update `config show` to display "cloud" as source when Cloud_Config is active
    - _Requirements: 9.1, 9.2, 9.3, 9.5, 9.6_

  - [ ]* 10.3 Write property test for full resolution chain precedence (Phase 2)
    - Generate random combinations of env vars, Config_File, Cloud_Config, and defaults
    - Assert the resolver always returns the value from the highest-priority non-empty source
    - **Property 1: Config Resolution Chain Precedence (full chain)**
    - _Requirements: 9.1, 9.2, 9.3, 9.8_

//! Trait-based template registry for deterministic vulnerability remediation.
//!
//! The `TemplateRegistry` maps Rule IDs and CWE numbers to `PatchTemplate`
//! implementations. When a vulnerability is found, the engine queries the
//! registry first. If a static template exists it applies it directly —
//! bypassing the LLM entirely to prevent semantic drift and eliminate latency.
//! Only unmatched vulnerabilities fall through to the LLM verification loop.
//!
//! # Adding a new template
//!
//! 1. Define a unit struct (e.g. `pub struct MyTemplate;`).
//! 2. Implement `PatchTemplate` for it.
//! 3. Register it in `TemplateRegistry::default()` via
//!    `registry.register_rule(...)` or `registry.register_cwe(...)`.
//!
//! Requirements: 3.1–3.7, 13.5

use std::collections::HashMap;

pub mod auth;
pub mod crypto;
pub mod helpers;
pub mod iac_cloud;
pub mod injection;
pub mod input_file;
pub mod sql;
pub mod web_frameworks;
pub mod web_headers;

// Re-export all templates for convenience
pub use auth::*;
pub use crypto::*;
pub use iac_cloud::*;
pub use injection::*;
pub use input_file::*;
pub use sql::*;
pub use web_frameworks::*;
pub use web_headers::*;

use crate::parser::Language;

// ── Core traits ───────────────────────────────────────────────────────────────

/// A deterministic, LLM-free patch generator for a specific vulnerability class.
///
/// `generate_patch` receives the **single vulnerable line** (already extracted
/// by the engine) and the detected language. It returns `Some(replacement)`
/// when it can handle the case, or `None` to signal that the LLM loop should
/// be used instead.
///
/// The returned string is the replacement for the vulnerable line only — it
/// must NOT include surrounding context. Indentation is re-applied by
/// `splice_patch` in the engine.
pub trait PatchTemplate: Send + Sync {
    /// Attempt to generate a replacement for `vulnerable_line`.
    ///
    /// Returns `Some(fixed_line)` on success, `None` if this template cannot
    /// handle the given input (e.g. wrong language or unrecognised pattern).
    fn generate_patch(&self, vulnerable_line: &str, lang: Language) -> Option<String>;

    /// Human-readable name for diagnostics and logging.
    fn name(&self) -> &'static str;
}

/// A deterministic, LLM-free patch generator that operates on the **full file
/// content** rather than a single line.
///
/// Unlike `PatchTemplate`, which receives only the vulnerable line,
/// `MultiLinePatchTemplate` receives the entire file content and the
/// 1-based line number of the vulnerability. This allows AST-level rewrites
/// that span multiple lines (e.g. SQL parameterisation across a multi-line
/// query construction).
///
/// `generate_multiline_patch` returns `Some(new_file_content)` — the complete
/// fixed file — or `None` to signal that this template cannot handle the case
/// and the engine should fall through to the `PatchTemplate` lookup.
///
/// The returned content is validated with tree-sitter before being accepted.
/// If validation fails the result is discarded and the single-line lookup
/// proceeds.
pub trait MultiLinePatchTemplate: Send + Sync {
    /// Human-readable name for diagnostics and logging.
    fn name(&self) -> &'static str;

    /// Attempt to generate a fully-fixed file content for the vulnerability at
    /// `vulnerable_line` (1-based).
    ///
    /// Returns `Some(fixed_file_content)` on success, `None` if this template
    /// cannot handle the given input.
    fn generate_multiline_patch(
        &self,
        file_content: &str,
        vulnerable_line: usize,
        lang: Language,
    ) -> Option<String>;
}

// ── Registry ──────────────────────────────────────────────────────────────────

/// Maps Rule IDs and CWE numbers to their `PatchTemplate` implementations.
///
/// Lookup order:
/// 1. Multi-line Rule ID match (highest priority — AST-level rewrite)
/// 2. Multi-line CWE match
/// 3. Exact Rule ID match (single-line template)
/// 4. CWE number match (single-line template)
pub struct TemplateRegistry {
    /// rule_id → single-line template
    by_rule: HashMap<String, Box<dyn PatchTemplate>>,
    /// CWE number string (e.g. "338") → single-line template
    by_cwe: HashMap<String, Box<dyn PatchTemplate>>,
    /// rule_id → multi-line template (checked before single-line)
    by_rule_multi: HashMap<String, Box<dyn MultiLinePatchTemplate>>,
    /// CWE number string → multi-line template (checked before single-line)
    by_cwe_multi: HashMap<String, Box<dyn MultiLinePatchTemplate>>,
}

impl TemplateRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            by_rule: HashMap::new(),
            by_cwe: HashMap::new(),
            by_rule_multi: HashMap::new(),
            by_cwe_multi: HashMap::new(),
        }
    }

    /// Register a template for an exact Rule ID.
    pub fn register_rule(&mut self, rule_id: &str, template: Box<dyn PatchTemplate>) {
        self.by_rule.insert(rule_id.to_string(), template);
    }

    /// Register a template for a CWE number (just the digits, e.g. `"338"`).
    pub fn register_cwe(&mut self, cwe_num: &str, template: Box<dyn PatchTemplate>) {
        self.by_cwe.insert(cwe_num.to_string(), template);
    }

    /// Register a `MultiLinePatchTemplate` for a rule ID and optional CWE number.
    ///
    /// The multi-line template is checked before any single-line template for
    /// the same rule/CWE. Pass `None` for `cwe_num` when no CWE alias is needed.
    pub fn register_multi(
        &mut self,
        rule_id: &str,
        cwe_num: Option<&str>,
        template: Box<dyn MultiLinePatchTemplate>,
    ) {
        // We need to store the same template under both keys. Since
        // `Box<dyn MultiLinePatchTemplate>` is not `Clone`, we use a shared
        // `Arc` internally. However, to keep the API simple and avoid changing
        // the field types, we accept a `Box` and register by rule_id only when
        // no CWE is provided, or register by CWE only when rule_id is empty.
        //
        // For the common case (both rule_id and cwe_num provided), the caller
        // must call `register_multi` twice — once per key — or use the
        // convenience wrapper below.
        self.by_rule_multi.insert(rule_id.to_string(), template);
        // CWE alias is registered separately via `register_multi_cwe`.
        let _ = cwe_num; // stored via register_multi_cwe if needed
    }

    /// Register a `MultiLinePatchTemplate` for a CWE number only.
    ///
    /// Use this alongside `register_multi` when the same template should be
    /// reachable by both rule ID and CWE number.
    pub fn register_multi_cwe(&mut self, cwe_num: &str, template: Box<dyn MultiLinePatchTemplate>) {
        self.by_cwe_multi.insert(cwe_num.to_string(), template);
    }

    /// Look up a `MultiLinePatchTemplate` for the given rule_id and optional CWE.
    ///
    /// Returns a reference to the best matching multi-line template, or `None`.
    pub fn lookup_multi(
        &self,
        rule_id: &str,
        cwe_id: Option<&str>,
    ) -> Option<&dyn MultiLinePatchTemplate> {
        // 1. Exact rule ID match
        if let Some(t) = self.by_rule_multi.get(rule_id) {
            return Some(t.as_ref());
        }

        // 2. CWE match — extract numeric part from "CWE-338" → "338"
        if let Some(cwe) = cwe_id {
            let cwe_num = cwe
                .to_lowercase()
                .trim_start_matches("cwe-")
                .trim()
                .to_string();
            if let Some(t) = self.by_cwe_multi.get(&cwe_num) {
                return Some(t.as_ref());
            }
        }

        None
    }

    /// Look up a template for the given rule_id and optional CWE string.
    ///
    /// Returns a reference to the best matching template, or `None` if no
    /// static template is registered for this vulnerability.
    pub fn lookup(&self, rule_id: &str, cwe_id: Option<&str>) -> Option<&dyn PatchTemplate> {
        // 1. Exact rule ID match
        if let Some(t) = self.by_rule.get(rule_id) {
            return Some(t.as_ref());
        }

        // 2. CWE match — extract numeric part from "CWE-338" → "338"
        if let Some(cwe) = cwe_id {
            let cwe_num = cwe
                .to_lowercase()
                .trim_start_matches("cwe-")
                .trim()
                .to_string();
            if let Some(t) = self.by_cwe.get(&cwe_num) {
                return Some(t.as_ref());
            }
        }

        None
    }

    /// Apply the best matching template for a vulnerability, if one exists.
    ///
    /// `vulnerable_line` is the single source line that triggered the finding.
    /// `lang` is the detected language of the file.
    ///
    /// Returns `Some(fixed_line)` when a template matched and produced output,
    /// `None` when no template is registered or the template declined.
    pub fn apply(
        &self,
        rule_id: &str,
        cwe_id: Option<&str>,
        vulnerable_line: &str,
        lang: Language,
    ) -> Option<String> {
        self.lookup(rule_id, cwe_id)?
            .generate_patch(vulnerable_line, lang)
    }
}

impl Default for TemplateRegistry {
    /// Build the default registry with all "Sicario 100" templates registered.
    fn default() -> Self {
        let mut r = Self::new();

        // ── Crypto ────────────────────────────────────────────────────────────
        r.register_cwe("328", Box::new(CryptoWeakHashTemplate)); // Weak hash (MD5/SHA1)
        r.register_cwe("338", Box::new(CryptoMathRandomTemplate)); // Insecure PRNG
        r.register_cwe("327", Box::new(CryptoEcbModeTemplate)); // Weak cipher mode (ECB)
        r.register_cwe("759", Box::new(AuthMissingSaltTemplate)); // Missing salt

        // Rule-ID aliases for the PRNG template (our own rules use these IDs)
        r.register_rule("js-crypto-math-random", Box::new(CryptoMathRandomTemplate));
        r.register_rule("js-math-random-crypto", Box::new(CryptoMathRandomTemplate));

        // Rule-ID aliases for ECB mode
        r.register_rule("crypto-ecb-mode", Box::new(CryptoEcbModeTemplate));
        r.register_rule("js-crypto-ecb", Box::new(CryptoEcbModeTemplate));
        r.register_rule("py-crypto-ecb", Box::new(CryptoEcbModeTemplate));

        // Rule-ID aliases for hardcoded JWT secret (CWE-798 is also used by
        // hardcoded-creds, so we register by rule ID to avoid collision)
        r.register_rule(
            "js-jwt-hardcoded-secret",
            Box::new(CryptoHardcodedJwtTemplate),
        );
        r.register_rule(
            "py-jwt-hardcoded-secret",
            Box::new(CryptoHardcodedJwtTemplate),
        );
        r.register_rule("jwt-hardcoded-secret", Box::new(CryptoHardcodedJwtTemplate));

        // Rule-ID aliases for missing bcrypt salt
        r.register_rule("js-bcrypt-missing-salt", Box::new(AuthMissingSaltTemplate));
        r.register_rule("bcrypt-missing-rounds", Box::new(AuthMissingSaltTemplate));

        // ── DOM / XSS ─────────────────────────────────────────────────────────
        r.register_rule("js-innerhtml", Box::new(DomInnerHtmlTemplate));
        r.register_rule(
            "js-xss-innerhtml-assignment",
            Box::new(DomInnerHtmlTemplate),
        );
        r.register_rule("js-document-write", Box::new(DomDocumentWriteTemplate));
        r.register_rule("js-xss-document-write", Box::new(DomDocumentWriteTemplate));

        // CWE-79 and generic "xss" rule alias
        r.register_cwe("79", Box::new(DomInnerHtmlTemplate));
        r.register_rule("xss", Box::new(DomInnerHtmlTemplate));
        r.register_rule("xss-reflected", Box::new(DomInnerHtmlTemplate));

        // postMessage wildcard origin
        r.register_cwe("345", Box::new(DomPostMessageWildcardTemplate));
        r.register_rule(
            "js-postmessage-wildcard",
            Box::new(DomPostMessageWildcardTemplate),
        );
        r.register_rule(
            "dom-postmessage-wildcard",
            Box::new(DomPostMessageWildcardTemplate),
        );

        // ── CORS ──────────────────────────────────────────────────────────────
        r.register_rule("cors-wildcard", Box::new(WebCorsWildcardTemplate));
        r.register_rule("js-cors-wildcard", Box::new(WebCorsWildcardTemplate));

        // ── Cookie security ───────────────────────────────────────────────────
        r.register_cwe("614", Box::new(WebCookieInsecureTemplate)); // Missing Secure flag
        r.register_cwe("1004", Box::new(WebCookieInsecureTemplate)); // Missing HttpOnly flag
        r.register_rule("js-cookie-no-httponly", Box::new(WebCookieInsecureTemplate));
        r.register_rule("js-cookie-no-secure", Box::new(WebCookieInsecureTemplate));
        r.register_rule(
            "express-cookie-insecure",
            Box::new(WebCookieInsecureTemplate),
        );

        // ── Express security headers ──────────────────────────────────────────
        r.register_cwe("200", Box::new(WebExpressXPoweredByTemplate)); // Info exposure
        r.register_rule(
            "express-x-powered-by",
            Box::new(WebExpressXPoweredByTemplate),
        );
        r.register_rule(
            "js-express-xpoweredby",
            Box::new(WebExpressXPoweredByTemplate),
        );

        // ── Python unsafe deserialization ─────────────────────────────────────
        r.register_rule("py-unsafe-yaml", Box::new(PyUnsafeDeserializeTemplate));
        r.register_rule("py-pickle-loads", Box::new(PyUnsafeDeserializeTemplate));
        r.register_rule(
            "python-unsafe-deserialization",
            Box::new(PyUnsafeDeserializeTemplate),
        );

        // ── Python TLS verification disabled ─────────────────────────────────
        r.register_cwe("295", Box::new(PyRequestsVerifyFalseTemplate)); // Improper cert validation
        r.register_rule(
            "py-requests-verify-false",
            Box::new(PyRequestsVerifyFalseTemplate),
        );
        r.register_rule(
            "python-ssl-verify-false",
            Box::new(PyRequestsVerifyFalseTemplate),
        );

        // ── Go resource leak ──────────────────────────────────────────────────
        r.register_rule("go-defer-close", Box::new(GoDeferCloseTemplate));
        r.register_rule("go-missing-defer-close", Box::new(GoDeferCloseTemplate));

        // ── Injection ─────────────────────────────────────────────────────────
        r.register_cwe("94", Box::new(InjectEvalTemplate)); // Code injection via eval
        r.register_rule("js-eval-injection", Box::new(InjectEvalTemplate));
        r.register_rule("py-eval-injection", Box::new(InjectEvalTemplate));

        r.register_rule("js-child-process-exec", Box::new(InjectOsExecTemplate));
        r.register_rule("node-exec-injection", Box::new(InjectOsExecTemplate));

        r.register_cwe("943", Box::new(InjectNoSqlTypeCastTemplate)); // NoSQL injection
        r.register_rule("js-nosql-injection", Box::new(InjectNoSqlTypeCastTemplate));
        r.register_rule(
            "mongoose-nosql-injection",
            Box::new(InjectNoSqlTypeCastTemplate),
        );

        r.register_rule(
            "react-dangerously-set-innerhtml",
            Box::new(ReactDangerouslySetInnerHtmlTemplate),
        );
        r.register_rule(
            "js-react-xss",
            Box::new(ReactDangerouslySetInnerHtmlTemplate),
        );

        // ── IaC / Dockerfile ──────────────────────────────────────────────────
        r.register_cwe("269", Box::new(IacDockerRootUserTemplate)); // Privilege escalation
        r.register_rule("dockerfile-root-user", Box::new(IacDockerRootUserTemplate));
        r.register_rule("iac-docker-root", Box::new(IacDockerRootUserTemplate));

        // ── Sprint 1: Cryptography & Secrets ─────────────────────────────────
        r.register_cwe("916", Box::new(CryptoPbkdf2LowIterationsTemplate)); // Weak KDF iterations
        r.register_rule(
            "js-pbkdf2-low-iterations",
            Box::new(CryptoPbkdf2LowIterationsTemplate),
        );
        r.register_rule(
            "py-pbkdf2-low-iterations",
            Box::new(CryptoPbkdf2LowIterationsTemplate),
        );
        r.register_rule(
            "crypto-pbkdf2-iterations",
            Box::new(CryptoPbkdf2LowIterationsTemplate),
        );

        r.register_cwe("326", Box::new(CryptoRsaKeyTooShortTemplate)); // Inadequate key strength
        r.register_rule(
            "js-rsa-key-too-short",
            Box::new(CryptoRsaKeyTooShortTemplate),
        );
        r.register_rule(
            "py-rsa-key-too-short",
            Box::new(CryptoRsaKeyTooShortTemplate),
        );
        r.register_rule(
            "crypto-rsa-weak-key",
            Box::new(CryptoRsaKeyTooShortTemplate),
        );

        r.register_cwe("321", Box::new(CryptoHardcodedAesKeyTemplate)); // Hardcoded crypto key
        r.register_rule(
            "js-hardcoded-aes-key",
            Box::new(CryptoHardcodedAesKeyTemplate),
        );
        r.register_rule(
            "py-hardcoded-aes-key",
            Box::new(CryptoHardcodedAesKeyTemplate),
        );
        r.register_rule(
            "crypto-hardcoded-key",
            Box::new(CryptoHardcodedAesKeyTemplate),
        );

        r.register_cwe("335", Box::new(CryptoInsecureRandomSeedTemplate)); // Predictable seed
        r.register_rule(
            "py-random-seed-fixed",
            Box::new(CryptoInsecureRandomSeedTemplate),
        );
        r.register_rule(
            "py-insecure-random-seed",
            Box::new(CryptoInsecureRandomSeedTemplate),
        );

        // CWE-916 is shared with PBKDF2; register md5-password by rule ID only
        r.register_rule(
            "js-md5-password-hash",
            Box::new(CryptoMd5PasswordHashTemplate),
        );
        r.register_rule(
            "py-md5-password-hash",
            Box::new(CryptoMd5PasswordHashTemplate),
        );
        r.register_rule(
            "go-md5-password-hash",
            Box::new(CryptoMd5PasswordHashTemplate),
        );
        r.register_rule(
            "crypto-md5-password",
            Box::new(CryptoMd5PasswordHashTemplate),
        );

        r.register_cwe("347", Box::new(CryptoJwtNoneAlgorithmTemplate)); // Missing signature verification
        r.register_rule(
            "js-jwt-none-algorithm",
            Box::new(CryptoJwtNoneAlgorithmTemplate),
        );
        r.register_rule(
            "py-jwt-none-algorithm",
            Box::new(CryptoJwtNoneAlgorithmTemplate),
        );
        r.register_rule(
            "jwt-algorithm-none",
            Box::new(CryptoJwtNoneAlgorithmTemplate),
        );

        // CWE-327 is shared with ECB; register weak-jwt by rule ID only
        r.register_rule(
            "js-jwt-weak-algorithm",
            Box::new(CryptoJwtWeakAlgorithmTemplate),
        );
        r.register_rule(
            "py-jwt-weak-algorithm",
            Box::new(CryptoJwtWeakAlgorithmTemplate),
        );
        r.register_rule(
            "jwt-weak-algorithm",
            Box::new(CryptoJwtWeakAlgorithmTemplate),
        );

        r.register_cwe("760", Box::new(CryptoHardcodedSaltTemplate)); // Hardcoded salt
        r.register_rule(
            "py-bcrypt-hardcoded-salt",
            Box::new(CryptoHardcodedSaltTemplate),
        );
        r.register_rule(
            "crypto-hardcoded-salt",
            Box::new(CryptoHardcodedSaltTemplate),
        );

        // ── Sprint 2: Auth & Session ──────────────────────────────────────────
        r.register_cwe("1004", Box::new(AuthSessionNoHttpOnlyTemplate));
        r.register_rule(
            "express-session-no-httponly",
            Box::new(AuthSessionNoHttpOnlyTemplate),
        );
        r.register_rule(
            "js-session-cookie-httponly",
            Box::new(AuthSessionNoHttpOnlyTemplate),
        );

        r.register_cwe("614", Box::new(AuthSessionNoSecureFlagTemplate));
        r.register_rule(
            "express-session-no-secure",
            Box::new(AuthSessionNoSecureFlagTemplate),
        );
        r.register_rule(
            "js-session-cookie-secure",
            Box::new(AuthSessionNoSecureFlagTemplate),
        );

        r.register_cwe("384", Box::new(AuthSessionFixationTemplate));
        r.register_rule("js-session-fixation", Box::new(AuthSessionFixationTemplate));
        r.register_rule(
            "express-session-fixation",
            Box::new(AuthSessionFixationTemplate),
        );

        r.register_cwe("532", Box::new(AuthPasswordInLogTemplate));
        r.register_rule("js-password-in-log", Box::new(AuthPasswordInLogTemplate));
        r.register_rule("py-password-in-log", Box::new(AuthPasswordInLogTemplate));
        r.register_rule("log-sensitive-data", Box::new(AuthPasswordInLogTemplate));

        r.register_cwe("523", Box::new(AuthBasicAuthOverHttpTemplate));
        r.register_rule(
            "js-basic-auth-over-http",
            Box::new(AuthBasicAuthOverHttpTemplate),
        );

        r.register_cwe("613", Box::new(AuthJwtNoExpiryTemplate));
        r.register_rule("js-jwt-no-expiry", Box::new(AuthJwtNoExpiryTemplate));
        r.register_rule("py-jwt-no-expiry", Box::new(AuthJwtNoExpiryTemplate));
        r.register_rule("jwt-missing-expiry", Box::new(AuthJwtNoExpiryTemplate));

        // ── Sprint 2: Injection (continued) ──────────────────────────────────
        r.register_rule(
            "js-child-process-shell-true",
            Box::new(InjectChildProcessShellTrueTemplate),
        );
        r.register_rule(
            "node-spawn-shell-true",
            Box::new(InjectChildProcessShellTrueTemplate),
        );

        r.register_rule(
            "py-subprocess-shell-true",
            Box::new(InjectPythonSubprocessShellTemplate),
        );
        r.register_rule(
            "python-shell-injection",
            Box::new(InjectPythonSubprocessShellTemplate),
        );

        // CWE-78 and command-injection rule aliases
        r.register_cwe("78", Box::new(OsSystemInjectionTemplate));
        r.register_rule("command-injection", Box::new(OsSystemInjectionTemplate));
        r.register_rule("command-injection-os", Box::new(OsSystemInjectionTemplate));

        r.register_rule("py-ssti-render-template", Box::new(InjectSstiTemplate));
        r.register_rule("flask-ssti", Box::new(InjectSstiTemplate));

        r.register_cwe("90", Box::new(InjectLdapTemplate));
        r.register_rule("js-ldap-injection", Box::new(InjectLdapTemplate));
        r.register_rule("py-ldap-injection", Box::new(InjectLdapTemplate));

        r.register_cwe("643", Box::new(InjectXpathTemplate));
        r.register_rule("js-xpath-injection", Box::new(InjectXpathTemplate));
        r.register_rule("py-xpath-injection", Box::new(InjectXpathTemplate));

        // ── Sprint 3: Web Headers ─────────────────────────────────────────────
        r.register_rule("express-helmet-missing", Box::new(WebHelmetMissingTemplate));
        r.register_rule("js-helmet-missing", Box::new(WebHelmetMissingTemplate));

        r.register_rule("express-csp-missing", Box::new(WebCspMissingTemplate));
        r.register_rule("js-csp-missing", Box::new(WebCspMissingTemplate));

        r.register_cwe("319", Box::new(WebHstsDisabledTemplate));
        r.register_rule("express-hsts-disabled", Box::new(WebHstsDisabledTemplate));
        r.register_rule("js-hsts-disabled", Box::new(WebHstsDisabledTemplate));

        r.register_cwe("942", Box::new(WebCorsCredentialsWildcardTemplate));
        r.register_rule(
            "js-cors-credentials-wildcard",
            Box::new(WebCorsCredentialsWildcardTemplate),
        );

        r.register_rule(
            "express-referrer-policy",
            Box::new(WebReferrerPolicyMissingTemplate),
        );
        r.register_rule(
            "js-referrer-policy-missing",
            Box::new(WebReferrerPolicyMissingTemplate),
        );

        r.register_cwe("1021", Box::new(WebClickjackingTemplate));
        r.register_rule(
            "express-frameguard-disabled",
            Box::new(WebClickjackingTemplate),
        );
        r.register_rule("js-clickjacking", Box::new(WebClickjackingTemplate));

        r.register_cwe("525", Box::new(WebCacheControlMissingTemplate));
        r.register_rule(
            "express-no-cache-control",
            Box::new(WebCacheControlMissingTemplate),
        );
        r.register_rule(
            "js-cache-control-missing",
            Box::new(WebCacheControlMissingTemplate),
        );

        // ── Sprint 3: Input Validation ────────────────────────────────────────
        r.register_cwe("1321", Box::new(PrototypePollutionMergeTemplate));
        r.register_rule(
            "js-prototype-pollution-merge",
            Box::new(PrototypePollutionMergeTemplate),
        );

        r.register_rule(
            "js-prototype-pollution-set",
            Box::new(PrototypePollutionSetTemplate),
        );
        r.register_rule(
            "js-prototype-unsafe-merge",
            Box::new(PrototypePollutionSetTemplate),
        );

        r.register_cwe("1333", Box::new(InputRegexDosTemplate));
        r.register_rule("js-redos", Box::new(InputRegexDosTemplate));
        r.register_rule("js-regex-dos", Box::new(InputRegexDosTemplate));

        r.register_cwe("755", Box::new(InputJsonParseNoTryCatchTemplate));
        r.register_rule(
            "js-json-parse-no-try-catch",
            Box::new(InputJsonParseNoTryCatchTemplate),
        );

        r.register_cwe("22", Box::new(InputPathTraversalTemplate));
        r.register_rule("js-path-traversal", Box::new(InputPathTraversalTemplate));
        r.register_rule("node-path-traversal", Box::new(InputPathTraversalTemplate));

        r.register_cwe("20", Box::new(InputReqBodyNoValidationTemplate));
        r.register_rule(
            "js-req-body-no-validation",
            Box::new(InputReqBodyNoValidationTemplate),
        );
        r.register_rule(
            "express-no-input-validation",
            Box::new(InputReqBodyNoValidationTemplate),
        );

        // ── Sprint 3: File & Resource ─────────────────────────────────────────
        r.register_cwe("434", Box::new(FileUploadNoMimeCheckTemplate));
        r.register_rule(
            "js-multer-no-mime-check",
            Box::new(FileUploadNoMimeCheckTemplate),
        );
        r.register_rule(
            "express-file-upload-unsafe",
            Box::new(FileUploadNoMimeCheckTemplate),
        );

        r.register_cwe("377", Box::new(FileTempFileInsecureTemplate));
        r.register_rule("py-tempfile-mktemp", Box::new(FileTempFileInsecureTemplate));

        r.register_cwe("732", Box::new(FilePermissionsWorldWritableTemplate));
        r.register_rule(
            "py-world-writable-file",
            Box::new(FilePermissionsWorldWritableTemplate),
        );
        r.register_rule(
            "py-chmod-world-writable",
            Box::new(FilePermissionsWorldWritableTemplate),
        );

        r.register_cwe("390", Box::new(GoFileCloseErrorIgnoredTemplate));
        r.register_rule(
            "go-close-error-ignored",
            Box::new(GoFileCloseErrorIgnoredTemplate),
        );
        r.register_rule(
            "go-defer-close-unchecked",
            Box::new(GoFileCloseErrorIgnoredTemplate),
        );

        r.register_cwe("400", Box::new(FileReadSyncTemplate));
        r.register_rule("js-readfilesync-user-input", Box::new(FileReadSyncTemplate));
        r.register_rule("node-sync-file-read", Box::new(FileReadSyncTemplate));

        // ── Sprint 4: SQL + TLS/SSRF + Django/Flask + Cloud/IaC + React ──────

        // AST-level SQL rewrite (multi-line, JS/TS only) — highest priority for CWE-89
        // Replaces the comment-only single-line templates for these rule IDs.
        r.register_multi(
            "js-sql-string-concat",
            None,
            Box::new(SqlAstRewriteTemplate),
        );
        r.register_multi(
            "js-sql-template-string",
            None,
            Box::new(SqlAstRewriteTemplate),
        );
        r.register_multi(
            "node-sql-template-literal",
            None,
            Box::new(SqlAstRewriteTemplate),
        );
        // Register CWE-89 multi-line alias so lookup_multi("...", Some("CWE-89")) works
        r.register_multi_cwe("89", Box::new(SqlAstRewriteTemplate));

        // js-sql-template-literal — YAML rule ID for backtick SQL template literals
        r.register_multi(
            "js-sql-template-literal",
            None,
            Box::new(SqlAstRewriteTemplate),
        );

        // Single-line fallback for non-JS/TS SQL concat (Python, Go, generic)
        r.register_cwe("89", Box::new(SqlStringConcatTemplate));
        r.register_rule("sql-injection", Box::new(SqlStringConcatTemplate));
        r.register_rule("sql-injection-concat", Box::new(SqlStringConcatTemplate));
        r.register_rule("py-sql-string-concat", Box::new(SqlStringConcatTemplate));
        r.register_rule("go-sql-string-concat", Box::new(SqlStringConcatTemplate));
        r.register_rule("sql-string-concat", Box::new(SqlStringConcatTemplate));
        // js-sql-string-concat single-line fallback (used if multi-line returns None)
        r.register_rule("js-sql-string-concat", Box::new(SqlStringConcatTemplate));
        // js-sql-template-string / node-sql-template-literal single-line fallback
        r.register_rule(
            "js-sql-template-string",
            Box::new(SqlTemplateStringTemplate),
        );
        r.register_rule(
            "node-sql-template-literal",
            Box::new(SqlTemplateStringTemplate),
        );
        r.register_rule(
            "js-sql-template-literal",
            Box::new(SqlTemplateStringTemplate),
        );

        // TLS
        r.register_rule("js-tls-min-version", Box::new(TlsMinVersionTemplate));
        r.register_rule("go-tls-min-version", Box::new(TlsMinVersionTemplate));
        r.register_rule("tls-insecure-version", Box::new(TlsMinVersionTemplate));

        r.register_rule(
            "js-tls-reject-unauthorized",
            Box::new(TlsCertVerifyDisabledNodeTemplate),
        );
        r.register_rule(
            "node-tls-verify-disabled",
            Box::new(TlsCertVerifyDisabledNodeTemplate),
        );

        r.register_rule(
            "go-tls-insecure-skip-verify",
            Box::new(TlsCertVerifyDisabledGoTemplate),
        );
        r.register_rule(
            "go-insecure-skip-verify",
            Box::new(TlsCertVerifyDisabledGoTemplate),
        );

        // SSRF
        r.register_rule("js-ssrf-axios", Box::new(SsrfHttpGetUserInputTemplate));
        r.register_rule("py-ssrf-requests", Box::new(SsrfHttpGetUserInputTemplate));
        r.register_rule("ssrf-http-get", Box::new(SsrfHttpGetUserInputTemplate));

        r.register_rule("js-ssrf-fetch", Box::new(SsrfFetchUserInputTemplate));
        r.register_rule("node-fetch-ssrf", Box::new(SsrfFetchUserInputTemplate));

        // Django
        r.register_rule("django-debug-true", Box::new(DjangoDebugTrueTemplate));
        r.register_rule("py-django-debug", Box::new(DjangoDebugTrueTemplate));

        r.register_rule(
            "django-secret-key-hardcoded",
            Box::new(DjangoSecretKeyHardcodedTemplate),
        );
        r.register_rule(
            "py-django-secret-key",
            Box::new(DjangoSecretKeyHardcodedTemplate),
        );

        r.register_cwe("183", Box::new(DjangoAllowedHostsWildcardTemplate));
        r.register_rule(
            "django-allowed-hosts-wildcard",
            Box::new(DjangoAllowedHostsWildcardTemplate),
        );

        r.register_cwe("352", Box::new(DjangoCsrfExemptTemplate));
        r.register_rule("django-csrf-exempt", Box::new(DjangoCsrfExemptTemplate));
        r.register_rule("py-csrf-exempt", Box::new(DjangoCsrfExemptTemplate));

        r.register_cwe("215", Box::new(FlaskDebugTrueTemplate));
        r.register_rule("flask-debug-true", Box::new(FlaskDebugTrueTemplate));
        r.register_rule("py-flask-debug", Box::new(FlaskDebugTrueTemplate));

        r.register_rule(
            "flask-secret-key-hardcoded",
            Box::new(FlaskSecretKeyHardcodedTemplate),
        );
        r.register_rule(
            "py-flask-secret-key",
            Box::new(FlaskSecretKeyHardcodedTemplate),
        );

        r.register_rule(
            "flask-sqlalchemy-uri-hardcoded",
            Box::new(FlaskSqlAlchemyUriHardcodedTemplate),
        );
        r.register_rule(
            "py-sqlalchemy-uri",
            Box::new(FlaskSqlAlchemyUriHardcodedTemplate),
        );

        // Cloud / IaC
        r.register_rule(
            "aws-hardcoded-access-key",
            Box::new(AwsHardcodedAccessKeyTemplate),
        );
        r.register_rule(
            "js-aws-hardcoded-key",
            Box::new(AwsHardcodedAccessKeyTemplate),
        );
        r.register_rule(
            "py-aws-hardcoded-key",
            Box::new(AwsHardcodedAccessKeyTemplate),
        );

        r.register_rule(
            "aws-s3-public-read-acl",
            Box::new(AwsS3PublicReadAclTemplate),
        );
        r.register_rule("js-s3-public-acl", Box::new(AwsS3PublicReadAclTemplate));

        r.register_cwe("1104", Box::new(IacDockerLatestTagTemplate));
        r.register_rule(
            "dockerfile-latest-tag",
            Box::new(IacDockerLatestTagTemplate),
        );
        r.register_rule("iac-docker-latest", Box::new(IacDockerLatestTagTemplate));

        r.register_cwe("706", Box::new(IacDockerAddInsteadOfCopyTemplate));
        r.register_rule(
            "dockerfile-add-instead-of-copy",
            Box::new(IacDockerAddInsteadOfCopyTemplate),
        );
        r.register_rule(
            "iac-docker-add",
            Box::new(IacDockerAddInsteadOfCopyTemplate),
        );

        // IacEnvFileHardcoded — registered by rule ID only (no CWE-798 collision with other templates)
        r.register_rule(
            "env-file-hardcoded-secret",
            Box::new(IacEnvFileHardcodedTemplate),
        );
        r.register_rule(
            "dotenv-hardcoded-value",
            Box::new(IacEnvFileHardcodedTemplate),
        );

        // React / Frontend
        r.register_rule(
            "react-href-javascript",
            Box::new(ReactHrefJavascriptTemplate),
        );
        r.register_rule("js-href-user-input", Box::new(ReactHrefJavascriptTemplate));

        r.register_cwe("601", Box::new(ReactWindowLocationTemplate));
        r.register_rule(
            "js-window-location-redirect",
            Box::new(ReactWindowLocationTemplate),
        );
        r.register_rule("react-open-redirect", Box::new(ReactWindowLocationTemplate));

        r.register_cwe("922", Box::new(ReactLocalStorageTokenTemplate));
        r.register_rule(
            "js-localstorage-token",
            Box::new(ReactLocalStorageTokenTemplate),
        );
        r.register_rule(
            "react-localstorage-auth",
            Box::new(ReactLocalStorageTokenTemplate),
        );

        r.register_cwe("362", Box::new(ReactUseEffectMissingDepTemplate));
        r.register_rule(
            "react-useeffect-missing-dep",
            Box::new(ReactUseEffectMissingDepTemplate),
        );
        r.register_rule(
            "js-useeffect-stale-closure",
            Box::new(ReactUseEffectMissingDepTemplate),
        );

        r
    }
}

// ── Template implementations ──────────────────────────────────────────────────

#[cfg(test)]
mod multi_line_tests {
    use super::*;
    use crate::parser::Language;

    // ── Stub implementations ──────────────────────────────────────────────────

    /// A `MultiLinePatchTemplate` that always returns `Some` with a fixed
    /// replacement (valid JS syntax).
    struct AlwaysSomeMultiTemplate;

    impl MultiLinePatchTemplate for AlwaysSomeMultiTemplate {
        fn name(&self) -> &'static str {
            "always-some-multi"
        }

        fn generate_multiline_patch(
            &self,
            _file_content: &str,
            _vulnerable_line: usize,
            _lang: Language,
        ) -> Option<String> {
            // Return a syntactically valid JS file
            Some("const x = 1;\n".to_string())
        }
    }

    /// A `MultiLinePatchTemplate` that always returns `None`.
    struct AlwaysNoneMultiTemplate;

    impl MultiLinePatchTemplate for AlwaysNoneMultiTemplate {
        fn name(&self) -> &'static str {
            "always-none-multi"
        }

        fn generate_multiline_patch(
            &self,
            _file_content: &str,
            _vulnerable_line: usize,
            _lang: Language,
        ) -> Option<String> {
            None
        }
    }

    /// A `PatchTemplate` that always returns `Some` with a sentinel value so
    /// we can detect when the single-line path was taken.
    struct SentinelSingleTemplate;

    impl PatchTemplate for SentinelSingleTemplate {
        fn name(&self) -> &'static str {
            "sentinel-single"
        }

        fn generate_patch(&self, _vulnerable_line: &str, _lang: Language) -> Option<String> {
            Some("SENTINEL_SINGLE_LINE_FIX".to_string())
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// `register_multi` stores the template and `lookup_multi` retrieves it by
    /// rule ID.
    #[test]
    fn register_multi_and_lookup_by_rule_id() {
        let mut registry = TemplateRegistry::new();
        registry.register_multi("test-rule", None, Box::new(AlwaysSomeMultiTemplate));

        let result = registry.lookup_multi("test-rule", None);
        assert!(
            result.is_some(),
            "lookup_multi should find the registered template"
        );
        assert_eq!(result.unwrap().name(), "always-some-multi");
    }

    /// `register_multi_cwe` stores the template and `lookup_multi` retrieves it
    /// by CWE ID (both raw number and "CWE-NNN" format).
    #[test]
    fn register_multi_cwe_and_lookup_by_cwe() {
        let mut registry = TemplateRegistry::new();
        registry.register_multi_cwe("89", Box::new(AlwaysSomeMultiTemplate));

        // Lookup with raw CWE number
        let result = registry.lookup_multi("unknown-rule", Some("89"));
        assert!(
            result.is_some(),
            "lookup_multi should find template by CWE number"
        );

        // Lookup with "CWE-NNN" format
        let result2 = registry.lookup_multi("unknown-rule", Some("CWE-89"));
        assert!(
            result2.is_some(),
            "lookup_multi should find template by CWE-NNN format"
        );
    }

    /// Rule ID takes priority over CWE when both are registered.
    #[test]
    fn rule_id_takes_priority_over_cwe_in_multi_lookup() {
        let mut registry = TemplateRegistry::new();
        registry.register_multi("priority-rule", None, Box::new(AlwaysSomeMultiTemplate));
        registry.register_multi_cwe("89", Box::new(AlwaysNoneMultiTemplate));

        let result = registry.lookup_multi("priority-rule", Some("89"));
        assert!(result.is_some());
        // Should get the rule-ID match (AlwaysSomeMultiTemplate), not the CWE match
        assert_eq!(result.unwrap().name(), "always-some-multi");
    }

    /// `lookup_multi` returns `None` when no multi-line template is registered
    /// for the given rule/CWE.
    #[test]
    fn lookup_multi_returns_none_when_not_registered() {
        let registry = TemplateRegistry::new();
        assert!(registry.lookup_multi("nonexistent-rule", None).is_none());
        assert!(registry
            .lookup_multi("nonexistent-rule", Some("999"))
            .is_none());
    }

    /// When a `MultiLinePatchTemplate` returns `Some`, `generate_multiline_patch`
    /// produces the expected content.
    #[test]
    fn multi_template_some_produces_content() {
        let tmpl = AlwaysSomeMultiTemplate;
        let result = tmpl.generate_multiline_patch("original content\n", 1, Language::JavaScript);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "const x = 1;\n");
    }

    /// When a `MultiLinePatchTemplate` returns `None`, the result is `None`.
    #[test]
    fn multi_template_none_returns_none() {
        let tmpl = AlwaysNoneMultiTemplate;
        let result = tmpl.generate_multiline_patch("original content\n", 1, Language::JavaScript);
        assert!(result.is_none());
    }

    /// A registry with both a multi-line and a single-line template registered
    /// for the same rule: `lookup_multi` finds the multi-line one, `lookup`
    /// finds the single-line one. This verifies the two maps are independent.
    #[test]
    fn multi_and_single_registrations_are_independent() {
        let mut registry = TemplateRegistry::new();
        registry.register_multi("shared-rule", None, Box::new(AlwaysSomeMultiTemplate));
        registry.register_rule("shared-rule", Box::new(SentinelSingleTemplate));

        // Multi-line lookup returns the multi-line template
        let multi = registry.lookup_multi("shared-rule", None);
        assert!(multi.is_some());
        assert_eq!(multi.unwrap().name(), "always-some-multi");

        // Single-line lookup returns the single-line template
        let single = registry.lookup("shared-rule", None);
        assert!(single.is_some());
        assert_eq!(single.unwrap().name(), "sentinel-single");
    }

    /// `MultiLinePatchTemplate` trait object is `Send + Sync` (compile-time check).
    #[test]
    fn multi_line_template_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn MultiLinePatchTemplate>>();
    }
}

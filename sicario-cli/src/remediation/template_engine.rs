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

use crate::parser::Language;

// ── Core trait ────────────────────────────────────────────────────────────────

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

// ── Registry ──────────────────────────────────────────────────────────────────

/// Maps Rule IDs and CWE numbers to their `PatchTemplate` implementations.
///
/// Lookup order:
/// 1. Exact Rule ID match (highest priority — most specific)
/// 2. CWE number match (e.g. "338" for CWE-338)
pub struct TemplateRegistry {
    /// rule_id → template
    by_rule: HashMap<String, Box<dyn PatchTemplate>>,
    /// CWE number string (e.g. "338") → template
    by_cwe: HashMap<String, Box<dyn PatchTemplate>>,
}

impl TemplateRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            by_rule: HashMap::new(),
            by_cwe: HashMap::new(),
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

        r
    }
}

// ── Template implementations ──────────────────────────────────────────────────

// ── 1. CryptoWeakHashTemplate (CWE-328) ──────────────────────────────────────

/// Replaces weak hash calls (MD5, SHA1) with SHA-256.
///
/// Handles:
/// - `.md5()` → `.sha256()`
/// - `.sha1()` → `.sha256()`
/// - `hashlib.md5(` → `hashlib.sha256(`
/// - `hashlib.sha1(` → `hashlib.sha256(`
/// - `MessageDigest.getInstance("MD5")` → `MessageDigest.getInstance("SHA-256")`
/// - `MessageDigest.getInstance("SHA-1")` → `MessageDigest.getInstance("SHA-256")`
pub struct CryptoWeakHashTemplate;

impl PatchTemplate for CryptoWeakHashTemplate {
    fn name(&self) -> &'static str {
        "CryptoWeakHash"
    }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("md5") && !lower.contains("sha1") && !lower.contains("sha-1") {
            return None;
        }

        let fixed = line
            // Java MessageDigest
            .replace("\"MD5\"", "\"SHA-256\"")
            .replace("\"SHA-1\"", "\"SHA-256\"")
            // Python hashlib
            .replace("hashlib.md5(", "hashlib.sha256(")
            .replace("hashlib.sha1(", "hashlib.sha256(")
            // Generic method-call style
            .replace(".md5()", ".sha256()")
            .replace(".sha1()", ".sha256()")
            // Rust ring / sha1 crate
            .replace("sha1::Sha1", "sha2::Sha256")
            .replace("md5::compute", "sha2::Sha256::digest");

        if fixed == line {
            return None; // pattern not matched
        }
        Some(fixed)
    }
}

// ── 2. CryptoMathRandomTemplate (CWE-338) ────────────────────────────────────

/// Replaces `Math.random()` with a cryptographically secure alternative.
///
/// JavaScript/TypeScript only. Produces:
/// `(crypto.getRandomValues(new Uint32Array(1))[0] / 4294967295)`
pub struct CryptoMathRandomTemplate;

impl PatchTemplate for CryptoMathRandomTemplate {
    fn name(&self) -> &'static str {
        "CryptoMathRandom"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("Math.random()") {
            return None;
        }
        Some(line.replace(
            "Math.random()",
            "(crypto.getRandomValues(new Uint32Array(1))[0] / 4294967295)",
        ))
    }
}

// ── 3. DomInnerHtmlTemplate (CWE-79) ─────────────────────────────────────────

/// Replaces `.innerHTML =` assignments with `.textContent =`.
///
/// This is the safest mechanical fix — it prevents HTML injection while
/// preserving the assignment structure. Applies to JS/TS only.
pub struct DomInnerHtmlTemplate;

impl PatchTemplate for DomInnerHtmlTemplate {
    fn name(&self) -> &'static str {
        "DomInnerHTML"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains(".innerHTML") {
            return None;
        }
        // Replace `.innerHTML =` with `.textContent =`
        // Also handle `innerHTML =` without a leading dot (rare but possible)
        let fixed = line
            .replace(".innerHTML =", ".textContent =")
            .replace(".innerHTML=", ".textContent=");
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// ── 4. DomDocumentWriteTemplate (CWE-79) ─────────────────────────────────────

/// Replaces `document.write(expr)` with a safe DOM text-node append.
///
/// Extracts the argument from `document.write(...)` and rewrites it as:
/// `document.body.appendChild(document.createTextNode(expr))`
pub struct DomDocumentWriteTemplate;

impl PatchTemplate for DomDocumentWriteTemplate {
    fn name(&self) -> &'static str {
        "DomDocumentWrite"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("document.write(") {
            return None;
        }

        // Extract the argument between document.write( ... )
        let arg = extract_call_arg(line, "document.write")?;
        let indent = get_indent(line);
        let semicolon = if line.trim_end().ends_with(';') {
            ";"
        } else {
            ""
        };

        Some(format!(
            "{indent}document.body.appendChild(document.createTextNode({arg})){semicolon}"
        ))
    }
}

// ── 5. WebCorsWildcardTemplate ────────────────────────────────────────────────

/// Replaces `Access-Control-Allow-Origin: *` with an env-var-driven value.
///
/// Works in any language since it's a string replacement. Handles both
/// header-string literals and programmatic header-setting calls.
pub struct WebCorsWildcardTemplate;

impl PatchTemplate for WebCorsWildcardTemplate {
    fn name(&self) -> &'static str {
        "WebCorsWildcard"
    }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        // String literal: `"Access-Control-Allow-Origin", "*"`
        // or header value: `Access-Control-Allow-Origin: *`
        if !line.contains("Access-Control-Allow-Origin") {
            return None;
        }

        let fixed = line
            // Express / Node: res.setHeader("Access-Control-Allow-Origin", "*")
            .replace(
                "\"Access-Control-Allow-Origin\", \"*\"",
                "\"Access-Control-Allow-Origin\", process.env.ALLOWED_ORIGIN || \"\"",
            )
            // Python Flask/Django: response["Access-Control-Allow-Origin"] = "*"
            .replace(
                "\"Access-Control-Allow-Origin\"] = \"*\"",
                "\"Access-Control-Allow-Origin\"] = os.environ.get(\"ALLOWED_ORIGIN\", \"\")",
            )
            // Go: w.Header().Set("Access-Control-Allow-Origin", "*")
            .replace(
                "\"Access-Control-Allow-Origin\", \"*\")",
                "\"Access-Control-Allow-Origin\", os.Getenv(\"ALLOWED_ORIGIN\"))",
            )
            // Raw header string (e.g. in config files or string constants)
            .replace(
                "Access-Control-Allow-Origin: *",
                "Access-Control-Allow-Origin: ${ALLOWED_ORIGIN}",
            );

        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// ── 6. PyUnsafeDeserializeTemplate (CWE-502) ─────────────────────────────────

/// Replaces unsafe Python deserialization calls with safe alternatives.
///
/// - `yaml.load(...)` → `yaml.safe_load(...)`
/// - `pickle.loads(...)` → `json.loads(...)`
/// - `pickle.load(...)` → `json.load(...)`
pub struct PyUnsafeDeserializeTemplate;

impl PatchTemplate for PyUnsafeDeserializeTemplate {
    fn name(&self) -> &'static str {
        "PyUnsafeDeserialize"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }

        let fixed = line
            // yaml.load( → yaml.safe_load(  (must come before generic .load( check)
            .replace("yaml.load(", "yaml.safe_load(")
            // pickle.loads( → json.loads(
            .replace("pickle.loads(", "json.loads(")
            // pickle.load( → json.load(
            .replace("pickle.load(", "json.load(");

        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// ── 7. GoDeferCloseTemplate ───────────────────────────────────────────────────

/// Injects a `defer <var>.Close()` statement after a Go resource-open call.
///
/// Detects patterns like:
/// - `f, err := os.Open(...)`
/// - `rows, err := db.Query(...)`
/// - `resp, err := http.Get(...)`
///
/// and inserts `defer <var>.Close()` on the following line, preserving
/// the original indentation.
pub struct GoDeferCloseTemplate;

impl PatchTemplate for GoDeferCloseTemplate {
    fn name(&self) -> &'static str {
        "GoDeferClose"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Go {
            return None;
        }

        // Match patterns: `varName, err := someCall(...)` or `varName := someCall(...)`
        // where the call is a known resource-opening function.
        let resource_openers = [
            "os.Open(",
            "os.Create(",
            "os.OpenFile(",
            "db.Query(",
            "db.QueryRow(",
            "db.Prepare(",
            "db.Begin(",
            "http.Get(",
            "http.Post(",
            "http.Do(",
            "net.Dial(",
            "net.Listen(",
            "sql.Open(",
        ];

        let trimmed = line.trim();
        let is_resource_open = resource_openers.iter().any(|op| line.contains(op));
        if !is_resource_open {
            return None;
        }

        // Extract the variable name: first identifier before `,` or `:=`
        let var_name = trimmed
            .split([',', ' '])
            .next()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_'))?;

        let indent = get_indent(line);

        // Return the original line plus the defer on the next line
        Some(format!("{line}\n{indent}defer {var_name}.Close()"))
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Get the leading whitespace of a line.
fn get_indent(line: &str) -> &str {
    let trimmed = line.trim_start();
    &line[..line.len() - trimmed.len()]
}

/// Extract the argument string from a simple single-argument function call.
///
/// Given `"  document.write(userInput);"` and `"document.write"`,
/// returns `Some("userInput")`.
///
/// Returns `None` if the call pattern is not found or the argument is empty.
fn extract_call_arg<'a>(line: &'a str, fn_name: &str) -> Option<&'a str> {
    let call = format!("{fn_name}(");
    let start = line.find(&call)? + call.len();
    // Find the matching closing paren — handle one level of nesting
    let rest = &line[start..];
    let mut depth = 1usize;
    let mut end = 0;
    for (i, ch) in rest.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }
    let arg = rest[..end].trim();
    if arg.is_empty() {
        None
    } else {
        Some(arg)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// ── 8. CryptoEcbModeTemplate (CWE-327) ───────────────────────────────────────

/// Replaces ECB cipher mode with GCM in cipher algorithm strings.
///
/// ECB (Electronic Codebook) is deterministic and leaks patterns across blocks.
/// GCM (Galois/Counter Mode) provides authenticated encryption.
///
/// Handles:
/// - `"aes-128-ecb"` → `"aes-256-gcm"`
/// - `"AES/ECB/PKCS5Padding"` → `"AES/GCM/NoPadding"` (Java)
/// - `Cipher.getInstance("AES/ECB/...")` → `Cipher.getInstance("AES/GCM/NoPadding")`
/// - `createCipheriv("aes-...-ecb", ...)` → `createCipheriv("aes-256-gcm", ...)`
pub struct CryptoEcbModeTemplate;

impl PatchTemplate for CryptoEcbModeTemplate {
    fn name(&self) -> &'static str {
        "CryptoEcbMode"
    }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("ecb") {
            return None;
        }

        let fixed = line
            // Java JCE: "AES/ECB/PKCS5Padding" → "AES/GCM/NoPadding"
            .replace("AES/ECB/PKCS5Padding", "AES/GCM/NoPadding")
            .replace("AES/ECB/PKCS7Padding", "AES/GCM/NoPadding")
            .replace("AES/ECB/NoPadding", "AES/GCM/NoPadding")
            // Node.js crypto: any "aes-NNN-ecb" → "aes-256-gcm"
            .replace("aes-128-ecb", "aes-256-gcm")
            .replace("aes-192-ecb", "aes-256-gcm")
            .replace("aes-256-ecb", "aes-256-gcm")
            // Python PyCryptodome / cryptography: AES.MODE_ECB → AES.MODE_GCM
            .replace("AES.MODE_ECB", "AES.MODE_GCM")
            // Generic uppercase ECB → GCM (catches remaining patterns)
            .replace("ECB", "GCM");

        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// ── 9. CryptoHardcodedJwtTemplate (CWE-798) ──────────────────────────────────

/// Replaces hardcoded JWT signing secrets with environment variable lookups.
///
/// Handles JS/TS `jwt.sign(payload, "literal")` and Python
/// `jwt.encode(payload, "literal", ...)`.
///
/// The replacement preserves the rest of the call — only the secret argument
/// is swapped.
pub struct CryptoHardcodedJwtTemplate;

impl PatchTemplate for CryptoHardcodedJwtTemplate {
    fn name(&self) -> &'static str {
        "CryptoHardcodedJwt"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        // Must contain a JWT sign/encode call with a string literal secret
        let lower = line.to_lowercase();
        if !lower.contains("jwt.sign") && !lower.contains("jwt.encode") {
            return None;
        }

        match lang {
            Language::JavaScript | Language::TypeScript => {
                // Replace any string literal (single or double quoted) that
                // appears as the second argument to jwt.sign(...)
                // Pattern: jwt.sign(<anything>, "<secret>") or jwt.sign(<anything>, '<secret>')
                let fixed = replace_jwt_secret_js(line, "process.env.JWT_SECRET")?;
                Some(fixed)
            }
            Language::Python => {
                let fixed = replace_jwt_secret_py(line, "os.environ.get(\"JWT_SECRET\")")?;
                Some(fixed)
            }
            _ => None,
        }
    }
}

/// Replace the string-literal secret in a JS/TS `jwt.sign(payload, "secret", ...)` call.
fn replace_jwt_secret_js(line: &str, replacement: &str) -> Option<String> {
    // Find jwt.sign( or jwt.verify( then locate the second string argument
    for fn_name in &["jwt.sign(", "jwt.verify("] {
        if let Some(call_start) = line.find(fn_name) {
            let after_fn = &line[call_start + fn_name.len()..];
            // Skip the first argument (up to the first top-level comma)
            if let Some(comma_pos) = find_top_level_comma(after_fn) {
                let after_comma = after_fn[comma_pos + 1..].trim_start();
                // Check if the second arg starts with a string literal
                if let Some((secret_end, quote_char)) = find_string_literal_end(after_comma) {
                    let before_secret = &line[..call_start + fn_name.len() + comma_pos + 1];
                    let after_secret = &after_comma[secret_end..];
                    let indent_len = line.len() - line.trim_start().len();
                    let indent = &line[..indent_len];
                    let _ = quote_char; // consumed
                    return Some(format!("{before_secret} {replacement}{after_secret}"));
                }
            }
        }
    }
    None
}

/// Replace the string-literal secret in a Python `jwt.encode(payload, "secret", ...)` call.
fn replace_jwt_secret_py(line: &str, replacement: &str) -> Option<String> {
    for fn_name in &["jwt.encode(", "jwt.decode("] {
        if let Some(call_start) = line.find(fn_name) {
            let after_fn = &line[call_start + fn_name.len()..];
            if let Some(comma_pos) = find_top_level_comma(after_fn) {
                let after_comma = after_fn[comma_pos + 1..].trim_start();
                if let Some((secret_end, _)) = find_string_literal_end(after_comma) {
                    let before_secret = &line[..call_start + fn_name.len() + comma_pos + 1];
                    let after_secret = &after_comma[secret_end..];
                    return Some(format!("{before_secret} {replacement}{after_secret}"));
                }
            }
        }
    }
    None
}

// ── 10. AuthMissingSaltTemplate (CWE-759) ────────────────────────────────────

/// Injects a secure salt-rounds parameter into bcrypt hash calls missing one.
///
/// `bcrypt.hash(password)` → `bcrypt.hash(password, 12)`
/// `bcrypt.hashSync(password)` → `bcrypt.hashSync(password, 12)`
/// `bcrypt.hashpw(password, ...)` is Python — already requires a salt, so
/// this template targets the JS/TS pattern where the rounds arg is omitted.
pub struct AuthMissingSaltTemplate;

impl PatchTemplate for AuthMissingSaltTemplate {
    fn name(&self) -> &'static str {
        "AuthMissingSalt"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }

        let lower = line.to_lowercase();
        if !lower.contains("bcrypt.hash") {
            return None;
        }

        // Only fix calls that have exactly one argument (missing salt rounds).
        // If there's already a second argument (comma inside the call), leave it.
        for fn_name in &["bcrypt.hashSync(", "bcrypt.hash("] {
            if let Some(start) = line.find(fn_name) {
                let after_fn = &line[start + fn_name.len()..];
                // Find the closing paren
                if let Some(close) = find_matching_paren(after_fn) {
                    let args = &after_fn[..close];
                    // If there's already a top-level comma, salt is present
                    if find_top_level_comma(args).is_some() {
                        return None;
                    }
                    // Inject salt rounds
                    let before = &line[..start + fn_name.len()];
                    let after = &after_fn[close..];
                    return Some(format!("{before}{args}, 12{after}"));
                }
            }
        }
        None
    }
}

// ── 11. DomPostMessageWildcardTemplate (CWE-345) ─────────────────────────────

/// Replaces `postMessage(data, '*')` wildcard origin with an env-var target.
///
/// A wildcard origin allows any page to receive the message, enabling
/// cross-origin data leakage.
pub struct DomPostMessageWildcardTemplate;

impl PatchTemplate for DomPostMessageWildcardTemplate {
    fn name(&self) -> &'static str {
        "DomPostMessageWildcard"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("postMessage") {
            return None;
        }

        // Replace the wildcard origin argument: , '*') or , "*")
        let fixed = line
            .replace(", '*')", ", process.env.EXPECTED_ORIGIN)")
            .replace(", \"*\")", ", process.env.EXPECTED_ORIGIN)");

        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// ── 12. WebCookieInsecureTemplate (CWE-614 / CWE-1004) ───────────────────────

/// Appends secure cookie flags to `res.cookie(...)` calls missing them.
///
/// Detects Express.js `res.cookie('name', value)` calls that don't already
/// include a security options object, and appends
/// `{ httpOnly: true, secure: true, sameSite: 'strict' }`.
pub struct WebCookieInsecureTemplate;

impl PatchTemplate for WebCookieInsecureTemplate {
    fn name(&self) -> &'static str {
        "WebCookieInsecure"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }

        if !line.contains("res.cookie(") && !line.contains(".cookie(") {
            return None;
        }

        // If the call already contains httpOnly or secure flags, leave it
        if line.contains("httpOnly") || line.contains("secure:") || line.contains("sameSite") {
            return None;
        }

        // Find the closing paren of the cookie call and inject options before it
        let call = if line.contains("res.cookie(") {
            "res.cookie("
        } else {
            ".cookie("
        };
        let start = line.find(call)?;
        let after_fn = &line[start + call.len()..];
        let close = find_matching_paren(after_fn)?;

        let args = &after_fn[..close];
        let rest = &after_fn[close + 1..]; // everything after the closing paren
        let before = &line[..start + call.len()];

        // Trim trailing semicolon from rest for clean reconstruction
        let rest_trimmed = rest.trim_end_matches(';').trim_end();
        let semicolon = if rest.trim_end().ends_with(';') || line.trim_end().ends_with(';') {
            ";"
        } else {
            ""
        };

        Some(format!(
            "{before}{args}, {{ httpOnly: true, secure: true, sameSite: 'strict' }}){rest_trimmed}{semicolon}"
        ))
    }
}

// ── 13. WebExpressXPoweredByTemplate (CWE-200) ───────────────────────────────

/// Injects `app.disable('x-powered-by')` after Express app initialisation.
///
/// The `X-Powered-By: Express` header leaks framework information to attackers.
/// Detects `const app = express()` (and variants) and appends the disable call
/// on the following line, preserving indentation.
pub struct WebExpressXPoweredByTemplate;

impl PatchTemplate for WebExpressXPoweredByTemplate {
    fn name(&self) -> &'static str {
        "WebExpressXPoweredBy"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }

        // Match: <var> = express() with optional const/let/var
        let trimmed = line.trim();
        if !trimmed.contains("express()") {
            return None;
        }

        // Extract the app variable name
        let app_var = trimmed
            .trim_start_matches("const ")
            .trim_start_matches("let ")
            .trim_start_matches("var ")
            .split(|c: char| c == '=' || c.is_whitespace())
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())?;

        let indent = get_indent(line);
        let semicolon = if line.trim_end().ends_with(';') {
            ";"
        } else {
            ""
        };

        // Return original line + injected disable call on next line
        Some(format!(
            "{line}\n{indent}{app_var}.disable('x-powered-by'){semicolon}"
        ))
    }
}

// ── 14. PyRequestsVerifyFalseTemplate (CWE-295) ───────────────────────────────

/// Removes `verify=False` from Python `requests` calls, restoring TLS verification.
///
/// `requests.get(url, verify=False)` → `requests.get(url)`
/// `requests.post(url, data=d, verify=False)` → `requests.post(url, data=d)`
///
/// Handles both standalone `verify=False` and `verify=False` mixed with other kwargs.
pub struct PyRequestsVerifyFalseTemplate;

impl PatchTemplate for PyRequestsVerifyFalseTemplate {
    fn name(&self) -> &'static str {
        "PyRequestsVerifyFalse"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }
        if !line.contains("verify=False") && !line.contains("verify = False") {
            return None;
        }

        // Remove ", verify=False" or ", verify = False" (with optional spaces)
        // Also handle the case where it's the only kwarg: "(url, verify=False)"
        let fixed = remove_verify_false(line)?;
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

/// Remove `verify=False` (with surrounding comma/space) from a Python call.
fn remove_verify_false(line: &str) -> Option<String> {
    // Try patterns in order of specificity
    let patterns = [
        ", verify=False",
        ", verify = False",
        ",verify=False",
        ",verify = False",
        // Last-arg with no trailing comma
        " verify=False",
        " verify = False",
    ];
    for pat in &patterns {
        if line.contains(pat) {
            return Some(line.replacen(pat, "", 1));
        }
    }
    // Sole kwarg: (url, verify=False) → already handled above
    // Edge case: verify=False is the only argument after url
    if line.contains("(verify=False)") {
        return Some(line.replace("(verify=False)", "()"));
    }
    None
}

// ── 15. InjectEvalTemplate (CWE-94) ──────────────────────────────────────────

/// Replaces `eval(` with `JSON.parse(` (JS/TS) or `ast.literal_eval(` (Python).
///
/// `eval` executes arbitrary code; `JSON.parse` / `ast.literal_eval` safely
/// parse data without code execution.
pub struct InjectEvalTemplate;

impl PatchTemplate for InjectEvalTemplate {
    fn name(&self) -> &'static str {
        "InjectEval"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {
                if !line.contains("eval(") {
                    return None;
                }
                Some(line.replace("eval(", "JSON.parse("))
            }
            Language::Python => {
                if !line.contains("eval(") {
                    return None;
                }
                Some(line.replace("eval(", "ast.literal_eval("))
            }
            _ => None,
        }
    }
}

// ── 16. InjectOsExecTemplate (CWE-78) ────────────────────────────────────────

/// Replaces standalone `exec(` with `execFile(` in Node.js child_process calls.
///
/// `exec` passes the command string to the shell, enabling injection.
/// `execFile` spawns the executable directly with an argument array,
/// bypassing shell interpretation entirely.
///
/// Does NOT replace `.exec(` (regex method) or `execFile(`/`execSync(`.
pub struct InjectOsExecTemplate;

impl PatchTemplate for InjectOsExecTemplate {
    fn name(&self) -> &'static str {
        "InjectOsExec"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !contains_standalone_exec(line) {
            return None;
        }
        Some(replace_standalone_exec(line))
    }
}

/// Returns true if `line` contains `exec(` that is NOT preceded by a dot
/// and is NOT already `execFile(`, `execSync(`, or `execFileSync(`.
fn contains_standalone_exec(line: &str) -> bool {
    let mut search = line;
    while let Some(pos) = search.find("exec(") {
        let before = &search[..pos];
        let prev_char = before.chars().last();
        let suffix = &search[pos..];
        if prev_char != Some('.')
            && !suffix.starts_with("execFile(")
            && !suffix.starts_with("execSync(")
            && !suffix.starts_with("execFileSync(")
        {
            return true;
        }
        search = &search[pos + 5..];
    }
    false
}

/// Replace the first standalone `exec(` with `execFile(`.
fn replace_standalone_exec(line: &str) -> String {
    let mut result = String::with_capacity(line.len() + 4);
    let mut search = line;
    let mut replaced = false;
    while !search.is_empty() {
        if !replaced {
            if let Some(pos) = search.find("exec(") {
                let before = &search[..pos];
                let prev_char = before.chars().last();
                let suffix = &search[pos..];
                if prev_char != Some('.')
                    && !suffix.starts_with("execFile(")
                    && !suffix.starts_with("execSync(")
                    && !suffix.starts_with("execFileSync(")
                {
                    result.push_str(before);
                    result.push_str("execFile(");
                    search = &search[pos + 5..];
                    replaced = true;
                    continue;
                }
                result.push_str(&search[..pos + 5]);
                search = &search[pos + 5..];
                continue;
            }
        }
        result.push_str(search);
        break;
    }
    result
}

// ── 17. InjectNoSqlTypeCastTemplate (CWE-943) ────────────────────────────────

/// Wraps untyped user-input variables in `String()` casts inside MongoDB queries.
///
/// `User.find({ _id: req.query.id })` → `User.find({ _id: String(req.query.id) })`
///
/// Prevents NoSQL object injection where `req.query.id` could be `{ $gt: "" }`
/// instead of a plain string.
pub struct InjectNoSqlTypeCastTemplate;

impl PatchTemplate for InjectNoSqlTypeCastTemplate {
    fn name(&self) -> &'static str {
        "InjectNoSqlTypeCast"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        let is_query = line.contains(".find(")
            || line.contains(".findOne(")
            || line.contains(".findById(")
            || line.contains(".updateOne(")
            || line.contains(".deleteOne(")
            || line.contains(".countDocuments(");
        if !is_query {
            return None;
        }
        let user_input_patterns = ["req.body.", "req.query.", "req.params."];
        let mut fixed = line.to_string();
        let mut changed = false;
        for pat in &user_input_patterns {
            if fixed.contains(pat) {
                fixed = wrap_nosql_input(&fixed, pat);
                changed = true;
            }
        }
        if !changed || fixed == line {
            return None;
        }
        Some(fixed)
    }
}

/// Wrap occurrences of `req.X.field` that are not already inside `String(...)`.
fn wrap_nosql_input(line: &str, prefix: &str) -> String {
    let mut result = String::with_capacity(line.len() + 16);
    let mut rest = line;
    while let Some(pos) = rest.find(prefix) {
        let before = &rest[..pos];
        let already_wrapped = before.trim_end().ends_with("String(");
        let after_prefix = &rest[pos + prefix.len()..];
        let ident_len = after_prefix
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(after_prefix.len());
        let ident = &after_prefix[..ident_len];
        let full_expr = format!("{prefix}{ident}");
        let rest_after = &rest[pos + full_expr.len()..];
        result.push_str(before);
        if already_wrapped || ident.is_empty() {
            result.push_str(&full_expr);
        } else {
            result.push_str(&format!("String({full_expr})"));
        }
        rest = rest_after;
    }
    result.push_str(rest);
    result
}

// ── 18. ReactDangerouslySetInnerHtmlTemplate (CWE-79) ────────────────────────

/// Wraps the `__html` value in `DOMPurify.sanitize(...)` in React JSX.
///
/// `dangerouslySetInnerHTML={{ __html: userInput }}`
/// → `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }}`
pub struct ReactDangerouslySetInnerHtmlTemplate;

impl PatchTemplate for ReactDangerouslySetInnerHtmlTemplate {
    fn name(&self) -> &'static str {
        "ReactDangerouslySetInnerHTML"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("dangerouslySetInnerHTML") || !line.contains("__html:") {
            return None;
        }
        if line.contains("DOMPurify.sanitize(") || line.contains("sanitize(") {
            return None;
        }
        let fixed = wrap_html_value(line)?;
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

/// Wrap the value after `__html:` in `DOMPurify.sanitize(...)`.
fn wrap_html_value(line: &str) -> Option<String> {
    let marker = "__html:";
    let pos = line.find(marker)?;
    let after_marker = &line[pos + marker.len()..];
    let value_start = after_marker.len() - after_marker.trim_start().len();
    let value_str = after_marker.trim_start();
    let value_end = find_value_end(value_str)?;
    let value = value_str[..value_end].trim();
    let before = &line[..pos + marker.len() + value_start];
    let after = &value_str[value_end..];
    Some(format!("{before}DOMPurify.sanitize({value}){after}"))
}

/// Find the end of a JSX expression value (stops at `}` or `,` at depth 0).
fn find_value_end(s: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_str: Option<char> = None;
    for (i, ch) in s.char_indices() {
        if let Some(q) = in_str {
            if ch == q {
                in_str = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => in_str = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' if depth > 0 => {
                depth = depth.saturating_sub(1);
            }
            '}' => {
                if depth == 0 {
                    return Some(i);
                }
                depth -= 1;
            }
            ',' if depth == 0 => return Some(i),
            _ => {}
        }
    }
    Some(s.len())
}

// ── 19. IacDockerRootUserTemplate (CWE-269) ──────────────────────────────────

/// Injects `USER nonroot` before the final `CMD` or `ENTRYPOINT` in a Dockerfile.
///
/// Running containers as root is a privilege escalation risk. This template
/// detects CMD/ENTRYPOINT lines and prepends a USER instruction.
///
/// Accepts any language — Dockerfiles have no entry in the `Language` enum,
/// so the registry matches by rule ID only.
pub struct IacDockerRootUserTemplate;

impl PatchTemplate for IacDockerRootUserTemplate {
    fn name(&self) -> &'static str {
        "IacDockerRootUser"
    }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        let trimmed = line.trim();
        if !trimmed.starts_with("CMD ")
            && !trimmed.starts_with("CMD[")
            && !trimmed.starts_with("ENTRYPOINT ")
            && !trimmed.starts_with("ENTRYPOINT[")
        {
            return None;
        }
        let indent = get_indent(line);
        Some(format!("{indent}USER nonroot\n{line}"))
    }
}

// ── Shared parsing helpers ────────────────────────────────────────────────────
fn find_top_level_comma(s: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_str: Option<char> = None;
    for (i, ch) in s.char_indices() {
        if let Some(q) = in_str {
            if ch == q {
                in_str = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => in_str = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth == 0 {
                    return None; // hit closing paren before finding comma
                }
                depth -= 1;
            }
            ',' if depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

/// Find the end position of a string literal starting at the beginning of `s`.
///
/// Returns `(end_exclusive, quote_char)` where `end_exclusive` is the index
/// just past the closing quote.
fn find_string_literal_end(s: &str) -> Option<(usize, char)> {
    let mut chars = s.char_indices();
    let (_, quote) = chars.next()?;
    if quote != '"' && quote != '\'' && quote != '`' {
        return None;
    }
    for (i, ch) in chars {
        if ch == quote {
            return Some((i + 1, quote));
        }
    }
    None
}

/// Find the index of the closing `)` that matches the opening of `s`
/// (i.e., `s` starts just after the opening `(`).
fn find_matching_paren(s: &str) -> Option<usize> {
    let mut depth = 1usize;
    let mut in_str: Option<char> = None;
    for (i, ch) in s.char_indices() {
        if let Some(q) = in_str {
            if ch == q {
                in_str = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => in_str = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

// ── Sprint 1: Cryptography & Secrets (7 templates) ───────────────────────────

// ── 20. CryptoPbkdf2LowIterationsTemplate (CWE-916) ──────────────────────────

/// Replaces dangerously low PBKDF2 iteration counts with the OWASP 2023 minimum.
///
/// OWASP recommends ≥ 310,000 iterations for PBKDF2-HMAC-SHA256.
/// Handles Node.js `crypto.pbkdf2Sync(pwd, salt, <N>, ...)` and
/// Python `hashlib.pbkdf2_hmac('sha256', pwd, salt, <N>)`.
///
/// Only fires when the iteration count is a numeric literal < 100,000.
pub struct CryptoPbkdf2LowIterationsTemplate;

impl PatchTemplate for CryptoPbkdf2LowIterationsTemplate {
    fn name(&self) -> &'static str {
        "CryptoPbkdf2LowIterations"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript | Language::Python => {}
            _ => return None,
        }

        let lower = line.to_lowercase();
        if !lower.contains("pbkdf2") {
            return None;
        }

        // Find a numeric literal that looks like an iteration count (3rd positional
        // arg in Node, 4th in Python hashlib). We scan for standalone integers
        // that are < 100_000 and replace the first one found.
        replace_low_iteration_count(line, 310_000)
    }
}

/// Scan `line` for the first integer literal < `threshold` and replace it.
/// Returns `None` if no such literal is found or all literals are already safe.
fn replace_low_iteration_count(line: &str, replacement: u64) -> Option<String> {
    // Walk through the line looking for digit sequences
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            // Make sure this isn't part of a larger identifier (preceded by letter/_)
            let preceded_by_ident =
                i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            if preceded_by_ident {
                // Skip past this digit run
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                continue;
            }

            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            // Make sure not followed by a letter (e.g. "1000px")
            let followed_by_ident = i < bytes.len()
                && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' || bytes[i] == b'.');
            if followed_by_ident {
                continue;
            }

            let num_str = &line[start..i];
            if let Ok(n) = num_str.parse::<u64>() {
                // Only replace values that look like iteration counts:
                // > 100 (avoids key lengths like 32/64) and < 100,000 (unsafe)
                if n > 100 && n < 100_000 {
                    let fixed = format!("{}{}{}", &line[..start], replacement, &line[i..]);
                    return Some(fixed);
                }
            }
        } else {
            i += 1;
        }
    }
    None
}

// ── 21. CryptoRsaKeyTooShortTemplate (CWE-326) ───────────────────────────────

/// Replaces RSA key sizes < 2048 bits with 4096.
///
/// Handles:
/// - Node.js: `generateKeyPair('rsa', { modulusLength: 1024 })`
/// - Python cryptography: `rsa.generate_private_key(key_size=1024, ...)`
/// - Python Crypto: `RSA.generate(1024)`
pub struct CryptoRsaKeyTooShortTemplate;

impl PatchTemplate for CryptoRsaKeyTooShortTemplate {
    fn name(&self) -> &'static str {
        "CryptoRsaKeyTooShort"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript | Language::Python => {}
            _ => return None,
        }

        let lower = line.to_lowercase();
        // Must be an RSA key generation context
        if !lower.contains("rsa") && !lower.contains("moduluslength") && !lower.contains("key_size")
        {
            return None;
        }

        // Replace any integer literal in [512, 2047] with 4096
        replace_rsa_key_size(line, 4096)
    }
}

/// Replace the first RSA key size literal in [512, 2047] with `replacement`.
fn replace_rsa_key_size(line: &str, replacement: u32) -> Option<String> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let preceded_by_ident =
                i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            if preceded_by_ident {
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                continue;
            }
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let followed_by_ident = i < bytes.len()
                && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' || bytes[i] == b'.');
            if followed_by_ident {
                continue;
            }

            let num_str = &line[start..i];
            if let Ok(n) = num_str.parse::<u32>() {
                if (512..2048).contains(&n) {
                    return Some(format!("{}{}{}", &line[..start], replacement, &line[i..]));
                }
            }
        } else {
            i += 1;
        }
    }
    None
}

// ── 22. CryptoHardcodedAesKeyTemplate (CWE-321) ──────────────────────────────

/// Replaces a hardcoded string literal used as an AES key with an env-var lookup.
///
/// Handles:
/// - Node.js: `createCipheriv('aes-256-gcm', 'hardcodedkey', iv)`
///   → `createCipheriv('aes-256-gcm', process.env.AES_KEY, iv)`
/// - Python: `AES.new(b'hardcodedkey', AES.MODE_GCM)`
///   → `AES.new(os.environ.get("AES_KEY").encode(), AES.MODE_GCM)`
pub struct CryptoHardcodedAesKeyTemplate;

impl PatchTemplate for CryptoHardcodedAesKeyTemplate {
    fn name(&self) -> &'static str {
        "CryptoHardcodedAesKey"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("aes") {
            return None;
        }

        match lang {
            Language::JavaScript | Language::TypeScript => {
                // createCipheriv / createDecipheriv: second arg is the key
                for fn_name in &["createCipheriv(", "createDecipheriv("] {
                    if let Some(pos) = line.find(fn_name) {
                        let after = &line[pos + fn_name.len()..];
                        // Skip first arg (algorithm string)
                        if let Some(comma) = find_top_level_comma(after) {
                            let after_comma = after[comma + 1..].trim_start();
                            if let Some((end, _)) = find_string_literal_end(after_comma) {
                                let before = &line[..pos + fn_name.len() + comma + 1];
                                let rest = &after_comma[end..];
                                return Some(format!("{before} process.env.AES_KEY{rest}"));
                            }
                        }
                    }
                }
                None
            }
            Language::Python => {
                // AES.new(b'key', ...) or AES.new('key', ...)
                if let Some(pos) = line.find("AES.new(") {
                    let after = &line[pos + "AES.new(".len()..];
                    // The first arg is the key — check for string/bytes literal
                    let trimmed = after.trim_start();
                    // Handle b'...' or b"..." byte literals
                    let (literal_end, is_bytes) =
                        if trimmed.starts_with("b'") || trimmed.starts_with("b\"") {
                            let quote = trimmed.chars().nth(1)?;
                            let inner = &trimmed[2..];
                            let end = inner.find(quote)? + 3; // b + quote + content + quote
                            (end, true)
                        } else if trimmed.starts_with('\'') || trimmed.starts_with('"') {
                            let quote = trimmed.chars().next()?;
                            let inner = &trimmed[1..];
                            let end = inner.find(quote)? + 2;
                            (end, false)
                        } else {
                            return None;
                        };
                    let offset = after.len() - trimmed.len();
                    let before = &line[..pos + "AES.new(".len() + offset];
                    let rest = &trimmed[literal_end..];
                    let _ = is_bytes;
                    return Some(format!(
                        "{before}os.environ.get(\"AES_KEY\").encode(){rest}"
                    ));
                }
                None
            }
            _ => None,
        }
    }
}

// ── 23. CryptoInsecureRandomSeedTemplate (CWE-335) ───────────────────────────

/// Removes deterministic `random.seed(<integer>)` calls in Python.
///
/// A fixed seed makes the PRNG output predictable. The fix replaces the
/// entire call with a comment so the developer is aware of the change.
pub struct CryptoInsecureRandomSeedTemplate;

impl PatchTemplate for CryptoInsecureRandomSeedTemplate {
    fn name(&self) -> &'static str {
        "CryptoInsecureRandomSeed"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }

        if !line.contains("random.seed(") {
            return None;
        }

        // Only fire when the argument is an integer literal (including 0)
        let after_open = line.find("random.seed(")? + "random.seed(".len();
        let rest = &line[after_open..];
        let close = rest.find(')')?;
        let arg = rest[..close].trim();

        // Accept integer literals (possibly negative)
        let is_int_literal = arg
            .trim_start_matches('-')
            .chars()
            .all(|c| c.is_ascii_digit())
            && !arg.is_empty();

        if !is_int_literal {
            return None;
        }

        let indent = get_indent(line);
        Some(format!("{indent}# SICARIO FIX: removed deterministic random.seed({arg}) — PRNG is now seeded from OS entropy"))
    }
}

// ── 24. CryptoMd5PasswordHashTemplate (CWE-916) ──────────────────────────────

/// Replaces MD5-based password hashing with bcrypt.
///
/// MD5 is not a password hashing function — it's a fast hash with no work
/// factor, making it trivially brute-forceable.
///
/// Handles:
/// - JS: `md5(password)` → `await bcrypt.hash(password, 12)`
/// - Python: `hashlib.md5(password.encode())` → `bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))`
/// - Go: `md5.Sum([]byte(password))` → `bcrypt.GenerateFromPassword([]byte(password), 12)`
pub struct CryptoMd5PasswordHashTemplate;

impl PatchTemplate for CryptoMd5PasswordHashTemplate {
    fn name(&self) -> &'static str {
        "CryptoMd5PasswordHash"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("md5") {
            return None;
        }

        let indent = get_indent(line);

        match lang {
            Language::JavaScript | Language::TypeScript => {
                if !line.contains("md5(") && !line.contains("md5.hex(") {
                    return None;
                }
                // Replace the md5(...) call with bcrypt.hash(...)
                // Extract the argument
                let call = if line.contains("md5.hex(") {
                    "md5.hex("
                } else {
                    "md5("
                };
                if let Some(pos) = line.find(call) {
                    let after = &line[pos + call.len()..];
                    if let Some(close) = find_matching_paren(after) {
                        let arg = &after[..close];
                        let before = &line[..pos];
                        let rest = &after[close + 1..];
                        return Some(format!("{before}await bcrypt.hash({arg}, 12){rest}"));
                    }
                }
                None
            }
            Language::Python => {
                if !line.contains("hashlib.md5(") {
                    return None;
                }
                if let Some(pos) = line.find("hashlib.md5(") {
                    let after = &line[pos + "hashlib.md5(".len()..];
                    if let Some(close) = find_matching_paren(after) {
                        let arg = &after[..close];
                        let before = &line[..pos];
                        let rest = &after[close + 1..];
                        return Some(format!(
                            "{before}bcrypt.hashpw({arg}, bcrypt.gensalt(12)){rest}"
                        ));
                    }
                }
                None
            }
            Language::Go => {
                if !line.contains("md5.Sum(") && !line.contains("md5.New(") {
                    return None;
                }
                let call = if line.contains("md5.Sum(") {
                    "md5.Sum("
                } else {
                    "md5.New("
                };
                if let Some(pos) = line.find(call) {
                    let after = &line[pos + call.len()..];
                    if let Some(close) = find_matching_paren(after) {
                        let arg = &after[..close];
                        let before = &line[..pos];
                        let rest = &after[close + 1..];
                        return Some(format!(
                            "{before}bcrypt.GenerateFromPassword({arg}, 12){rest}"
                        ));
                    }
                }
                None
            }
            _ => None,
        }
    }
}

// ── 25. CryptoJwtNoneAlgorithmTemplate (CWE-347) ─────────────────────────────

/// Replaces `'none'` / `"none"` in JWT algorithm specifications with `'HS256'`.
///
/// The `none` algorithm disables signature verification entirely, allowing
/// any token to be accepted as valid.
///
/// Handles:
/// - JS: `{ algorithms: ['none'] }` → `{ algorithms: ['HS256'] }`
/// - JS: `jwt.verify(token, secret, { algorithms: ['none'] })`
/// - Python: `algorithm='none'` → `algorithm='HS256'`
pub struct CryptoJwtNoneAlgorithmTemplate;

impl PatchTemplate for CryptoJwtNoneAlgorithmTemplate {
    fn name(&self) -> &'static str {
        "CryptoJwtNoneAlgorithm"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript | Language::Python => {}
            _ => return None,
        }

        let lower = line.to_lowercase();
        if !lower.contains("none") {
            return None;
        }
        // Must be in a JWT context
        if !lower.contains("jwt") && !lower.contains("algorithm") && !lower.contains("algorithms") {
            return None;
        }

        let fixed = line
            .replace("'none'", "'HS256'")
            .replace("\"none\"", "\"HS256\"");

        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// ── 26. CryptoJwtWeakAlgorithmTemplate (CWE-327) ─────────────────────────────

/// Replaces weak JWT signing algorithms (HS1, RS1, none) with HS256.
///
/// Handles both string literal forms in JS/TS and Python keyword arguments.
pub struct CryptoJwtWeakAlgorithmTemplate;

impl PatchTemplate for CryptoJwtWeakAlgorithmTemplate {
    fn name(&self) -> &'static str {
        "CryptoJwtWeakAlgorithm"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript | Language::Python => {}
            _ => return None,
        }

        let lower = line.to_lowercase();
        // Must be in a JWT context
        if !lower.contains("jwt") && !lower.contains("algorithm") {
            return None;
        }

        // Weak algorithms to replace
        let weak = [
            ("'HS1'", "'HS256'"),
            ("\"HS1\"", "\"HS256\""),
            ("'RS1'", "'RS256'"),
            ("\"RS1\"", "\"RS256\""),
            ("'HS0'", "'HS256'"),
            ("\"HS0\"", "\"HS256\""),
        ];

        let mut fixed = line.to_string();
        let mut changed = false;
        for (from, to) in &weak {
            if fixed.contains(from) {
                fixed = fixed.replace(from, to);
                changed = true;
            }
        }

        if !changed {
            return None;
        }
        Some(fixed)
    }
}

// ── 27. CryptoHardcodedSaltTemplate (CWE-760) ────────────────────────────────

/// Replaces hardcoded bcrypt salt literals with `bcrypt.gensalt(12)`.
///
/// A hardcoded salt defeats the purpose of salting — every password gets the
/// same salt, enabling precomputed rainbow table attacks.
///
/// Handles Python: `bcrypt.hashpw(password, b"$2b$12$hardcodedsalt...")`
pub struct CryptoHardcodedSaltTemplate;

impl PatchTemplate for CryptoHardcodedSaltTemplate {
    fn name(&self) -> &'static str {
        "CryptoHardcodedSalt"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }

        if !line.contains("bcrypt.hashpw(") {
            return None;
        }

        // Find the second argument (the salt) — look for a bytes literal b"..." or b'...'
        let fn_start = line.find("bcrypt.hashpw(")? + "bcrypt.hashpw(".len();
        let after_fn = &line[fn_start..];

        // Skip first argument
        let comma = find_top_level_comma(after_fn)?;
        let after_comma = after_fn[comma + 1..].trim_start();

        // Check if the second arg is a bytes literal (b'...' or b"...")
        if !after_comma.starts_with("b'") && !after_comma.starts_with("b\"") {
            return None;
        }

        let quote = after_comma.chars().nth(1)?;
        let inner = &after_comma[2..];
        let close = inner.find(quote)?;
        let literal_end = close + 3; // b + quote + content + quote

        let before = &line[..fn_start + comma + 1];
        let rest = &after_comma[literal_end..];

        Some(format!("{before} bcrypt.gensalt(12){rest}"))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn js() -> Language {
        Language::JavaScript
    }
    fn ts() -> Language {
        Language::TypeScript
    }
    fn py() -> Language {
        Language::Python
    }
    fn go() -> Language {
        Language::Go
    }

    // ── Registry ──────────────────────────────────────────────────────────────

    #[test]
    fn test_registry_lookup_by_rule_id() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("js-innerhtml", None).is_some());
        assert!(reg.lookup("js-crypto-math-random", None).is_some());
        assert!(reg.lookup("nonexistent-rule", None).is_none());
    }

    #[test]
    fn test_registry_lookup_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown-rule", Some("CWE-338")).is_some());
        assert!(reg.lookup("unknown-rule", Some("cwe-328")).is_some());
        assert!(reg.lookup("unknown-rule", Some("CWE-999")).is_none());
    }

    #[test]
    fn test_registry_rule_takes_priority_over_cwe() {
        let reg = TemplateRegistry::default();
        // js-innerhtml is registered by rule; CWE-79 is not registered by CWE
        let t = reg.lookup("js-innerhtml", Some("CWE-79")).unwrap();
        assert_eq!(t.name(), "DomInnerHTML");
    }

    // ── CryptoWeakHashTemplate ────────────────────────────────────────────────

    #[test]
    fn test_weak_hash_md5_python() {
        let t = CryptoWeakHashTemplate;
        let line = "    h = hashlib.md5(data)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("hashlib.sha256("));
        assert!(!result.contains("md5"));
    }

    #[test]
    fn test_weak_hash_sha1_java() {
        let t = CryptoWeakHashTemplate;
        let line = "    MessageDigest md = MessageDigest.getInstance(\"SHA-1\");";
        let result = t.generate_patch(line, Language::Java).unwrap();
        assert!(result.contains("\"SHA-256\""));
    }

    #[test]
    fn test_weak_hash_no_match() {
        let t = CryptoWeakHashTemplate;
        assert!(t
            .generate_patch("    let x = sha256(data);", js())
            .is_none());
    }

    // ── CryptoMathRandomTemplate ──────────────────────────────────────────────

    #[test]
    fn test_math_random_replaced() {
        let t = CryptoMathRandomTemplate;
        let line = "    const token = Math.random().toString(36);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("crypto.getRandomValues"));
        assert!(!result.contains("Math.random()"));
    }

    #[test]
    fn test_math_random_wrong_lang() {
        let t = CryptoMathRandomTemplate;
        assert!(t.generate_patch("x = Math.random()", py()).is_none());
    }

    #[test]
    fn test_math_random_no_match() {
        let t = CryptoMathRandomTemplate;
        assert!(t.generate_patch("    const x = 42;", js()).is_none());
    }

    // ── DomInnerHtmlTemplate ──────────────────────────────────────────────────

    #[test]
    fn test_innerhtml_replaced() {
        let t = DomInnerHtmlTemplate;
        let line = "    document.getElementById(\"output\").innerHTML = userInput;";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains(".textContent ="));
        assert!(!result.contains(".innerHTML"));
    }

    #[test]
    fn test_innerhtml_wrong_lang() {
        let t = DomInnerHtmlTemplate;
        assert!(t.generate_patch("el.innerHTML = x", py()).is_none());
    }

    // ── DomDocumentWriteTemplate ──────────────────────────────────────────────

    #[test]
    fn test_document_write_replaced() {
        let t = DomDocumentWriteTemplate;
        let line = "    document.write(userInput);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("document.body.appendChild"));
        assert!(result.contains("document.createTextNode"));
        assert!(result.contains("userInput"));
        assert!(!result.contains("document.write("));
    }

    #[test]
    fn test_document_write_preserves_semicolon() {
        let t = DomDocumentWriteTemplate;
        let line = "    document.write(x);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.ends_with(';'));
    }

    #[test]
    fn test_document_write_no_semicolon() {
        let t = DomDocumentWriteTemplate;
        let line = "    document.write(x)";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(!result.ends_with(';'));
    }

    // ── WebCorsWildcardTemplate ───────────────────────────────────────────────

    #[test]
    fn test_cors_wildcard_node() {
        let t = WebCorsWildcardTemplate;
        let line = "    res.setHeader(\"Access-Control-Allow-Origin\", \"*\");";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("process.env.ALLOWED_ORIGIN"));
        assert!(!result.contains(", \"*\""));
    }

    #[test]
    fn test_cors_no_match() {
        let t = WebCorsWildcardTemplate;
        assert!(t
            .generate_patch("    res.setHeader(\"Content-Type\", \"*\");", js())
            .is_none());
    }

    // ── PyUnsafeDeserializeTemplate ───────────────────────────────────────────

    #[test]
    fn test_yaml_load_replaced() {
        let t = PyUnsafeDeserializeTemplate;
        let line = "    data = yaml.load(stream)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("yaml.safe_load("));
        assert!(!result.contains("yaml.load("));
    }

    #[test]
    fn test_pickle_loads_replaced() {
        let t = PyUnsafeDeserializeTemplate;
        let line = "    obj = pickle.loads(data)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("json.loads("));
        assert!(!result.contains("pickle.loads("));
    }

    #[test]
    fn test_py_deserialize_wrong_lang() {
        let t = PyUnsafeDeserializeTemplate;
        assert!(t.generate_patch("yaml.load(x)", js()).is_none());
    }

    // ── GoDeferCloseTemplate ──────────────────────────────────────────────────

    #[test]
    fn test_go_defer_close_os_open() {
        let t = GoDeferCloseTemplate;
        let line = "\tf, err := os.Open(filename)";
        let result = t.generate_patch(line, go()).unwrap();
        assert!(result.contains("defer f.Close()"));
        // Original line must be preserved
        assert!(result.contains("os.Open(filename)"));
    }

    #[test]
    fn test_go_defer_close_db_query() {
        let t = GoDeferCloseTemplate;
        let line = "\trows, err := db.Query(query, args...)";
        let result = t.generate_patch(line, go()).unwrap();
        assert!(result.contains("defer rows.Close()"));
    }

    #[test]
    fn test_go_defer_close_wrong_lang() {
        let t = GoDeferCloseTemplate;
        assert!(t.generate_patch("\tf, err := os.Open(x)", js()).is_none());
    }

    #[test]
    fn test_go_defer_close_no_match() {
        let t = GoDeferCloseTemplate;
        assert!(t.generate_patch("\tx := someOtherCall()", go()).is_none());
    }

    // ── extract_call_arg ──────────────────────────────────────────────────────

    #[test]
    fn test_extract_call_arg_simple() {
        assert_eq!(
            extract_call_arg("document.write(userInput)", "document.write"),
            Some("userInput")
        );
    }

    #[test]
    fn test_extract_call_arg_nested() {
        assert_eq!(
            extract_call_arg("document.write(foo(bar))", "document.write"),
            Some("foo(bar)")
        );
    }

    #[test]
    fn test_extract_call_arg_with_semicolon() {
        assert_eq!(
            extract_call_arg("    document.write(x);", "document.write"),
            Some("x")
        );
    }

    // ── CryptoEcbModeTemplate ─────────────────────────────────────────────────

    #[test]
    fn test_ecb_node_cipher() {
        let t = CryptoEcbModeTemplate;
        let line = "    const cipher = crypto.createCipheriv('aes-128-ecb', key, iv);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("aes-256-gcm"));
        assert!(!result.contains("ecb"));
    }

    #[test]
    fn test_ecb_java_jce() {
        let t = CryptoEcbModeTemplate;
        let line = "    Cipher c = Cipher.getInstance(\"AES/ECB/PKCS5Padding\");";
        let result = t.generate_patch(line, Language::Java).unwrap();
        assert!(result.contains("AES/GCM/NoPadding"));
        assert!(!result.contains("ECB"));
    }

    #[test]
    fn test_ecb_python_pycryptodome() {
        let t = CryptoEcbModeTemplate;
        let line = "    cipher = AES.new(key, AES.MODE_ECB)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("AES.MODE_GCM"));
    }

    #[test]
    fn test_ecb_no_match() {
        let t = CryptoEcbModeTemplate;
        assert!(t
            .generate_patch("    const x = 'aes-256-gcm';", js())
            .is_none());
    }

    // ── CryptoHardcodedJwtTemplate ────────────────────────────────────────────

    #[test]
    fn test_jwt_hardcoded_js() {
        let t = CryptoHardcodedJwtTemplate;
        let line = "    const token = jwt.sign(payload, \"mysecret\");";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("process.env.JWT_SECRET"));
        assert!(!result.contains("\"mysecret\""));
    }

    #[test]
    fn test_jwt_hardcoded_single_quote() {
        let t = CryptoHardcodedJwtTemplate;
        let line = "    const token = jwt.sign(payload, 'mysecret', { expiresIn: '1h' });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("process.env.JWT_SECRET"));
    }

    #[test]
    fn test_jwt_hardcoded_python() {
        let t = CryptoHardcodedJwtTemplate;
        let line = "    token = jwt.encode(payload, \"secret\", algorithm=\"HS256\")";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("os.environ.get(\"JWT_SECRET\")"));
        assert!(!result.contains("\"secret\""));
    }

    #[test]
    fn test_jwt_no_match() {
        let t = CryptoHardcodedJwtTemplate;
        assert!(t
            .generate_patch("    const x = jwt.verify(token, pubKey);", js())
            .is_none());
    }

    // ── AuthMissingSaltTemplate ───────────────────────────────────────────────

    #[test]
    fn test_bcrypt_missing_rounds() {
        let t = AuthMissingSaltTemplate;
        let line = "    const hash = await bcrypt.hash(password);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("bcrypt.hash(password, 12)"));
    }

    #[test]
    fn test_bcrypt_sync_missing_rounds() {
        let t = AuthMissingSaltTemplate;
        let line = "    const hash = bcrypt.hashSync(password);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("bcrypt.hashSync(password, 12)"));
    }

    #[test]
    fn test_bcrypt_already_has_rounds() {
        let t = AuthMissingSaltTemplate;
        // Already has salt rounds — should not modify
        assert!(t
            .generate_patch("    bcrypt.hash(password, 10);", js())
            .is_none());
    }

    #[test]
    fn test_bcrypt_wrong_lang() {
        let t = AuthMissingSaltTemplate;
        assert!(t.generate_patch("bcrypt.hash(password)", py()).is_none());
    }

    // ── DomPostMessageWildcardTemplate ────────────────────────────────────────

    #[test]
    fn test_postmessage_wildcard_single_quote() {
        let t = DomPostMessageWildcardTemplate;
        let line = "    window.postMessage(data, '*');";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("process.env.EXPECTED_ORIGIN"));
        assert!(!result.contains("'*'"));
    }

    #[test]
    fn test_postmessage_wildcard_double_quote() {
        let t = DomPostMessageWildcardTemplate;
        let line = "    iframe.contentWindow.postMessage(msg, \"*\");";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("process.env.EXPECTED_ORIGIN"));
    }

    #[test]
    fn test_postmessage_no_wildcard() {
        let t = DomPostMessageWildcardTemplate;
        // Already has a specific origin
        assert!(t
            .generate_patch("    window.postMessage(data, 'https://example.com');", js())
            .is_none());
    }

    // ── WebCookieInsecureTemplate ─────────────────────────────────────────────

    #[test]
    fn test_cookie_missing_flags() {
        let t = WebCookieInsecureTemplate;
        let line = "    res.cookie('session', token);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("httpOnly: true"));
        assert!(result.contains("secure: true"));
        assert!(result.contains("sameSite: 'strict'"));
    }

    #[test]
    fn test_cookie_already_secure() {
        let t = WebCookieInsecureTemplate;
        let line = "    res.cookie('session', token, { httpOnly: true });";
        assert!(t.generate_patch(line, js()).is_none());
    }

    #[test]
    fn test_cookie_wrong_lang() {
        let t = WebCookieInsecureTemplate;
        assert!(t.generate_patch("    res.cookie('s', t);", py()).is_none());
    }

    // ── WebExpressXPoweredByTemplate ──────────────────────────────────────────

    #[test]
    fn test_express_xpoweredby_const() {
        let t = WebExpressXPoweredByTemplate;
        let line = "const app = express();";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("app.disable('x-powered-by')"));
        // Original line must be preserved
        assert!(result.contains("express()"));
    }

    #[test]
    fn test_express_xpoweredby_custom_var() {
        let t = WebExpressXPoweredByTemplate;
        let line = "  const server = express();";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("server.disable('x-powered-by')"));
    }

    #[test]
    fn test_express_no_match() {
        let t = WebExpressXPoweredByTemplate;
        assert!(t
            .generate_patch("    const router = express.Router();", js())
            .is_none());
    }

    // ── PyRequestsVerifyFalseTemplate ─────────────────────────────────────────

    #[test]
    fn test_requests_verify_false_get() {
        let t = PyRequestsVerifyFalseTemplate;
        let line = "    resp = requests.get(url, verify=False)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(!result.contains("verify=False"));
        assert!(result.contains("requests.get(url)"));
    }

    #[test]
    fn test_requests_verify_false_with_other_kwargs() {
        let t = PyRequestsVerifyFalseTemplate;
        let line = "    resp = requests.post(url, data=payload, verify=False)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(!result.contains("verify=False"));
        assert!(result.contains("data=payload"));
    }

    #[test]
    fn test_requests_verify_true_untouched() {
        let t = PyRequestsVerifyFalseTemplate;
        // verify=True is the default — no match
        assert!(t
            .generate_patch("    resp = requests.get(url, verify=True)", py())
            .is_none());
    }

    #[test]
    fn test_requests_verify_wrong_lang() {
        let t = PyRequestsVerifyFalseTemplate;
        assert!(t
            .generate_patch("requests.get(url, verify=False)", js())
            .is_none());
    }
}

#[cfg(test)]
mod injection_tests {
    use super::*;

    fn js() -> Language {
        Language::JavaScript
    }
    fn ts() -> Language {
        Language::TypeScript
    }
    fn py() -> Language {
        Language::Python
    }
    fn go() -> Language {
        Language::Go
    }

    // ── InjectEvalTemplate ────────────────────────────────────────────────────

    #[test]
    fn test_eval_js_replaced() {
        let t = InjectEvalTemplate;
        let line = "    eval(userInput);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("JSON.parse("));
        assert!(!result.contains("eval("));
    }

    #[test]
    fn test_eval_ts_replaced() {
        let t = InjectEvalTemplate;
        let result = t.generate_patch("    eval(data);", ts()).unwrap();
        assert!(result.contains("JSON.parse("));
    }

    #[test]
    fn test_eval_python_replaced() {
        let t = InjectEvalTemplate;
        let line = "    result = eval(user_input)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("ast.literal_eval("));
        // The bare `eval(` call must be gone — only ast.literal_eval( remains
        assert!(!result.contains(" eval("), "bare eval( should be replaced");
    }

    #[test]
    fn test_eval_wrong_lang() {
        let t = InjectEvalTemplate;
        assert!(t.generate_patch("eval(x)", go()).is_none());
    }

    #[test]
    fn test_eval_no_match() {
        let t = InjectEvalTemplate;
        assert!(t.generate_patch("    const x = 42;", js()).is_none());
    }

    // ── InjectOsExecTemplate ──────────────────────────────────────────────────

    #[test]
    fn test_exec_replaced() {
        let t = InjectOsExecTemplate;
        let line = "    exec(userCommand, callback);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("execFile("));
        assert!(!result.contains("exec("));
    }

    #[test]
    fn test_exec_dot_exec_not_replaced() {
        let t = InjectOsExecTemplate;
        // regex.exec() must NOT be replaced
        assert!(t
            .generate_patch("    const m = pattern.exec(input);", js())
            .is_none());
    }

    #[test]
    fn test_exec_already_execfile_not_replaced() {
        let t = InjectOsExecTemplate;
        assert!(t
            .generate_patch("    execFile(cmd, args, cb);", js())
            .is_none());
    }

    #[test]
    fn test_exec_wrong_lang() {
        let t = InjectOsExecTemplate;
        assert!(t.generate_patch("exec(cmd)", py()).is_none());
    }

    // ── InjectNoSqlTypeCastTemplate ───────────────────────────────────────────

    #[test]
    fn test_nosql_req_query_wrapped() {
        let t = InjectNoSqlTypeCastTemplate;
        let line = "    const user = await User.find({ _id: req.query.id });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("String(req.query.id)"));
        assert!(!result.contains("{ _id: req.query.id }"));
    }

    #[test]
    fn test_nosql_req_body_wrapped() {
        let t = InjectNoSqlTypeCastTemplate;
        let line = "    const doc = await Item.findOne({ name: req.body.name });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("String(req.body.name)"));
    }

    #[test]
    fn test_nosql_already_cast_not_double_wrapped() {
        let t = InjectNoSqlTypeCastTemplate;
        let line = "    User.find({ _id: String(req.query.id) });";
        // Already wrapped — should return None
        assert!(t.generate_patch(line, js()).is_none());
    }

    #[test]
    fn test_nosql_not_a_query() {
        let t = InjectNoSqlTypeCastTemplate;
        assert!(t
            .generate_patch("    const x = req.query.id;", js())
            .is_none());
    }

    #[test]
    fn test_nosql_wrong_lang() {
        let t = InjectNoSqlTypeCastTemplate;
        assert!(t
            .generate_patch("User.find({ _id: req.query.id })", py())
            .is_none());
    }

    // ── ReactDangerouslySetInnerHtmlTemplate ──────────────────────────────────

    #[test]
    fn test_react_dangerous_wrapped() {
        let t = ReactDangerouslySetInnerHtmlTemplate;
        let line = "    <div dangerouslySetInnerHTML={{ __html: userContent }} />";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("DOMPurify.sanitize(userContent)"));
        assert!(!result.contains("__html: userContent }"));
    }

    #[test]
    fn test_react_dangerous_already_sanitized() {
        let t = ReactDangerouslySetInnerHtmlTemplate;
        let line = "    <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(x) }} />";
        assert!(t.generate_patch(line, js()).is_none());
    }

    #[test]
    fn test_react_dangerous_no_match() {
        let t = ReactDangerouslySetInnerHtmlTemplate;
        assert!(t
            .generate_patch("    <div className=\"foo\" />", js())
            .is_none());
    }

    #[test]
    fn test_react_dangerous_wrong_lang() {
        let t = ReactDangerouslySetInnerHtmlTemplate;
        assert!(t
            .generate_patch("dangerouslySetInnerHTML={{ __html: x }}", py())
            .is_none());
    }

    // ── IacDockerRootUserTemplate ─────────────────────────────────────────────

    #[test]
    fn test_docker_cmd_gets_user_injected() {
        let t = IacDockerRootUserTemplate;
        let line = "CMD [\"node\", \"server.js\"]";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("USER nonroot"));
        // USER must come BEFORE CMD
        let user_pos = result.find("USER nonroot").unwrap();
        let cmd_pos = result.find("CMD").unwrap();
        assert!(user_pos < cmd_pos, "USER must precede CMD");
    }

    #[test]
    fn test_docker_entrypoint_gets_user_injected() {
        let t = IacDockerRootUserTemplate;
        let line = "ENTRYPOINT [\"/app/start.sh\"]";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("USER nonroot"));
        assert!(result.contains("ENTRYPOINT"));
    }

    #[test]
    fn test_docker_run_not_matched() {
        let t = IacDockerRootUserTemplate;
        assert!(t.generate_patch("RUN npm install", js()).is_none());
    }

    #[test]
    fn test_docker_from_not_matched() {
        let t = IacDockerRootUserTemplate;
        assert!(t.generate_patch("FROM node:18-alpine", js()).is_none());
    }

    #[test]
    fn test_docker_preserves_indentation() {
        let t = IacDockerRootUserTemplate;
        let line = "  CMD [\"start\"]";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.starts_with("  USER nonroot"));
    }

    // ── Registry integration ──────────────────────────────────────────────────

    #[test]
    fn test_registry_eval_injection_registered() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("js-eval-injection", None).is_some());
        assert_eq!(
            reg.lookup("js-eval-injection", None).unwrap().name(),
            "InjectEval"
        );
    }

    #[test]
    fn test_registry_nosql_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-943")).is_some());
    }

    #[test]
    fn test_registry_docker_root_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-269")).is_some());
    }

    #[test]
    fn test_registry_exec_injection_registered() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("js-child-process-exec", None).is_some());
    }

    #[test]
    fn test_registry_react_xss_registered() {
        let reg = TemplateRegistry::default();
        assert!(reg
            .lookup("react-dangerously-set-innerhtml", None)
            .is_some());
    }
}

// ── Sprint 1 tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod sprint1_tests {
    use super::*;

    fn js() -> Language {
        Language::JavaScript
    }
    fn ts() -> Language {
        Language::TypeScript
    }
    fn py() -> Language {
        Language::Python
    }
    fn go() -> Language {
        Language::Go
    }

    // ── CryptoPbkdf2LowIterationsTemplate ─────────────────────────────────────

    #[test]
    fn test_pbkdf2_low_iterations_node() {
        let t = CryptoPbkdf2LowIterationsTemplate;
        let line = "    const key = crypto.pbkdf2Sync(password, salt, 1000, 32, 'sha256');";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("310000"), "should replace 1000 with 310000");
        assert!(!result.contains(", 1000,"), "original count should be gone");
    }

    #[test]
    fn test_pbkdf2_low_iterations_python() {
        let t = CryptoPbkdf2LowIterationsTemplate;
        let line = "    key = hashlib.pbkdf2_hmac('sha256', pwd, salt, 10000)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("310000"));
        assert!(
            !result.contains("10000,") && !result.contains("10000)") || result.contains("310000")
        );
    }

    #[test]
    fn test_pbkdf2_already_safe() {
        let t = CryptoPbkdf2LowIterationsTemplate;
        // 310000 is already safe — should not modify
        let line = "    crypto.pbkdf2Sync(pwd, salt, 310000, 32, 'sha256');";
        assert!(t.generate_patch(line, js()).is_none());
    }

    #[test]
    fn test_pbkdf2_no_match() {
        let t = CryptoPbkdf2LowIterationsTemplate;
        assert!(t
            .generate_patch("    const x = sha256(data);", js())
            .is_none());
    }

    #[test]
    fn test_pbkdf2_wrong_lang() {
        let t = CryptoPbkdf2LowIterationsTemplate;
        assert!(t.generate_patch("pbkdf2(pwd, salt, 1000)", go()).is_none());
    }

    // ── CryptoRsaKeyTooShortTemplate ──────────────────────────────────────────

    #[test]
    fn test_rsa_key_1024_replaced() {
        let t = CryptoRsaKeyTooShortTemplate;
        let line = "    crypto.generateKeyPair('rsa', { modulusLength: 1024 }, cb);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("4096"));
        assert!(!result.contains("1024"));
    }

    #[test]
    fn test_rsa_key_512_replaced() {
        let t = CryptoRsaKeyTooShortTemplate;
        let line = "    key_size=512";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("4096"));
    }

    #[test]
    fn test_rsa_key_2048_not_replaced() {
        let t = CryptoRsaKeyTooShortTemplate;
        // 2048 is the minimum — should not be replaced
        let line = "    crypto.generateKeyPair('rsa', { modulusLength: 2048 }, cb);";
        assert!(t.generate_patch(line, js()).is_none());
    }

    #[test]
    fn test_rsa_key_4096_not_replaced() {
        let t = CryptoRsaKeyTooShortTemplate;
        let line = "    modulusLength: 4096";
        assert!(t.generate_patch(line, js()).is_none());
    }

    #[test]
    fn test_rsa_key_wrong_lang() {
        let t = CryptoRsaKeyTooShortTemplate;
        assert!(t.generate_patch("modulusLength: 1024", go()).is_none());
    }

    // ── CryptoHardcodedAesKeyTemplate ─────────────────────────────────────────

    #[test]
    fn test_aes_hardcoded_key_node() {
        let t = CryptoHardcodedAesKeyTemplate;
        let line =
            "    const cipher = crypto.createCipheriv('aes-256-gcm', 'mysecretkey12345', iv);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("process.env.AES_KEY"));
        assert!(!result.contains("'mysecretkey12345'"));
    }

    #[test]
    fn test_aes_hardcoded_key_python_bytes() {
        let t = CryptoHardcodedAesKeyTemplate;
        let line = "    cipher = AES.new(b'hardcodedkey1234', AES.MODE_GCM)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("os.environ.get(\"AES_KEY\")"));
        assert!(!result.contains("b'hardcodedkey1234'"));
    }

    #[test]
    fn test_aes_no_match_no_aes() {
        let t = CryptoHardcodedAesKeyTemplate;
        assert!(t
            .generate_patch("    const x = encrypt(key, data);", js())
            .is_none());
    }

    #[test]
    fn test_aes_wrong_lang() {
        let t = CryptoHardcodedAesKeyTemplate;
        assert!(t
            .generate_patch("AES.new(b'key', AES.MODE_GCM)", go())
            .is_none());
    }

    // ── CryptoInsecureRandomSeedTemplate ──────────────────────────────────────

    #[test]
    fn test_random_seed_zero() {
        let t = CryptoInsecureRandomSeedTemplate;
        let line = "    random.seed(0)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("# SICARIO FIX"));
        assert!(result.contains("random.seed(0)"));
        assert!(!result.starts_with("    random.seed(0)"));
    }

    #[test]
    fn test_random_seed_integer() {
        let t = CryptoInsecureRandomSeedTemplate;
        let line = "random.seed(42)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("# SICARIO FIX"));
    }

    #[test]
    fn test_random_seed_variable_not_replaced() {
        let t = CryptoInsecureRandomSeedTemplate;
        // Variable seed — not deterministic, don't touch
        assert!(t.generate_patch("    random.seed(entropy)", py()).is_none());
    }

    #[test]
    fn test_random_seed_wrong_lang() {
        let t = CryptoInsecureRandomSeedTemplate;
        assert!(t.generate_patch("random.seed(0)", js()).is_none());
    }

    #[test]
    fn test_random_seed_preserves_indentation() {
        let t = CryptoInsecureRandomSeedTemplate;
        let line = "        random.seed(1)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.starts_with("        #"));
    }

    // ── CryptoMd5PasswordHashTemplate ─────────────────────────────────────────

    #[test]
    fn test_md5_password_js() {
        let t = CryptoMd5PasswordHashTemplate;
        let line = "    const hash = md5(password);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("bcrypt.hash(password, 12)"));
        assert!(!result.contains("md5("));
    }

    #[test]
    fn test_md5_password_python() {
        let t = CryptoMd5PasswordHashTemplate;
        let line = "    hashed = hashlib.md5(password.encode())";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("bcrypt.hashpw("));
        assert!(result.contains("bcrypt.gensalt(12)"));
    }

    #[test]
    fn test_md5_password_go() {
        let t = CryptoMd5PasswordHashTemplate;
        let line = "\thash := md5.Sum([]byte(password))";
        let result = t.generate_patch(line, go()).unwrap();
        assert!(result.contains("bcrypt.GenerateFromPassword("));
    }

    #[test]
    fn test_md5_no_match() {
        let t = CryptoMd5PasswordHashTemplate;
        assert!(t
            .generate_patch("    const x = sha256(data);", js())
            .is_none());
    }

    // ── CryptoJwtNoneAlgorithmTemplate ────────────────────────────────────────

    #[test]
    fn test_jwt_none_algorithm_js_single_quote() {
        let t = CryptoJwtNoneAlgorithmTemplate;
        let line = "    jwt.verify(token, secret, { algorithms: ['none'] });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("'HS256'"));
        assert!(!result.contains("'none'"));
    }

    #[test]
    fn test_jwt_none_algorithm_js_double_quote() {
        let t = CryptoJwtNoneAlgorithmTemplate;
        let line = "    jwt.verify(token, secret, { algorithms: [\"none\"] });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("\"HS256\""));
    }

    #[test]
    fn test_jwt_none_algorithm_python() {
        let t = CryptoJwtNoneAlgorithmTemplate;
        let line = "    payload = jwt.decode(token, options={'verify_signature': False}, algorithms=['none'])";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("'HS256'"));
    }

    #[test]
    fn test_jwt_none_no_match() {
        let t = CryptoJwtNoneAlgorithmTemplate;
        // 'none' not in a JWT context
        assert!(t.generate_patch("    const x = 'none';", js()).is_none());
    }

    #[test]
    fn test_jwt_none_wrong_lang() {
        let t = CryptoJwtNoneAlgorithmTemplate;
        assert!(t.generate_patch("algorithms: ['none']", go()).is_none());
    }

    // ── CryptoJwtWeakAlgorithmTemplate ────────────────────────────────────────

    #[test]
    fn test_jwt_weak_hs1_replaced() {
        let t = CryptoJwtWeakAlgorithmTemplate;
        let line = "    const token = jwt.sign(payload, secret, { algorithm: 'HS1' });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("'HS256'"));
        assert!(!result.contains("'HS1'"));
    }

    #[test]
    fn test_jwt_weak_rs1_replaced() {
        let t = CryptoJwtWeakAlgorithmTemplate;
        let line = "    jwt.sign(payload, key, { algorithm: 'RS1' });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("'RS256'"));
    }

    #[test]
    fn test_jwt_weak_double_quote() {
        let t = CryptoJwtWeakAlgorithmTemplate;
        let line = "    jwt.sign(payload, secret, { algorithm: \"HS1\" });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("\"HS256\""));
    }

    #[test]
    fn test_jwt_weak_hs256_not_replaced() {
        let t = CryptoJwtWeakAlgorithmTemplate;
        assert!(t
            .generate_patch(
                "    jwt.sign(payload, secret, { algorithm: 'HS256' });",
                js()
            )
            .is_none());
    }

    #[test]
    fn test_jwt_weak_wrong_lang() {
        let t = CryptoJwtWeakAlgorithmTemplate;
        assert!(t.generate_patch("algorithm: 'HS1'", go()).is_none());
    }

    // ── CryptoHardcodedSaltTemplate ───────────────────────────────────────────

    #[test]
    fn test_hardcoded_salt_bytes_single_quote() {
        let t = CryptoHardcodedSaltTemplate;
        let line = "    hashed = bcrypt.hashpw(password, b'$2b$12$hardcodedsaltvalue')";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("bcrypt.gensalt(12)"));
        assert!(!result.contains("b'$2b$12$hardcodedsaltvalue'"));
    }

    #[test]
    fn test_hardcoded_salt_bytes_double_quote() {
        let t = CryptoHardcodedSaltTemplate;
        let line = "    hashed = bcrypt.hashpw(pwd, b\"$2b$12$fixedsalt\")";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("bcrypt.gensalt(12)"));
    }

    #[test]
    fn test_hardcoded_salt_gensalt_not_replaced() {
        let t = CryptoHardcodedSaltTemplate;
        // Already using gensalt — no match
        assert!(t
            .generate_patch("    bcrypt.hashpw(pwd, bcrypt.gensalt(12))", py())
            .is_none());
    }

    #[test]
    fn test_hardcoded_salt_wrong_lang() {
        let t = CryptoHardcodedSaltTemplate;
        assert!(t
            .generate_patch("bcrypt.hashpw(pwd, b'salt')", js())
            .is_none());
    }

    // ── Registry integration ──────────────────────────────────────────────────

    #[test]
    fn test_registry_pbkdf2_by_cwe() {
        let reg = TemplateRegistry::default();
        let t = reg.lookup("unknown", Some("CWE-916"));
        assert!(t.is_some());
        // CWE-916 maps to PBKDF2 (first registered)
        assert_eq!(t.unwrap().name(), "CryptoPbkdf2LowIterations");
    }

    #[test]
    fn test_registry_rsa_by_rule_id() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("js-rsa-key-too-short", None).is_some());
        assert_eq!(
            reg.lookup("js-rsa-key-too-short", None).unwrap().name(),
            "CryptoRsaKeyTooShort"
        );
    }

    #[test]
    fn test_registry_jwt_none_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-347")).is_some());
    }

    #[test]
    fn test_registry_hardcoded_salt_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-760")).is_some());
    }

    #[test]
    fn test_registry_insecure_seed_by_rule() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("py-random-seed-fixed", None).is_some());
    }
}

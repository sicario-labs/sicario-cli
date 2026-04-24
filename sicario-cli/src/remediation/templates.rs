//! Template-based vulnerability fix engine
//!
//! Provides rule-based code transformations for 9 vulnerability types as a
//! fallback when the LLM is unavailable or returns invalid code.
//!
//! Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7

use std::path::Path;

use crate::engine::Vulnerability;

// ── Vulnerability classification ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnType {
    SqlInjection,       // CWE-89
    Xss,                // CWE-79
    CommandInjection,   // CWE-78
    PathTraversal,      // CWE-22
    Ssrf,               // CWE-918
    InsecureDeserial,   // CWE-502
    HardcodedCreds,     // CWE-798
    OpenRedirect,       // CWE-601
    Xxe,                // CWE-611
    Unknown,
}

/// Classify a vulnerability by its `cwe_id` and `rule_id`.
pub fn classify_vulnerability(vuln: &Vulnerability) -> VulnType {
    // Check CWE first (most reliable)
    if let Some(cwe) = &vuln.cwe_id {
        let cwe_lower = cwe.to_lowercase();
        if cwe_lower.contains("89") {
            return VulnType::SqlInjection;
        }
        if cwe_lower.contains("79") {
            return VulnType::Xss;
        }
        if cwe_lower.contains("78") {
            return VulnType::CommandInjection;
        }
        if cwe_lower.contains("22") {
            return VulnType::PathTraversal;
        }
        if cwe_lower.contains("918") {
            return VulnType::Ssrf;
        }
        if cwe_lower.contains("502") {
            return VulnType::InsecureDeserial;
        }
        if cwe_lower.contains("798") {
            return VulnType::HardcodedCreds;
        }
        if cwe_lower.contains("601") {
            return VulnType::OpenRedirect;
        }
        if cwe_lower.contains("611") {
            return VulnType::Xxe;
        }
    }

    // Fall back to rule_id pattern matching
    let rule = vuln.rule_id.to_lowercase();
    if rule.contains("sql") && (rule.contains("inject") || rule.contains("sqli")) {
        return VulnType::SqlInjection;
    }
    if rule.contains("xss") || rule.contains("cross-site") {
        return VulnType::Xss;
    }
    if rule.contains("command") && rule.contains("inject")
        || rule.contains("cmd-inject")
        || rule.contains("os-command")
    {
        return VulnType::CommandInjection;
    }
    if rule.contains("path-traversal") || rule.contains("directory-traversal") {
        return VulnType::PathTraversal;
    }
    if rule.contains("ssrf") || rule.contains("server-side-request") {
        return VulnType::Ssrf;
    }
    if rule.contains("deserial") || rule.contains("pickle") || rule.contains("unsafe-yaml") {
        return VulnType::InsecureDeserial;
    }
    if rule.contains("hardcoded") || rule.contains("hard-coded") || rule.contains("secret-in-source") {
        return VulnType::HardcodedCreds;
    }
    if rule.contains("redirect") || rule.contains("open-redirect") {
        return VulnType::OpenRedirect;
    }
    if rule.contains("xxe") || rule.contains("xml-external") {
        return VulnType::Xxe;
    }

    VulnType::Unknown
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Apply a template-based fix for the given vulnerability.
///
/// Dispatches to the appropriate template handler based on vulnerability
/// classification. Per Requirement 3.7, the output MUST differ from the
/// original for every supported vulnerability type.
pub fn apply_template_fix(original: &str, vuln: &Vulnerability) -> String {
    let vuln_type = classify_vulnerability(vuln);

    match vuln_type {
        VulnType::SqlInjection => apply_sql_injection_template(original, vuln),
        VulnType::Xss => apply_xss_template(original, vuln),
        VulnType::CommandInjection => apply_command_injection_template(original, vuln),
        VulnType::PathTraversal => apply_path_traversal_template(original, vuln),
        VulnType::Ssrf => apply_ssrf_template(original, vuln),
        VulnType::InsecureDeserial => apply_insecure_deserialization_template(original, vuln),
        VulnType::HardcodedCreds => apply_hardcoded_creds_template(original, vuln),
        VulnType::OpenRedirect => apply_open_redirect_template(original, vuln),
        VulnType::Xxe => apply_xxe_template(original, vuln),
        VulnType::Unknown => apply_unknown_template(original, vuln),
    }
}

// ── Existing template fix implementations ─────────────────────────────────────

/// Apply SQL injection template fix: replace string concatenation/interpolation
/// with parameterized queries. Supports Python, JavaScript, Java, Go, Rust.
fn apply_sql_injection_template(original: &str, vuln: &Vulnerability) -> String {
    let lang = detect_language_name(&vuln.file_path).to_lowercase();
    let target_line = vuln.line.saturating_sub(1);
    let lines: Vec<&str> = original.lines().collect();

    if target_line >= lines.len() {
        return apply_comment_warning(
            original,
            vuln,
            "SQL injection detected — use parameterized queries",
        );
    }

    let vuln_line = lines[target_line];

    let replacement = match lang.as_str() {
        "python"
            if vuln_line.contains('+')
                || vuln_line.contains("f\"")
                || vuln_line.contains("f'")
                || vuln_line.contains('%') =>
        {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}# SICARIO FIX: Use parameterized query to prevent SQL injection\n\
                 {indent}cursor.execute(\"SELECT * FROM table WHERE col = %s\", (user_input,))",
            )
        }
        "javascript" | "typescript" if vuln_line.contains('+') || vuln_line.contains('`') => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use parameterized query to prevent SQL injection\n\
                 {indent}const result = await db.query(\"SELECT * FROM table WHERE col = $1\", [userInput]);",
            )
        }
        "java" if vuln_line.contains('+') || vuln_line.contains("concat") => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use PreparedStatement to prevent SQL injection\n\
                 {indent}PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM table WHERE col = ?\");\n\
                 {indent}stmt.setString(1, userInput);",
            )
        }
        "go" if vuln_line.contains('+')
            || vuln_line.contains("Sprintf")
            || vuln_line.contains("fmt.") =>
        {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use parameterized query to prevent SQL injection\n\
                 {indent}rows, err := db.Query(\"SELECT * FROM table WHERE col = $1\", userInput)",
            )
        }
        "rust" if vuln_line.contains("format!") || vuln_line.contains('+') => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use parameterized query to prevent SQL injection\n\
                 {indent}sqlx::query(\"SELECT * FROM table WHERE col = $1\").bind(&user_input)",
            )
        }
        _ => {
            return apply_comment_warning(
                original,
                vuln,
                "SQL injection detected — use parameterized queries",
            );
        }
    };

    replace_line(original, target_line, &replacement)
}

/// Apply XSS template fix: replace dangerous HTML output with context-appropriate
/// encoding/escaping.
fn apply_xss_template(original: &str, vuln: &Vulnerability) -> String {
    let lang = detect_language_name(&vuln.file_path).to_lowercase();
    let target_line = vuln.line.saturating_sub(1);
    let lines: Vec<&str> = original.lines().collect();

    if target_line >= lines.len() {
        return apply_comment_warning(original, vuln, "XSS detected — apply output encoding");
    }

    let vuln_line = lines[target_line];

    let replacement = match lang.as_str() {
        "python" => {
            let indent = get_indent(vuln_line);
            if vuln_line.contains("render_template_string") || vuln_line.contains("Markup") {
                format!(
                    "{indent}# SICARIO FIX: Escape user input to prevent XSS\n\
                     {indent}from markupsafe import escape\n\
                     {indent}safe_output = escape(user_input)",
                )
            } else {
                format!(
                    "{indent}# SICARIO FIX: Escape user input to prevent XSS\n\
                     {indent}import html\n\
                     {indent}safe_output = html.escape(user_input)",
                )
            }
        }
        "javascript" | "typescript" => {
            let indent = get_indent(vuln_line);
            if vuln_line.contains("innerHTML") || vuln_line.contains("dangerouslySetInnerHTML") {
                format!(
                    "{indent}// SICARIO FIX: Use textContent instead of innerHTML to prevent XSS\n\
                     {indent}element.textContent = userInput;",
                )
            } else if vuln_line.contains("document.write") {
                format!(
                    "{indent}// SICARIO FIX: Use textContent instead of document.write to prevent XSS\n\
                     {indent}document.body.textContent = userInput;",
                )
            } else {
                format!(
                    "{indent}// SICARIO FIX: Encode output to prevent XSS\n\
                     {indent}const safeOutput = userInput.replace(/[&<>\"']/g, (c) => ({{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}})[c]);",
                )
            }
        }
        "java" => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Encode output to prevent XSS\n\
                 {indent}String safeOutput = org.owasp.encoder.Encode.forHtml(userInput);",
            )
        }
        _ => {
            return apply_comment_warning(original, vuln, "XSS detected — apply output encoding");
        }
    };

    replace_line(original, target_line, &replacement)
}

/// Apply command injection template fix: replace shell invocations with
/// allowlist-validated arguments.
fn apply_command_injection_template(original: &str, vuln: &Vulnerability) -> String {
    let lang = detect_language_name(&vuln.file_path).to_lowercase();
    let target_line = vuln.line.saturating_sub(1);
    let lines: Vec<&str> = original.lines().collect();

    if target_line >= lines.len() {
        return apply_comment_warning(
            original,
            vuln,
            "Command injection detected — use allowlist validation",
        );
    }

    let vuln_line = lines[target_line];

    let replacement = match lang.as_str() {
        "python" => {
            let indent = get_indent(vuln_line);
            if vuln_line.contains("os.system") || vuln_line.contains("os.popen") {
                format!(
                    "{indent}# SICARIO FIX: Use subprocess with allowlist-validated args (no shell=True)\n\
                     {indent}import subprocess, shlex\n\
                     {indent}ALLOWED_COMMANDS = {{\"ls\", \"cat\", \"echo\"}}\n\
                     {indent}cmd = shlex.split(user_input)\n\
                     {indent}if cmd and cmd[0] in ALLOWED_COMMANDS:\n\
                     {indent}    subprocess.run(cmd, shell=False, check=True)",
                )
            } else {
                format!(
                    "{indent}# SICARIO FIX: Use subprocess with list args and allowlist validation\n\
                     {indent}import subprocess\n\
                     {indent}ALLOWED_COMMANDS = {{\"ls\", \"cat\", \"echo\"}}\n\
                     {indent}if command_name in ALLOWED_COMMANDS:\n\
                     {indent}    subprocess.run([command_name] + args, shell=False, check=True)",
                )
            }
        }
        "javascript" | "typescript" => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use execFile with allowlist-validated command (no shell)\n\
                 {indent}const {{ execFile }} = require('child_process');\n\
                 {indent}const ALLOWED_COMMANDS = new Set(['ls', 'cat', 'echo']);\n\
                 {indent}if (ALLOWED_COMMANDS.has(commandName)) {{\n\
                 {indent}  execFile(commandName, args, (err, stdout) => {{ /* handle */ }});\n\
                 {indent}}}",
            )
        }
        "java" => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use ProcessBuilder with allowlist-validated command\n\
                 {indent}Set<String> ALLOWED = Set.of(\"ls\", \"cat\", \"echo\");\n\
                 {indent}if (ALLOWED.contains(commandName)) {{\n\
                 {indent}    new ProcessBuilder(commandName).redirectErrorStream(true).start();\n\
                 {indent}}}",
            )
        }
        "go" => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use exec.Command with allowlist-validated command\n\
                 {indent}allowedCmds := map[string]bool{{\"ls\": true, \"cat\": true, \"echo\": true}}\n\
                 {indent}if allowedCmds[commandName] {{\n\
                 {indent}\tcmd := exec.Command(commandName, args...)\n\
                 {indent}}}",
            )
        }
        "rust" => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use Command with allowlist-validated args (no shell)\n\
                 {indent}let allowed = [\"ls\", \"cat\", \"echo\"];\n\
                 {indent}if allowed.contains(&command_name) {{\n\
                 {indent}    std::process::Command::new(command_name).args(&validated_args).output()?;\n\
                 {indent}}}",
            )
        }
        _ => {
            return apply_comment_warning(
                original,
                vuln,
                "Command injection detected — use allowlist validation",
            );
        }
    };

    replace_line(original, target_line, &replacement)
}

/// For unknown vulnerability types, insert a warning comment rather than
/// returning the original unchanged (Requirement 11.10).
fn apply_unknown_template(original: &str, vuln: &Vulnerability) -> String {
    let desc = vuln.cwe_id.as_deref().unwrap_or(&vuln.rule_id);
    apply_comment_warning(
        original,
        vuln,
        &format!(
            "Security issue detected ({}) — manual review required",
            desc
        ),
    )
}

// ── New template fix implementations (CWE-22, 918, 502, 798, 601, 611) ───────

/// Apply path traversal template fix (CWE-22): canonicalize path and validate
/// against an allowed base directory.
fn apply_path_traversal_template(original: &str, vuln: &Vulnerability) -> String {
    let lang = detect_language_name(&vuln.file_path).to_lowercase();
    let target_line = vuln.line.saturating_sub(1);
    let lines: Vec<&str> = original.lines().collect();

    if target_line >= lines.len() {
        return apply_comment_warning(
            original,
            vuln,
            "Path traversal detected — canonicalize and validate path",
        );
    }

    let vuln_line = lines[target_line];
    let indent = get_indent(vuln_line);

    let replacement = match lang.as_str() {
        "python" => {
            format!(
                "{indent}# SICARIO FIX: Canonicalize path and validate against base directory\n\
                 {indent}import os\n\
                 {indent}base_dir = os.path.realpath(ALLOWED_BASE_DIR)\n\
                 {indent}requested_path = os.path.realpath(user_input)\n\
                 {indent}if not requested_path.startswith(base_dir):\n\
                 {indent}    raise ValueError(\"Path traversal attempt blocked\")",
            )
        }
        "javascript" | "typescript" => {
            format!(
                "{indent}// SICARIO FIX: Resolve path and validate against base directory\n\
                 {indent}const path = require('path');\n\
                 {indent}const baseDir = path.resolve(ALLOWED_BASE_DIR);\n\
                 {indent}const requestedPath = path.resolve(userInput);\n\
                 {indent}if (!requestedPath.startsWith(baseDir)) {{\n\
                 {indent}  throw new Error('Path traversal attempt blocked');\n\
                 {indent}}}",
            )
        }
        "rust" => {
            format!(
                "{indent}// SICARIO FIX: Canonicalize path and validate against base directory\n\
                 {indent}let base_dir = std::fs::canonicalize(ALLOWED_BASE_DIR)?;\n\
                 {indent}let requested_path = std::fs::canonicalize(&user_input)?;\n\
                 {indent}if !requested_path.starts_with(&base_dir) {{\n\
                 {indent}    return Err(anyhow::anyhow!(\"Path traversal attempt blocked\"));\n\
                 {indent}}}",
            )
        }
        "go" => {
            format!(
                "{indent}// SICARIO FIX: Clean path and validate against base directory\n\
                 {indent}cleanPath := filepath.Clean(userInput)\n\
                 {indent}absPath, err := filepath.Abs(cleanPath)\n\
                 {indent}if err != nil || !strings.HasPrefix(absPath, allowedBaseDir) {{\n\
                 {indent}\treturn fmt.Errorf(\"path traversal attempt blocked\")\n\
                 {indent}}}",
            )
        }
        "java" => {
            format!(
                "{indent}// SICARIO FIX: Normalize path and validate against base directory\n\
                 {indent}Path basePath = Paths.get(ALLOWED_BASE_DIR).normalize().toRealPath();\n\
                 {indent}Path requestedPath = Paths.get(userInput).normalize().toRealPath();\n\
                 {indent}if (!requestedPath.startsWith(basePath)) {{\n\
                 {indent}    throw new SecurityException(\"Path traversal attempt blocked\");\n\
                 {indent}}}",
            )
        }
        _ => {
            return apply_comment_warning(
                original,
                vuln,
                "Path traversal detected — canonicalize and validate path",
            );
        }
    };

    replace_line(original, target_line, &replacement)
}

/// Apply SSRF template fix (CWE-918): validate URL host against an allowlist.
fn apply_ssrf_template(original: &str, vuln: &Vulnerability) -> String {
    let lang = detect_language_name(&vuln.file_path).to_lowercase();
    let target_line = vuln.line.saturating_sub(1);
    let lines: Vec<&str> = original.lines().collect();

    if target_line >= lines.len() {
        return apply_comment_warning(
            original,
            vuln,
            "SSRF detected — validate URL against host allowlist",
        );
    }

    let vuln_line = lines[target_line];
    let indent = get_indent(vuln_line);

    let replacement = match lang.as_str() {
        "python" => {
            format!(
                "{indent}# SICARIO FIX: Validate URL host against allowlist to prevent SSRF\n\
                 {indent}from urllib.parse import urlparse\n\
                 {indent}ALLOWED_HOSTS = {{\"api.example.com\", \"cdn.example.com\"}}\n\
                 {indent}parsed = urlparse(user_url)\n\
                 {indent}if parsed.hostname not in ALLOWED_HOSTS:\n\
                 {indent}    raise ValueError(\"SSRF attempt blocked: host not in allowlist\")",
            )
        }
        "javascript" | "typescript" => {
            format!(
                "{indent}// SICARIO FIX: Validate URL host against allowlist to prevent SSRF\n\
                 {indent}const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com']);\n\
                 {indent}const parsedUrl = new URL(userUrl);\n\
                 {indent}if (!ALLOWED_HOSTS.has(parsedUrl.hostname)) {{\n\
                 {indent}  throw new Error('SSRF attempt blocked: host not in allowlist');\n\
                 {indent}}}",
            )
        }
        "go" => {
            format!(
                "{indent}// SICARIO FIX: Validate URL host against allowlist to prevent SSRF\n\
                 {indent}allowedHosts := map[string]bool{{\"api.example.com\": true, \"cdn.example.com\": true}}\n\
                 {indent}parsedURL, err := url.Parse(userURL)\n\
                 {indent}if err != nil || !allowedHosts[parsedURL.Hostname()] {{\n\
                 {indent}\treturn fmt.Errorf(\"SSRF attempt blocked: host not in allowlist\")\n\
                 {indent}}}",
            )
        }
        "java" => {
            format!(
                "{indent}// SICARIO FIX: Validate URL host against allowlist to prevent SSRF\n\
                 {indent}Set<String> ALLOWED_HOSTS = Set.of(\"api.example.com\", \"cdn.example.com\");\n\
                 {indent}URI parsedUri = new URI(userUrl);\n\
                 {indent}if (!ALLOWED_HOSTS.contains(parsedUri.getHost())) {{\n\
                 {indent}    throw new SecurityException(\"SSRF attempt blocked: host not in allowlist\");\n\
                 {indent}}}",
            )
        }
        _ => {
            return apply_comment_warning(
                original,
                vuln,
                "SSRF detected — validate URL against host allowlist",
            );
        }
    };

    replace_line(original, target_line, &replacement)
}

/// Apply insecure deserialization template fix (CWE-502): replace unsafe
/// deserialization with safe alternatives.
fn apply_insecure_deserialization_template(original: &str, vuln: &Vulnerability) -> String {
    let lang = detect_language_name(&vuln.file_path).to_lowercase();
    let target_line = vuln.line.saturating_sub(1);
    let lines: Vec<&str> = original.lines().collect();

    if target_line >= lines.len() {
        return apply_comment_warning(
            original,
            vuln,
            "Insecure deserialization detected — use safe alternatives",
        );
    }

    let vuln_line = lines[target_line];
    let indent = get_indent(vuln_line);

    let replacement = match lang.as_str() {
        "python" => {
            if vuln_line.contains("yaml.load") {
                format!(
                    "{indent}# SICARIO FIX: Use yaml.safe_load() instead of yaml.load()\n\
                     {indent}import yaml\n\
                     {indent}data = yaml.safe_load(user_input)",
                )
            } else if vuln_line.contains("pickle.loads") || vuln_line.contains("pickle.load") {
                format!(
                    "{indent}# SICARIO FIX: Use json.loads() instead of pickle.loads()\n\
                     {indent}import json\n\
                     {indent}data = json.loads(user_input)",
                )
            } else {
                format!(
                    "{indent}# SICARIO FIX: Replace unsafe deserialization with safe alternative\n\
                     {indent}import json\n\
                     {indent}data = json.loads(user_input)",
                )
            }
        }
        "javascript" | "typescript" => {
            format!(
                "{indent}// SICARIO FIX: Validate deserialized data with schema validation\n\
                 {indent}const parsed = JSON.parse(userInput);\n\
                 {indent}// TODO: Add JSON schema validation for parsed data\n\
                 {indent}if (typeof parsed !== 'object' || parsed === null) {{\n\
                 {indent}  throw new Error('Invalid deserialized data');\n\
                 {indent}}}",
            )
        }
        "java" => {
            format!(
                "{indent}// SICARIO FIX: Use allowlist-based deserialization instead of ObjectInputStream\n\
                 {indent}ObjectInputStream ois = new ObjectInputStream(inputStream) {{\n\
                 {indent}    @Override\n\
                 {indent}    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {{\n\
                 {indent}        Set<String> ALLOWED = Set.of(\"java.lang.String\", \"java.lang.Integer\");\n\
                 {indent}        if (!ALLOWED.contains(desc.getName())) {{\n\
                 {indent}            throw new SecurityException(\"Deserialization of \" + desc.getName() + \" blocked\");\n\
                 {indent}        }}\n\
                 {indent}        return super.resolveClass(desc);\n\
                 {indent}    }}\n\
                 {indent}}};",
            )
        }
        _ => {
            return apply_comment_warning(
                original,
                vuln,
                "Insecure deserialization detected — use safe alternatives",
            );
        }
    };

    replace_line(original, target_line, &replacement)
}

/// Apply hardcoded credentials template fix (CWE-798): replace hardcoded
/// values with environment variable lookups.
fn apply_hardcoded_creds_template(original: &str, vuln: &Vulnerability) -> String {
    let lang = detect_language_name(&vuln.file_path).to_lowercase();
    let target_line = vuln.line.saturating_sub(1);
    let lines: Vec<&str> = original.lines().collect();

    if target_line >= lines.len() {
        return apply_comment_warning(
            original,
            vuln,
            "Hardcoded credentials detected — use environment variables",
        );
    }

    let vuln_line = lines[target_line];
    let indent = get_indent(vuln_line);

    let replacement = match lang.as_str() {
        "python" => {
            format!(
                "{indent}# SICARIO FIX: Read secret from environment variable instead of hardcoding\n\
                 {indent}import os\n\
                 {indent}secret = os.environ.get(\"SECRET_NAME\")",
            )
        }
        "javascript" | "typescript" => {
            format!(
                "{indent}// SICARIO FIX: Read secret from environment variable instead of hardcoding\n\
                 {indent}const secret = process.env.SECRET_NAME;",
            )
        }
        "rust" => {
            format!(
                "{indent}// SICARIO FIX: Read secret from environment variable instead of hardcoding\n\
                 {indent}let secret = std::env::var(\"SECRET_NAME\").expect(\"SECRET_NAME must be set\");",
            )
        }
        "go" => {
            format!(
                "{indent}// SICARIO FIX: Read secret from environment variable instead of hardcoding\n\
                 {indent}secret := os.Getenv(\"SECRET_NAME\")",
            )
        }
        "java" => {
            format!(
                "{indent}// SICARIO FIX: Read secret from environment variable instead of hardcoding\n\
                 {indent}String secret = System.getenv(\"SECRET_NAME\");",
            )
        }
        _ => {
            return apply_comment_warning(
                original,
                vuln,
                "Hardcoded credentials detected — use environment variables",
            );
        }
    };

    replace_line(original, target_line, &replacement)
}

/// Apply open redirect template fix (CWE-601): validate redirect URL against
/// an allowlist of permitted domains.
fn apply_open_redirect_template(original: &str, vuln: &Vulnerability) -> String {
    let lang = detect_language_name(&vuln.file_path).to_lowercase();
    let target_line = vuln.line.saturating_sub(1);
    let lines: Vec<&str> = original.lines().collect();

    if target_line >= lines.len() {
        return apply_comment_warning(
            original,
            vuln,
            "Open redirect detected — validate redirect URL against allowlist",
        );
    }

    let vuln_line = lines[target_line];
    let indent = get_indent(vuln_line);

    let replacement = match lang.as_str() {
        "python" => {
            format!(
                "{indent}# SICARIO FIX: Validate redirect URL against domain allowlist\n\
                 {indent}from urllib.parse import urlparse\n\
                 {indent}ALLOWED_DOMAINS = {{\"example.com\", \"app.example.com\"}}\n\
                 {indent}parsed = urlparse(redirect_url)\n\
                 {indent}if parsed.hostname not in ALLOWED_DOMAINS:\n\
                 {indent}    redirect_url = \"/\"",
            )
        }
        "javascript" | "typescript" => {
            format!(
                "{indent}// SICARIO FIX: Validate redirect URL against domain allowlist\n\
                 {indent}const ALLOWED_DOMAINS = new Set(['example.com', 'app.example.com']);\n\
                 {indent}try {{\n\
                 {indent}  const parsedUrl = new URL(redirectUrl, 'https://example.com');\n\
                 {indent}  if (!ALLOWED_DOMAINS.has(parsedUrl.hostname)) {{\n\
                 {indent}    redirectUrl = '/';\n\
                 {indent}  }}\n\
                 {indent}}} catch (e) {{\n\
                 {indent}  redirectUrl = '/';\n\
                 {indent}}}",
            )
        }
        "go" => {
            format!(
                "{indent}// SICARIO FIX: Validate redirect URL against domain allowlist\n\
                 {indent}allowedDomains := map[string]bool{{\"example.com\": true, \"app.example.com\": true}}\n\
                 {indent}parsedURL, err := url.Parse(redirectURL)\n\
                 {indent}if err != nil || !allowedDomains[parsedURL.Hostname()] {{\n\
                 {indent}\tredirectURL = \"/\"\n\
                 {indent}}}",
            )
        }
        "java" => {
            format!(
                "{indent}// SICARIO FIX: Validate redirect URL against domain allowlist\n\
                 {indent}Set<String> ALLOWED_DOMAINS = Set.of(\"example.com\", \"app.example.com\");\n\
                 {indent}try {{\n\
                 {indent}    URI parsedUri = new URI(redirectUrl);\n\
                 {indent}    if (!ALLOWED_DOMAINS.contains(parsedUri.getHost())) {{\n\
                 {indent}        redirectUrl = \"/\";\n\
                 {indent}    }}\n\
                 {indent}}} catch (URISyntaxException e) {{\n\
                 {indent}    redirectUrl = \"/\";\n\
                 {indent}}}",
            )
        }
        _ => {
            return apply_comment_warning(
                original,
                vuln,
                "Open redirect detected — validate redirect URL against allowlist",
            );
        }
    };

    replace_line(original, target_line, &replacement)
}

/// Apply XXE template fix (CWE-611): disable external entity processing in
/// XML parser configuration.
fn apply_xxe_template(original: &str, vuln: &Vulnerability) -> String {
    let lang = detect_language_name(&vuln.file_path).to_lowercase();
    let target_line = vuln.line.saturating_sub(1);
    let lines: Vec<&str> = original.lines().collect();

    if target_line >= lines.len() {
        return apply_comment_warning(
            original,
            vuln,
            "XXE detected — disable external entity processing",
        );
    }

    let vuln_line = lines[target_line];
    let indent = get_indent(vuln_line);

    let replacement = match lang.as_str() {
        "python" => {
            format!(
                "{indent}# SICARIO FIX: Use defusedxml to prevent XXE attacks\n\
                 {indent}import defusedxml.ElementTree as ET\n\
                 {indent}tree = ET.parse(xml_input)",
            )
        }
        "javascript" | "typescript" => {
            format!(
                "{indent}// SICARIO FIX: Disable external entities in XML parser\n\
                 {indent}const {{ parseXml }} = require('libxmljs');\n\
                 {indent}const doc = parseXml(xmlInput, {{ noent: false, nonet: true }});",
            )
        }
        "java" => {
            format!(
                "{indent}// SICARIO FIX: Disable external entity processing to prevent XXE\n\
                 {indent}import javax.xml.XMLConstants;\n\
                 {indent}DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n\
                 {indent}dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\n\
                 {indent}dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n\
                 {indent}dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n\
                 {indent}dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);",
            )
        }
        _ => {
            return apply_comment_warning(
                original,
                vuln,
                "XXE detected — disable external entity processing",
            );
        }
    };

    replace_line(original, target_line, &replacement)
}

// ── Helper functions ──────────────────────────────────────────────────────────

/// Insert a warning comment above the vulnerable line. This ensures the output
/// always differs from the original (Requirement 3.7 / 11.10).
fn apply_comment_warning(original: &str, vuln: &Vulnerability, message: &str) -> String {
    let lang = detect_language_name(&vuln.file_path).to_lowercase();
    let target_line = vuln.line.saturating_sub(1);
    let lines: Vec<&str> = original.lines().collect();

    if lines.is_empty() {
        let comment = format_comment(&lang, message);
        return format!("{}\n{}", comment, original);
    }

    let idx = target_line.min(lines.len() - 1);
    let indent = get_indent(lines[idx]);
    let comment = format!("{}{}", indent, format_comment(&lang, message));

    let mut result: Vec<String> = Vec::with_capacity(lines.len() + 1);
    for (i, line) in lines.iter().enumerate() {
        if i == idx {
            result.push(comment.clone());
        }
        result.push(line.to_string());
    }
    result.join("\n")
}

/// Format a comment in the appropriate style for the language.
fn format_comment(lang: &str, message: &str) -> String {
    match lang {
        "python" => format!("# SICARIO WARNING: {}", message),
        _ => format!("// SICARIO WARNING: {}", message),
    }
}

/// Get the leading whitespace of a line.
fn get_indent(line: &str) -> String {
    line.chars().take_while(|c| c.is_whitespace()).collect()
}

/// Replace a single line in the source with a (possibly multi-line) replacement.
fn replace_line(original: &str, line_idx: usize, replacement: &str) -> String {
    let lines: Vec<&str> = original.lines().collect();
    let mut result: Vec<String> = Vec::with_capacity(lines.len());
    for (i, line) in lines.iter().enumerate() {
        if i == line_idx {
            result.push(replacement.to_string());
        } else {
            result.push(line.to_string());
        }
    }
    // Preserve trailing newline if original had one
    let mut out = result.join("\n");
    if original.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Detect the human-readable language name from a file path extension.
///
/// This is a local copy used by templates. The canonical version lives in
/// `remediation_engine.rs` as `pub(crate) detect_language_name()`.
fn detect_language_name(path: &Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("js") => "JavaScript".to_string(),
        Some("ts") | Some("tsx") => "TypeScript".to_string(),
        Some("py") => "Python".to_string(),
        Some("rs") => "Rust".to_string(),
        Some("go") => "Go".to_string(),
        Some("java") => "Java".to_string(),
        Some(ext) => ext.to_string(),
        None => "Unknown".to_string(),
    }
}

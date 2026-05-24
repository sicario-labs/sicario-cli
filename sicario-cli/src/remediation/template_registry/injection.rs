//! Injection vulnerability patch templates.

use super::helpers::*;
use super::PatchTemplate;
use crate::parser::Language;

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

// â”€â”€ 16. InjectOsExecTemplate (CWE-78) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
pub struct InjectChildProcessShellTrueTemplate;

impl PatchTemplate for InjectChildProcessShellTrueTemplate {
    fn name(&self) -> &'static str {
        "InjectChildProcessShellTrue"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("shell: true") && !line.contains("shell:true") {
            return None;
        }
        // Only fire on spawn/execFile/exec calls
        let lower = line.to_lowercase();
        if !lower.contains("spawn") && !lower.contains("execfile") && !lower.contains("exec(") {
            return None;
        }
        let fixed = line
            .replace(", shell: true", "")
            .replace(",shell: true", "")
            .replace(", shell:true", "")
            .replace(",shell:true", "")
            .replace("{ shell: true }", "{}")
            .replace("{ shell: true, ", "{ ")
            .replace("{ shell:true }", "{}")
            .replace("{ shell:true, ", "{ ");
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 35. InjectPythonSubprocessShellTemplate (CWE-78) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `shell=True` with `shell=False` in Python subprocess calls.
pub struct InjectPythonSubprocessShellTemplate;

impl PatchTemplate for InjectPythonSubprocessShellTemplate {
    fn name(&self) -> &'static str {
        "InjectPythonSubprocessShell"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }
        if !line.contains("shell=True") && !line.contains("shell = True") {
            return None;
        }
        let lower = line.to_lowercase();
        if !lower.contains("subprocess.") {
            return None;
        }
        let fixed = line
            .replace("shell=True", "shell=False")
            .replace("shell = True", "shell = False");
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 36. OsSystemInjectionTemplate (CWE-78) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `os.system(user_input)` with `subprocess.run()` + allowlist.
///
/// Catches Python command-injection via `os.system(...)` and `os.popen(...)`
/// when the argument contains string concatenation or user-controlled variables.
pub struct OsSystemInjectionTemplate;

impl PatchTemplate for OsSystemInjectionTemplate {
    fn name(&self) -> &'static str {
        "OsSystemInjection"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }
        let lower = line.to_lowercase();
        if !lower.contains("os.system(") && !lower.contains("os.popen(") {
            return None;
        }
        // Must reference user input directly
        if !line.contains(" + ") && !line.contains("f\"") && !line.contains("f'") {
            return None;
        }
        let indent = get_indent(line);
        let fix = format!(
            "{indent}# SICARIO FIX: Use subprocess with allowlist-validated args (no shell)\n\
             {indent}import subprocess, shlex\n\
             {indent}ALLOWED_COMMANDS = {{\"ls\", \"cat\", \"echo\"}}\n\
             {indent}cmd = shlex.split(user_input)\n\
             {indent}if cmd and cmd[0] in ALLOWED_COMMANDS:\n\
             {indent}    subprocess.run(cmd, shell=False, check=True)"
        );
        if fix == line {
            return None;
        }
        Some(fix)
    }
}

// â”€â”€ 37. InjectSstiTemplate (CWE-94) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Wraps `render_template_string(user_input)` with `escape()`.
pub struct InjectSstiTemplate;

impl PatchTemplate for InjectSstiTemplate {
    fn name(&self) -> &'static str {
        "InjectSsti"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }
        if !line.contains("render_template_string(") {
            return None;
        }
        // Extract the argument and wrap it
        if let Some(pos) = line.find("render_template_string(") {
            let after = &line[pos + "render_template_string(".len()..];
            if let Some(close) = find_matching_paren(after) {
                let arg = &after[..close];
                let before = &line[..pos + "render_template_string(".len()];
                let rest = &after[close..];
                // Don't double-wrap
                if arg.trim_start().starts_with("escape(") {
                    return None;
                }
                return Some(format!("{before}escape({arg}){rest}"));
            }
        }
        None
    }
}

// â”€â”€ 37. InjectLdapTemplate (CWE-90) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Wraps user-controlled variables in LDAP filter strings with an escape helper.
pub struct InjectLdapTemplate;

impl PatchTemplate for InjectLdapTemplate {
    fn name(&self) -> &'static str {
        "InjectLdap"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("ldap") {
            return None;
        }
        // Must contain user input concatenation
        if !line.contains("req.body.")
            && !line.contains("req.query.")
            && !line.contains("req.params.")
            && !line.contains("user_input")
            && !line.contains("userInput")
        {
            return None;
        }

        match lang {
            Language::JavaScript | Language::TypeScript => {
                // wrap_nosql_input handles full `req.body.field` / `req.query.field` identifiers
                let fixed = wrap_nosql_input(line, "req.body.");
                let fixed = wrap_nosql_input(&fixed, "req.query.");
                let fixed = wrap_nosql_input(&fixed, "req.params.");
                // Replace the String() wrapper with ldap.escape()
                let fixed = fixed
                    .replace("String(req.body.", "ldap.escape(req.body.")
                    .replace("String(req.query.", "ldap.escape(req.query.")
                    .replace("String(req.params.", "ldap.escape(req.params.");
                // Also handle bare userInput
                let fixed =
                    if fixed.contains("userInput") && !fixed.contains("ldap.escape(userInput)") {
                        fixed.replace("userInput", "ldap.escape(userInput)")
                    } else {
                        fixed
                    };
                if fixed == line {
                    return None;
                }
                Some(fixed)
            }
            Language::Python => {
                let fixed = if line.contains("user_input")
                    && !line.contains("escape_filter_chars(user_input)")
                {
                    line.replace(
                        "user_input",
                        "ldap3.utils.conv.escape_filter_chars(user_input)",
                    )
                } else {
                    line.to_string()
                };
                if fixed == line {
                    return None;
                }
                Some(fixed)
            }
            _ => None,
        }
    }
}

// â”€â”€ 38. InjectXpathTemplate (CWE-643) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces user-controlled XPath string concatenation with a comment nudge.
///
/// Full parameterized XPath rewrite is context-dependent (varies by library),
/// so we insert a targeted comment on the vulnerable line.
pub struct InjectXpathTemplate;

impl PatchTemplate for InjectXpathTemplate {
    fn name(&self) -> &'static str {
        "InjectXpath"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("xpath") {
            return None;
        }
        // Must contain user input
        if !line.contains("req.body.")
            && !line.contains("req.query.")
            && !line.contains("user_input")
            && !line.contains("userInput")
        {
            return None;
        }
        // Must be a string concatenation or f-string
        if !line.contains(" + ")
            && !line.contains("f\"")
            && !line.contains("f'")
            && !line.contains('`')
        {
            return None;
        }

        let indent = get_indent(line);
        let comment = match lang {
            Language::Python => format!("{indent}# SICARIO FIX: use parameterized XPath â€” avoid string concatenation with user input"),
            _ => format!("{indent}// SICARIO FIX: use parameterized XPath â€” avoid string concatenation with user input"),
        };
        Some(format!("{comment}\n{line}"))
    }
}

// â”€â”€ Sprint 2 shared helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Inject a key-value pair into the first object literal after `marker` in `line`.
///
/// e.g. `inject_into_object("cookie: { secure: true }", "cookie:", "httpOnly: true")`
/// â†’ `"cookie: { httpOnly: true, secure: true }"`
#[cfg(test)]
mod injection_tests {
    use crate::remediation::template_registry::*;

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

    // â”€â”€ InjectEvalTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        // The bare `eval(` call must be gone â€” only ast.literal_eval( remains
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

    // â”€â”€ InjectOsExecTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    // â”€â”€ InjectNoSqlTypeCastTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        // Already wrapped â€” should return None
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

    // â”€â”€ ReactDangerouslySetInnerHtmlTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    // â”€â”€ IacDockerRootUserTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    // â”€â”€ Registry integration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

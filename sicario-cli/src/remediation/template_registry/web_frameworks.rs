//! Web framework (Django, Flask, TLS, SSRF, React) patch templates.

use super::helpers::*;
use super::PatchTemplate;
use crate::parser::Language;

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

// Wrap the value after `__html:` in `DOMPurify.sanitize(...)`.

// â”€â”€ Domain 7: Network & TLS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// â”€â”€ 60. TlsMinVersionTemplate (CWE-326) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces insecure TLS version strings with TLSv1.2.
pub struct TlsMinVersionTemplate;

impl PatchTemplate for TlsMinVersionTemplate {
    fn name(&self) -> &'static str {
        "TlsMinVersion"
    }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("tlsv1") && !lower.contains("minversion") {
            return None;
        }
        let fixed = line
            .replace("TLSv1_method", "TLSv1_2_method")
            .replace("TLSv1.1_method", "TLSv1_2_method")
            .replace("minVersion: 'TLSv1'", "minVersion: 'TLSv1.2'")
            .replace("minVersion: 'TLSv1.1'", "minVersion: 'TLSv1.2'")
            .replace("minVersion: \"TLSv1\"", "minVersion: \"TLSv1.2\"")
            .replace("minVersion: \"TLSv1.1\"", "minVersion: \"TLSv1.2\"")
            // Go: tls.VersionTLS10 / tls.VersionTLS11
            .replace("tls.VersionTLS10", "tls.VersionTLS12")
            .replace("tls.VersionTLS11", "tls.VersionTLS12");
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 61. TlsCertVerifyDisabledNodeTemplate (CWE-295) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Fixes disabled TLS certificate verification in Node.js.
pub struct TlsCertVerifyDisabledNodeTemplate;

impl PatchTemplate for TlsCertVerifyDisabledNodeTemplate {
    fn name(&self) -> &'static str {
        "TlsCertVerifyDisabledNode"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if line.contains("NODE_TLS_REJECT_UNAUTHORIZED") && line.contains("'0'") {
            return Some(line.replace("= '0'", "= '1'").replace("= \"0\"", "= \"1\""));
        }
        if line.contains("rejectUnauthorized: false") || line.contains("rejectUnauthorized:false") {
            return Some(
                line.replace("rejectUnauthorized: false", "rejectUnauthorized: true")
                    .replace("rejectUnauthorized:false", "rejectUnauthorized: true"),
            );
        }
        None
    }
}

// â”€â”€ 62. TlsCertVerifyDisabledGoTemplate (CWE-295) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `InsecureSkipVerify: true` with `false` in Go TLS configs.
pub struct TlsCertVerifyDisabledGoTemplate;

impl PatchTemplate for TlsCertVerifyDisabledGoTemplate {
    fn name(&self) -> &'static str {
        "TlsCertVerifyDisabledGo"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Go {
            return None;
        }
        if !line.contains("InsecureSkipVerify: true") && !line.contains("InsecureSkipVerify:true") {
            return None;
        }
        Some(
            line.replace("InsecureSkipVerify: true", "InsecureSkipVerify: false")
                .replace("InsecureSkipVerify:true", "InsecureSkipVerify: false"),
        )
    }
}

// â”€â”€ 63. SsrfHttpGetUserInputTemplate (CWE-918) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Prepends an allowlist guard before axios/requests calls with user-controlled URLs.
pub struct SsrfHttpGetUserInputTemplate;

impl PatchTemplate for SsrfHttpGetUserInputTemplate {
    fn name(&self) -> &'static str {
        "SsrfHttpGetUserInput"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        let is_http_call = lower.contains("axios.get(")
            || lower.contains("axios.post(")
            || lower.contains("requests.get(")
            || lower.contains("requests.post(")
            || lower.contains("http.get(")
            || lower.contains("http.post(");
        if !is_http_call {
            return None;
        }
        // Must use user-controlled URL
        if !line.contains("req.body.")
            && !line.contains("req.query.")
            && !line.contains("user_url")
            && !line.contains("userUrl")
            && !line.contains("url)")
        {
            return None;
        }
        if line.contains("ALLOWED_HOSTS") || line.contains("allowlist") {
            return None;
        }

        let indent = get_indent(line);
        match lang {
            Language::JavaScript | Language::TypeScript => Some(format!(
                "{indent}const _parsed = new URL(req.body.url || req.query.url);\n\
                 {indent}if (!ALLOWED_HOSTS.has(_parsed.hostname)) throw new Error('SSRF blocked');\n\
                 {line}"
            )),
            Language::Python => Some(format!(
                "{indent}from urllib.parse import urlparse as _urlparse\n\
                 {indent}_parsed = _urlparse(user_url)\n\
                 {indent}if _parsed.hostname not in ALLOWED_HOSTS: raise ValueError('SSRF blocked')\n\
                 {line}"
            )),
            _ => None,
        }
    }
}

// â”€â”€ 64. SsrfFetchUserInputTemplate (CWE-918) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Prepends an allowlist guard before `fetch(userInput)` calls.
pub struct SsrfFetchUserInputTemplate;

impl PatchTemplate for SsrfFetchUserInputTemplate {
    fn name(&self) -> &'static str {
        "SsrfFetchUserInput"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("fetch(") {
            return None;
        }
        if !line.contains("req.") && !line.contains("userInput") && !line.contains("url") {
            return None;
        }
        if line.contains("ALLOWED_HOSTS") {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}const _fetchUrl = new URL(userInput || req.query.url);\n\
             {indent}if (!ALLOWED_HOSTS.has(_fetchUrl.hostname)) throw new Error('SSRF blocked');\n\
             {line}"
        ))
    }
}

// â”€â”€ Domain 8: Django / Flask â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// â”€â”€ 65. DjangoDebugTrueTemplate (CWE-215) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `DEBUG = True` with an env-var-driven value.
pub struct DjangoDebugTrueTemplate;

impl PatchTemplate for DjangoDebugTrueTemplate {
    fn name(&self) -> &'static str {
        "DjangoDebugTrue"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }
        let trimmed = line.trim();
        if trimmed != "DEBUG = True" && trimmed != "DEBUG=True" {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'"
        ))
    }
}

// â”€â”€ 66. DjangoSecretKeyHardcodedTemplate (CWE-798) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces hardcoded `SECRET_KEY = '...'` with an env-var lookup.
pub struct DjangoSecretKeyHardcodedTemplate;

impl PatchTemplate for DjangoSecretKeyHardcodedTemplate {
    fn name(&self) -> &'static str {
        "DjangoSecretKeyHardcoded"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }
        let trimmed = line.trim();
        if !trimmed.starts_with("SECRET_KEY") {
            return None;
        }
        if !trimmed.contains(" = ") {
            return None;
        }
        // Must have a string literal value
        let after_eq = trimmed.split_once(" = ").map(|x| x.1).unwrap_or("").trim();
        if !after_eq.starts_with('\'') && !after_eq.starts_with('"') {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')"
        ))
    }
}

// â”€â”€ 67. DjangoAllowedHostsWildcardTemplate (CWE-183) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `ALLOWED_HOSTS = ['*']` with an env-var-driven list.
pub struct DjangoAllowedHostsWildcardTemplate;

impl PatchTemplate for DjangoAllowedHostsWildcardTemplate {
    fn name(&self) -> &'static str {
        "DjangoAllowedHostsWildcard"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }
        let trimmed = line.trim();
        if !trimmed.starts_with("ALLOWED_HOSTS") {
            return None;
        }
        if !trimmed.contains("'*'") && !trimmed.contains("\"*\"") {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')"
        ))
    }
}

// â”€â”€ 68. DjangoCsrfExemptTemplate (CWE-352) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Removes `@csrf_exempt` decorator and replaces with a comment.
pub struct DjangoCsrfExemptTemplate;

impl PatchTemplate for DjangoCsrfExemptTemplate {
    fn name(&self) -> &'static str {
        "DjangoCsrfExempt"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }
        if !line.trim().starts_with("@csrf_exempt") {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}# SICARIO FIX: removed @csrf_exempt â€” ensure CSRF token is sent by client"
        ))
    }
}

// â”€â”€ 69. FlaskDebugTrueTemplate (CWE-215) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `app.run(debug=True)` with an env-var-driven debug flag.
pub struct FlaskDebugTrueTemplate;

impl PatchTemplate for FlaskDebugTrueTemplate {
    fn name(&self) -> &'static str {
        "FlaskDebugTrue"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }
        if !line.contains("debug=True")
            && !line.contains("debug = True")
            && !line.contains("'DEBUG'] = True")
            && !line.contains("\"DEBUG\"] = True")
        {
            return None;
        }
        let fixed = line
            .replace(
                "debug=True",
                "debug=os.environ.get('FLASK_DEBUG', 'False') == 'True'",
            )
            .replace(
                "debug = True",
                "debug=os.environ.get('FLASK_DEBUG', 'False') == 'True'",
            )
            .replace(
                "'DEBUG'] = True",
                "'DEBUG'] = os.environ.get('FLASK_DEBUG', 'False') == 'True'",
            )
            .replace(
                "\"DEBUG\"] = True",
                "\"DEBUG\"] = os.environ.get('FLASK_DEBUG', 'False') == 'True'",
            );
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 70. FlaskSecretKeyHardcodedTemplate (CWE-798) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces hardcoded Flask secret key with an env-var lookup.
pub struct FlaskSecretKeyHardcodedTemplate;

impl PatchTemplate for FlaskSecretKeyHardcodedTemplate {
    fn name(&self) -> &'static str {
        "FlaskSecretKeyHardcoded"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }
        let lower = line.to_lowercase();
        if !lower.contains("secret_key") {
            return None;
        }
        // Must be an assignment with a string literal
        if !line.contains(" = ") {
            return None;
        }
        let after_eq = line.split_once(" = ").map(|x| x.1).unwrap_or("").trim();
        if !after_eq.starts_with('\'') && !after_eq.starts_with('"') {
            return None;
        }
        let indent = get_indent(line);
        if line.contains("app.secret_key") {
            return Some(format!(
                "{indent}app.secret_key = os.environ.get('FLASK_SECRET_KEY')"
            ));
        }
        if line.contains("'SECRET_KEY']") || line.contains("\"SECRET_KEY\"]") {
            return Some(format!(
                "{indent}app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')"
            ));
        }
        None
    }
}

// â”€â”€ 71. FlaskSqlAlchemyUriHardcodedTemplate (CWE-798) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces hardcoded SQLAlchemy database URI with an env-var lookup.
pub struct FlaskSqlAlchemyUriHardcodedTemplate;

impl PatchTemplate for FlaskSqlAlchemyUriHardcodedTemplate {
    fn name(&self) -> &'static str {
        "FlaskSqlAlchemyUriHardcoded"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }
        if !line.contains("SQLALCHEMY_DATABASE_URI") {
            return None;
        }
        if !line.contains(" = ") {
            return None;
        }
        let after_eq = line.split_once(" = ").map(|x| x.1).unwrap_or("").trim();
        if !after_eq.starts_with('\'') && !after_eq.starts_with('"') {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')"
        ))
    }
}

// â”€â”€ Domain 9: Cloud & Infrastructure â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// â”€â”€ 72. AwsHardcodedAccessKeyTemplate (CWE-798) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces hardcoded AWS access key IDs (starting with AKIA) with a comment.
pub struct ReactHrefJavascriptTemplate;

impl PatchTemplate for ReactHrefJavascriptTemplate {
    fn name(&self) -> &'static str {
        "ReactHrefJavascript"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("href={") {
            return None;
        }
        if line.contains("https?://") || line.contains("startsWith") {
            return None;
        }
        // Wrap the href value with a scheme check
        let fixed = line
            .replace(
                "href={userInput}",
                "href={/^https?:\\/\\//.test(userInput) ? userInput : '#'}",
            )
            .replace(
                "href={url}",
                "href={/^https?:\\/\\//.test(url) ? url : '#'}",
            );
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 77. ReactWindowLocationTemplate (CWE-601) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Prepends a URL validation guard before `window.location.href = userInput`.
pub struct ReactWindowLocationTemplate;

impl PatchTemplate for ReactWindowLocationTemplate {
    fn name(&self) -> &'static str {
        "ReactWindowLocation"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("window.location.href") && !line.contains("window.location.replace") {
            return None;
        }
        if line.contains("startsWith") || line.contains("test(") {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}if (!/^\\//.test(userInput) && !/^https:\\/\\//.test(userInput)) throw new Error('Redirect blocked');\n{line}"
        ))
    }
}

// â”€â”€ 78. ReactLocalStorageTokenTemplate (CWE-922) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `localStorage.setItem('token', ...)` with a comment.
pub struct ReactLocalStorageTokenTemplate;

impl PatchTemplate for ReactLocalStorageTokenTemplate {
    fn name(&self) -> &'static str {
        "ReactLocalStorageToken"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("localStorage.setItem(") {
            return None;
        }
        let lower = line.to_lowercase();
        if !lower.contains("token") && !lower.contains("jwt") && !lower.contains("auth") {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}// SICARIO FIX (CWE-922): store auth tokens in httpOnly cookies, not localStorage\n\
             {indent}// localStorage is accessible to XSS â€” use Set-Cookie with HttpOnly; Secure; SameSite=Strict"
        ))
    }
}

// â”€â”€ 79. ReactUseEffectMissingDepTemplate (CWE-362) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces empty `[]` dependency array in useEffect when the callback uses outer vars.
///
/// Heuristic: if the line contains `useEffect(` with `}, [])` and the callback
/// references a variable that looks like a prop/state (camelCase identifier),
/// replace `[]` with `[<detected_var>]`.
pub struct ReactUseEffectMissingDepTemplate;

impl PatchTemplate for ReactUseEffectMissingDepTemplate {
    fn name(&self) -> &'static str {
        "ReactUseEffectMissingDep"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        // Must end with }, []) â€” the empty dep array pattern
        let trimmed = line.trim_end();
        if !trimmed.ends_with("}, [])") && !trimmed.ends_with("}, []);") {
            return None;
        }
        if !line.contains("useEffect(") {
            return None;
        }
        // Extract the callback body to find referenced variables
        // Simple heuristic: look for fetchData(X) or similar patterns
        let var = extract_useeffect_dep(line)?;
        let dep_array = format!("[{var}]");
        // Build replacement strings without format! to avoid brace escaping issues
        let repl = ["},", " ", &dep_array, ")"].concat(); // }, [userId])
        let repl_semi = ["},", " ", &dep_array, ");"].concat(); // }, [userId]);
        let fixed = if trimmed.ends_with("}, []);") {
            line.replace("}, []);", &repl_semi)
        } else {
            line.replace("}, [])", &repl)
        };
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 80. IacEnvFileHardcodedTemplate (CWE-798) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces hardcoded secret values in `.env` files with a placeholder.
///
/// Fires on lines matching `KEY=<non-empty-literal-value>` that look like
/// real secrets (not already a reference like `${VAR}` or `$(cmd)`).
#[cfg(test)]
mod sprint4_tests {
    use crate::remediation::template_registry::*;

    fn js() -> Language {
        Language::JavaScript
    }
    fn py() -> Language {
        Language::Python
    }
    fn go() -> Language {
        Language::Go
    }

    #[test]
    fn test_sql_concat_comment_injected() {
        let t = SqlStringConcatTemplate;
        let line = "    db.query('SELECT * FROM users WHERE id = ' + req.body.id);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("// SICARIO FIX (CWE-89)"));
        assert!(result.contains("db.query("));
    }

    #[test]
    fn test_sql_concat_no_user_input() {
        let t = SqlStringConcatTemplate;
        assert!(t
            .generate_patch("    db.query('SELECT * FROM users');", js())
            .is_none());
    }

    #[test]
    fn test_sql_template_string_flagged() {
        let t = SqlTemplateStringTemplate;
        let line = "    db.query(`SELECT * FROM users WHERE id = ${userId}`);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("// SICARIO FIX (CWE-89)"));
    }

    #[test]
    fn test_sql_template_no_interpolation() {
        let t = SqlTemplateStringTemplate;
        assert!(t
            .generate_patch("    db.query(`SELECT * FROM users`);", js())
            .is_none());
    }

    #[test]
    fn test_tls_min_version_node() {
        let t = TlsMinVersionTemplate;
        let result = t
            .generate_patch("    tls.createServer({ minVersion: 'TLSv1' })", js())
            .unwrap();
        assert!(result.contains("TLSv1.2"));
        assert!(!result.contains("minVersion: 'TLSv1'"));
    }

    #[test]
    fn test_tls_min_version_go() {
        let t = TlsMinVersionTemplate;
        let result = t
            .generate_patch("\tMinVersion: tls.VersionTLS10,", go())
            .unwrap();
        assert!(result.contains("VersionTLS12"));
    }

    #[test]
    fn test_tls_already_v12() {
        let t = TlsMinVersionTemplate;
        assert!(t
            .generate_patch("    minVersion: 'TLSv1.2'", js())
            .is_none());
    }

    #[test]
    fn test_tls_reject_unauthorized_fixed() {
        let t = TlsCertVerifyDisabledNodeTemplate;
        let result = t
            .generate_patch("    const opts = { rejectUnauthorized: false };", js())
            .unwrap();
        assert!(result.contains("rejectUnauthorized: true"));
    }

    #[test]
    fn test_tls_node_env_fixed() {
        let t = TlsCertVerifyDisabledNodeTemplate;
        let result = t
            .generate_patch("    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';", js())
            .unwrap();
        assert!(result.contains("= '1'"));
    }

    #[test]
    fn test_go_insecure_skip_verify_fixed() {
        let t = TlsCertVerifyDisabledGoTemplate;
        let result = t
            .generate_patch("\t\tInsecureSkipVerify: true,", go())
            .unwrap();
        assert!(result.contains("InsecureSkipVerify: false"));
    }

    #[test]
    fn test_go_insecure_skip_verify_wrong_lang() {
        let t = TlsCertVerifyDisabledGoTemplate;
        assert!(t.generate_patch("InsecureSkipVerify: true", js()).is_none());
    }

    #[test]
    fn test_ssrf_axios_guard_injected() {
        let t = SsrfHttpGetUserInputTemplate;
        let result = t
            .generate_patch("    const resp = await axios.get(req.body.url);", js())
            .unwrap();
        assert!(result.contains("ALLOWED_HOSTS"));
        assert!(result.contains("SSRF blocked"));
        assert!(result.contains("axios.get("));
    }

    #[test]
    fn test_ssrf_already_guarded() {
        let t = SsrfHttpGetUserInputTemplate;
        assert!(t
            .generate_patch(
                "    if (!ALLOWED_HOSTS.has(h)) throw new Error(); axios.get(url);",
                js()
            )
            .is_none());
    }

    #[test]
    fn test_ssrf_fetch_guard_injected() {
        let t = SsrfFetchUserInputTemplate;
        let result = t
            .generate_patch("    const r = await fetch(req.query.url);", js())
            .unwrap();
        assert!(result.contains("ALLOWED_HOSTS"));
        assert!(result.contains("fetch("));
    }

    #[test]
    fn test_django_debug_replaced() {
        let t = DjangoDebugTrueTemplate;
        let result = t.generate_patch("DEBUG = True", py()).unwrap();
        assert!(result.contains("os.environ.get('DJANGO_DEBUG'"));
        assert!(!result.contains("DEBUG = True"));
    }

    #[test]
    fn test_django_debug_false_untouched() {
        let t = DjangoDebugTrueTemplate;
        assert!(t.generate_patch("DEBUG = False", py()).is_none());
    }

    #[test]
    fn test_django_secret_key_replaced() {
        let t = DjangoSecretKeyHardcodedTemplate;
        let result = t
            .generate_patch("SECRET_KEY = 'django-insecure-abc123'", py())
            .unwrap();
        assert!(result.contains("os.environ.get('DJANGO_SECRET_KEY')"));
    }

    #[test]
    fn test_django_allowed_hosts_replaced() {
        let t = DjangoAllowedHostsWildcardTemplate;
        let result = t.generate_patch("ALLOWED_HOSTS = ['*']", py()).unwrap();
        assert!(result.contains("os.environ.get('ALLOWED_HOSTS'"));
        assert!(result.contains(".split(',')"));
    }

    #[test]
    fn test_csrf_exempt_removed() {
        let t = DjangoCsrfExemptTemplate;
        let result = t.generate_patch("@csrf_exempt", py()).unwrap();
        assert!(result.contains("# SICARIO FIX"));
        assert!(result.starts_with('#'));
    }

    #[test]
    fn test_flask_debug_replaced() {
        let t = FlaskDebugTrueTemplate;
        let result = t.generate_patch("    app.run(debug=True)", py()).unwrap();
        assert!(result.contains("os.environ.get('FLASK_DEBUG'"));
    }

    #[test]
    fn test_flask_secret_key_replaced() {
        let t = FlaskSecretKeyHardcodedTemplate;
        let result = t
            .generate_patch("    app.secret_key = 'my-secret'", py())
            .unwrap();
        assert!(result.contains("os.environ.get('FLASK_SECRET_KEY')"));
    }

    #[test]
    fn test_sqlalchemy_uri_replaced() {
        let t = FlaskSqlAlchemyUriHardcodedTemplate;
        let result = t
            .generate_patch(
                "SQLALCHEMY_DATABASE_URI = 'postgresql://user:pass@localhost/db'",
                py(),
            )
            .unwrap();
        assert!(result.contains("os.environ.get('DATABASE_URL')"));
    }

    #[test]
    fn test_aws_key_comment_injected() {
        let t = AwsHardcodedAccessKeyTemplate;
        let result = t
            .generate_patch(
                &format!(
                    "    accessKeyId: '{}',",
                    concat!("AKIA", "IOSFODNN7EXAMPLE")
                ),
                js(),
            )
            .unwrap();
        assert!(result.contains("// SICARIO FIX (CWE-798)"));
        assert!(result.contains("IAM role"));
    }

    #[test]
    fn test_aws_key_no_akia() {
        let t = AwsHardcodedAccessKeyTemplate;
        assert!(t
            .generate_patch("    accessKeyId: process.env.AWS_ACCESS_KEY_ID,", js())
            .is_none());
    }

    #[test]
    fn test_s3_public_read_removed() {
        let t = AwsS3PublicReadAclTemplate;
        let line = "    s3.putObject({ Bucket: 'my-bucket', Key: 'file', ACL: 'public-read', Body: data });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(!result.contains("ACL: 'public-read'"));
        assert!(result.contains("Bucket:"));
    }

    #[test]
    fn test_docker_latest_node_replaced() {
        let t = IacDockerLatestTagTemplate;
        let result = t.generate_patch("FROM node:latest", js()).unwrap();
        assert!(result.contains("lts-alpine"));
        assert!(!result.contains(":latest"));
    }

    #[test]
    fn test_docker_latest_python_replaced() {
        let t = IacDockerLatestTagTemplate;
        let result = t.generate_patch("FROM python:latest", js()).unwrap();
        assert!(result.contains(":slim"));
    }

    #[test]
    fn test_docker_pinned_not_replaced() {
        let t = IacDockerLatestTagTemplate;
        assert!(t.generate_patch("FROM node:18-alpine", js()).is_none());
    }

    #[test]
    fn test_docker_add_replaced_with_copy() {
        let t = IacDockerAddInsteadOfCopyTemplate;
        let result = t.generate_patch("ADD ./app /app", js()).unwrap();
        assert!(result.starts_with("COPY"));
        assert!(!result.contains("ADD "));
    }

    #[test]
    fn test_docker_add_url_not_replaced() {
        let t = IacDockerAddInsteadOfCopyTemplate;
        assert!(t
            .generate_patch("ADD https://example.com/file.tar.gz /tmp/", js())
            .is_none());
    }

    #[test]
    fn test_env_file_secret_replaced() {
        let t = IacEnvFileHardcodedTemplate;
        let result = t
            .generate_patch("DATABASE_PASSWORD=super_secret_123", js())
            .unwrap();
        assert!(result.contains("# SICARIO:"));
        assert!(result.contains("<REPLACE_WITH_REAL_VALUE>"));
    }

    #[test]
    fn test_env_file_empty_value_skipped() {
        let t = IacEnvFileHardcodedTemplate;
        assert!(t.generate_patch("DATABASE_PASSWORD=", js()).is_none());
    }

    #[test]
    fn test_env_file_reference_skipped() {
        let t = IacEnvFileHardcodedTemplate;
        assert!(t
            .generate_patch("DATABASE_URL=${DATABASE_URL}", js())
            .is_none());
    }

    #[test]
    fn test_react_href_wrapped() {
        let t = ReactHrefJavascriptTemplate;
        let result = t
            .generate_patch("    <a href={userInput}>click</a>", js())
            .unwrap();
        assert!(result.contains("https?:"));
        assert!(result.contains("'#'"));
    }

    #[test]
    fn test_window_location_guard_injected() {
        let t = ReactWindowLocationTemplate;
        let result = t
            .generate_patch("    window.location.href = userInput;", js())
            .unwrap();
        assert!(result.contains("Redirect blocked"));
        assert!(result.contains("window.location.href"));
    }

    #[test]
    fn test_localstorage_token_replaced() {
        let t = ReactLocalStorageTokenTemplate;
        let result = t
            .generate_patch("    localStorage.setItem('token', accessToken);", js())
            .unwrap();
        assert!(result.contains("// SICARIO FIX (CWE-922)"));
        assert!(result.contains("httpOnly cookies"));
    }

    #[test]
    fn test_localstorage_non_auth_not_replaced() {
        let t = ReactLocalStorageTokenTemplate;
        assert!(t
            .generate_patch("    localStorage.setItem('theme', 'dark');", js())
            .is_none());
    }

    #[test]
    fn test_useeffect_dep_injected() {
        let t = ReactUseEffectMissingDepTemplate;
        let result = t
            .generate_patch("    useEffect(() => { fetchData(userId); }, [])", js())
            .unwrap();
        assert!(result.contains("[userId]"));
        assert!(!result.contains(", []"));
    }

    #[test]
    fn test_useeffect_no_dep_found() {
        let t = ReactUseEffectMissingDepTemplate;
        assert!(t
            .generate_patch("    useEffect(() => { doSomething(); }, [])", js())
            .is_none());
    }

    // â”€â”€ Registry integration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_registry_django_debug_by_rule() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("django-debug-true", None).is_some());
    }

    #[test]
    fn test_registry_csrf_exempt_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-352")).is_some());
    }

    #[test]
    fn test_registry_docker_latest_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-1104")).is_some());
    }

    #[test]
    fn test_registry_localstorage_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-922")).is_some());
    }

    #[test]
    fn test_registry_tls_go_by_rule() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("go-tls-insecure-skip-verify", None).is_some());
    }

    #[test]
    fn test_registry_env_file_by_rule() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("env-file-hardcoded-secret", None).is_some());
    }
}

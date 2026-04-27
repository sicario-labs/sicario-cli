//! Security guardrail: blocks shell execution attempts from MCP tools.
//!
//! Validates that MCP tool calls and proposed mutations do not contain
//! dangerous shell execution patterns, enforcing the zero-liability boundary.
//!
//! Validates: Architectural Guardrails

/// Patterns that indicate dangerous shell execution attempts.
const DANGEROUS_PATTERNS: &[&str] = &[
    "exec",
    "shell",
    "system",
    "popen",
    "spawn",
    "eval",
    "cmd",
    "bash",
    "sh",
    "powershell",
    "subprocess",
    "os.system",
    "child_process",
    "execSync",
    "spawnSync",
];

/// Guards against shell execution attempts in MCP tool calls and mutations.
pub struct ShellExecutionGuard;

impl ShellExecutionGuard {
    /// Returns `Err` with a descriptive message if `patched_syntax` contains
    /// any dangerous shell execution pattern (case-insensitive substring match).
    pub fn validate_mutation(patched_syntax: &str) -> Result<(), String> {
        let lower = patched_syntax.to_lowercase();
        for pattern in DANGEROUS_PATTERNS {
            if lower.contains(&pattern.to_lowercase()) {
                return Err(format!(
                    "Proposed mutation contains dangerous shell execution pattern: '{}'. \
                     MCP tools cannot execute shell commands.",
                    pattern
                ));
            }
        }
        Ok(())
    }

    /// Returns `true` if the method name itself matches a dangerous shell pattern.
    pub fn is_dangerous_method(method_name: &str) -> bool {
        let lower = method_name.to_lowercase();
        DANGEROUS_PATTERNS
            .iter()
            .any(|p| lower.contains(&p.to_lowercase()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_mutation_clean_syntax() {
        assert!(ShellExecutionGuard::validate_mutation("let x = 1 + 2;").is_ok());
        assert!(ShellExecutionGuard::validate_mutation("fn safe_function() {}").is_ok());
    }

    #[test]
    fn test_validate_mutation_dangerous_patterns() {
        assert!(ShellExecutionGuard::validate_mutation("exec('rm -rf /')").is_err());
        assert!(ShellExecutionGuard::validate_mutation("os.system('ls')").is_err());
        assert!(ShellExecutionGuard::validate_mutation("subprocess.run(['bash'])").is_err());
        assert!(ShellExecutionGuard::validate_mutation("child_process.exec('cmd')").is_err());
        assert!(ShellExecutionGuard::validate_mutation("execSync('powershell')").is_err());
    }

    #[test]
    fn test_validate_mutation_case_insensitive() {
        assert!(ShellExecutionGuard::validate_mutation("EXEC('something')").is_err());
        assert!(ShellExecutionGuard::validate_mutation("Shell.run()").is_err());
        assert!(ShellExecutionGuard::validate_mutation("EVAL(code)").is_err());
    }

    #[test]
    fn test_is_dangerous_method_known_patterns() {
        assert!(ShellExecutionGuard::is_dangerous_method("exec_command"));
        assert!(ShellExecutionGuard::is_dangerous_method("run_shell"));
        assert!(ShellExecutionGuard::is_dangerous_method("spawn_process"));
        assert!(ShellExecutionGuard::is_dangerous_method("eval_code"));
    }

    #[test]
    fn test_is_dangerous_method_safe_names() {
        assert!(!ShellExecutionGuard::is_dangerous_method("scan_file"));
        assert!(!ShellExecutionGuard::is_dangerous_method("get_rules"));
        assert!(!ShellExecutionGuard::is_dangerous_method("analyze_reachability"));
        assert!(!ShellExecutionGuard::is_dangerous_method("propose_safe_mutation"));
    }
}

// SAFE: rust-command-shell-sh — allowlist validation prevents command injection
// Rule: rust-command-shell-sh | CWE-78 | Expected: TrueNegative

use std::collections::HashSet;
use std::process::Command;

fn run_allowed_command(user_input: &str) -> Result<String, String> {
    let allowed: HashSet<&str> = ["date", "uptime", "pwd"].iter().cloned().collect();

    // SAFE: command validated against an allowlist; Command::new called directly, no sh -c
    if !allowed.contains(user_input) {
        return Err(format!("Command '{}' is not allowed", user_input));
    }

    let output = Command::new(user_input)
        .output()
        .map_err(|e| e.to_string())?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn main() {
    let user_input = std::env::args().nth(1).unwrap_or_else(|| "date".to_string());
    match run_allowed_command(&user_input) {
        Ok(result) => println!("{}", result),
        Err(e) => eprintln!("Error: {}", e),
    }
}

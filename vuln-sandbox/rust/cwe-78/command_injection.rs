// VULNERABLE: rust-command-shell-sh — Command::new("sh") with -c and user input
// Rule: rust-command-shell-sh | CWE-78 | Severity: CRITICAL

use std::process::Command;

fn run_user_command(user_input: &str) -> String {
    // VULNERABLE: user input passed to sh -c allows arbitrary command execution
    // An attacker can pass: ls; cat /etc/passwd to read sensitive files
    let output = Command::new("sh")
        .arg("-c")
        .arg(user_input)
        .output()
        .expect("failed to execute process");

    String::from_utf8_lossy(&output.stdout).to_string()
}

fn main() {
    // Simulating user input from an HTTP request parameter
    let user_input = std::env::args().nth(1).unwrap_or_default();
    let result = run_user_command(&user_input);
    println!("{}", result);
}

// VULNERABLE: rust-command-new-variable — Command::new with variable program name
// Rule: rust-command-new-variable | CWE-78 | Severity: HIGH

use std::process::Command;

fn execute_program(program_name: &str, args: &[&str]) -> String {
    // VULNERABLE: user-controlled program name passed to Command::new
    // An attacker can pass any binary path to execute arbitrary programs
    let output = Command::new(program_name)
        .args(args)
        .output()
        .expect("failed to execute process");

    String::from_utf8_lossy(&output.stdout).to_string()
}

fn main() {
    // Simulating user-controlled program name from request
    let program = std::env::args().nth(1).unwrap_or_default();
    let result = execute_program(&program, &["--version"]);
    println!("{}", result);
}

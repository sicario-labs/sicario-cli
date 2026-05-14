// SAFE: rust-command-new-variable — fixed command with validated argument prevents injection
// Rule: rust-command-new-variable | CWE-78 | Expected: TrueNegative

use std::process::Command;

fn ping_host(hostname: &str) -> Result<String, String> {
    // SAFE: validate hostname contains only alphanumeric characters and dots/hyphens
    if !hostname.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') {
        return Err(format!("Invalid hostname: {}", hostname));
    }

    // SAFE: command is fixed ("ping"); only the validated hostname is passed as an argument
    let output = Command::new("ping")
        .arg("-c")
        .arg("1")
        .arg(hostname)
        .output()
        .map_err(|e| e.to_string())?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn main() {
    let hostname = std::env::args().nth(1).unwrap_or_else(|| "localhost".to_string());
    match ping_host(&hostname) {
        Ok(result) => println!("{}", result),
        Err(e) => eprintln!("Error: {}", e),
    }
}

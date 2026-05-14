// VULNERABLE: rust-fs-read-format — std::fs::read with format! path
// Rule: rust-fs-read-format | CWE-22 | Severity: HIGH

use std::fs;

fn read_user_file(user_filename: &str) -> Vec<u8> {
    // VULNERABLE: user-controlled filename interpolated into file path via format!
    // An attacker can pass: ../../etc/passwd to read arbitrary files
    let data = std::fs::read(format!("/uploads/{}", user_filename))
        .unwrap_or_default();
    data
}

fn main() {
    // Simulating user input from an HTTP request parameter
    let filename = std::env::args().nth(1).unwrap_or_default();
    let content = read_user_file(&filename);
    println!("read {} bytes", content.len());
}

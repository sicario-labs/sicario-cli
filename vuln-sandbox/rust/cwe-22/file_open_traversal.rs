// VULNERABLE: rust-file-open-format — File::open with format! path
// Rule: rust-file-open-format | CWE-22 | Severity: HIGH

use std::fs::File;
use std::io::Read;

fn serve_file(user_input: &str) -> String {
    // VULNERABLE: user-controlled input interpolated into file path via format!
    // An attacker can pass: ../../etc/shadow to read sensitive system files
    let mut file = File::open(format!("/var/app/data/{}", user_input))
        .expect("file not found");

    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    contents
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_default();
    let content = serve_file(&path);
    println!("{}", content);
}

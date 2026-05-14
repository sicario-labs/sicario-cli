// VULNERABLE: rust-generic-format-sql (crypto context) — weak hash algorithm for passwords
// Rule: rust-generic-format-sql | CWE-327 | Severity: HIGH
// Note: MD5 used for password hashing — broken algorithm

use md5;

fn hash_password(password: &str) -> String {
    // VULNERABLE: MD5 is a broken hash algorithm for password storage
    // MD5 can be cracked in seconds using rainbow tables or GPU brute-force
    let digest = md5::compute(password.as_bytes());
    format!("{:x}", digest)
}

fn verify_password(password: &str, stored_hash: &str) -> bool {
    hash_password(password) == stored_hash
}

fn main() {
    let password = "user_password_123";
    let hash = hash_password(password);
    println!("MD5 hash: {}", hash);
    println!("Verified: {}", verify_password(password, &hash));
}

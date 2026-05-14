// VULNERABLE: rust-sql-string-concat — hardcoded secret key in source code
// Rule: rust-sql-string-concat | CWE-798 | Severity: CRITICAL

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn sign_token(payload: &str) -> Vec<u8> {
    // VULNERABLE: HMAC key hardcoded as a string literal in source code
    // Anyone with access to the binary or source can forge tokens
    let secret = "hardcoded-jwt-secret-key-do-not-use";
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn main() {
    let token = sign_token("user:admin");
    println!("token: {:?}", token);
}

// SAFE: rust-generic-format-sql — AES-256-GCM used instead of weak hash for data protection
// Rule: rust-generic-format-sql | CWE-327 | Expected: TrueNegative

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};

fn encrypt(plaintext: &[u8], key: &Key<Aes256Gcm>) -> Result<Vec<u8>, aes_gcm::Error> {
    // SAFE: AES-256-GCM is a strong authenticated encryption algorithm
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, plaintext)?;

    // Prepend nonce to ciphertext for storage
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn main() {
    let key = Aes256Gcm::generate_key(OsRng);
    match encrypt(b"sensitive data", &key) {
        Ok(ciphertext) => println!("Encrypted {} bytes", ciphertext.len()),
        Err(e) => eprintln!("Error: {}", e),
    }
}

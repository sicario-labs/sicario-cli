// SAFE: rust-fs-read-format — path canonicalization and containment check prevent traversal
// Rule: rust-fs-read-format | CWE-22 | Expected: TrueNegative

use std::fs;
use std::path::{Path, PathBuf};

fn read_user_file(base_dir: &Path, user_filename: &str) -> Result<Vec<u8>, String> {
    let base = base_dir.canonicalize().map_err(|e| e.to_string())?;

    // SAFE: resolve the full path and verify it stays within the allowed directory
    let file_path = base.join(user_filename);
    let canonical = file_path.canonicalize().map_err(|_| "File not found".to_string())?;

    if !canonical.starts_with(&base) {
        return Err("Path traversal detected".to_string());
    }

    fs::read(&canonical).map_err(|e| e.to_string())
}

fn main() {
    let base_dir = PathBuf::from("/uploads");
    let filename = std::env::args().nth(1).unwrap_or_default();

    match read_user_file(&base_dir, &filename) {
        Ok(content) => println!("read {} bytes", content.len()),
        Err(e) => eprintln!("Error: {}", e),
    }
}

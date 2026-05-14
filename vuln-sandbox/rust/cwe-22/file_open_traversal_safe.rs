// SAFE: rust-file-open-format — path containment check prevents directory traversal
// Rule: rust-file-open-format | CWE-22 | Expected: TrueNegative

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

fn open_user_file(base_dir: &Path, user_filename: &str) -> Result<String, String> {
    let base = base_dir.canonicalize().map_err(|e| e.to_string())?;
    let file_path = base.join(user_filename);

    // SAFE: canonicalize resolves symlinks and .. components; then verify containment
    let canonical = file_path.canonicalize().map_err(|_| "File not found".to_string())?;

    if !canonical.starts_with(&base) {
        return Err("Access denied: path traversal detected".to_string());
    }

    let mut file = File::open(&canonical).map_err(|e| e.to_string())?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|e| e.to_string())?;
    Ok(contents)
}

fn main() {
    let base_dir = PathBuf::from("/uploads");
    let filename = std::env::args().nth(1).unwrap_or_default();

    match open_user_file(&base_dir, &filename) {
        Ok(content) => println!("{}", content),
        Err(e) => eprintln!("Error: {}", e),
    }
}

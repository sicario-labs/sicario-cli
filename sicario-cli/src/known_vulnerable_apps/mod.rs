//! Bundled ground-truth manifests for Known_Vulnerable_Apps.
//!
//! These manifests list the expected vulnerable files and rule IDs for four
//! deliberately insecure applications used for security training:
//!   - DVWA (Damn Vulnerable Web Application)
//!   - WebGoat (OWASP WebGoat)
//!   - Juice Shop (OWASP Juice Shop)
//!   - OWASP NodeGoat
//!
//! When `sicario benchmark --target <path>` points at a local clone of one of
//! these apps, the correct manifest is loaded automatically and used as the
//! ground truth for Precision/Recall/F1 computation.
//!
//! Requirements: Req 9 — Production Validation Against Known-Vulnerable Apps

use std::path::Path;

// ── Bundled manifest content ──────────────────────────────────────────────────

/// Ground-truth manifest for DVWA (Damn Vulnerable Web Application).
pub const DVWA_MANIFEST: &str = include_str!("dvwa_manifest.md");

/// Ground-truth manifest for OWASP WebGoat.
pub const WEBGOAT_MANIFEST: &str = include_str!("webgoat_manifest.md");

/// Ground-truth manifest for OWASP Juice Shop.
pub const JUICESHOP_MANIFEST: &str = include_str!("juiceshop_manifest.md");

/// Ground-truth manifest for OWASP NodeGoat.
pub const NODEGOAT_MANIFEST: &str = include_str!("nodegoat_manifest.md");

// ── App detection ─────────────────────────────────────────────────────────────

/// Detect which Known_Vulnerable_App a directory contains by looking for
/// characteristic files and directory structures.
///
/// Returns the app name ("dvwa", "webgoat", "juiceshop", "nodegoat") or `None`
/// if the directory doesn't match any known app.
pub fn detect_app_from_path(path: &Path) -> Option<&'static str> {
    // DVWA: has dvwa/ subdirectory or DVWA-specific files
    if path.join("dvwa").is_dir()
        || path.join("DVWA").is_dir()
        || path.join("dvwa_email.inc").exists()
        || path.join("config").join("config.inc.php.dist").exists()
    {
        return Some("dvwa");
    }

    // WebGoat: Java Maven project with WebGoat in the name
    if path.join("webgoat-server").is_dir()
        || path.join("WebGoat").is_dir()
        || (path.join("pom.xml").exists()
            && std::fs::read_to_string(path.join("pom.xml"))
                .map(|c| c.contains("WebGoat"))
                .unwrap_or(false))
    {
        return Some("webgoat");
    }

    // Juice Shop: Node.js app with juice-shop package.json
    if path.join("frontend").is_dir()
        && (path.join("package.json").exists()
            && std::fs::read_to_string(path.join("package.json"))
                .map(|c| c.contains("juice-shop") || c.contains("OWASP Juice Shop"))
                .unwrap_or(false))
    {
        return Some("juiceshop");
    }

    // NodeGoat: Node.js app with nodegoat in package.json
    if path.join("package.json").exists()
        && std::fs::read_to_string(path.join("package.json"))
            .map(|c| c.contains("nodegoat") || c.contains("NodeGoat"))
            .unwrap_or(false)
    {
        return Some("nodegoat");
    }

    None
}

/// Return the bundled manifest content for a given app name.
///
/// Accepts: "dvwa", "webgoat", "juiceshop", "nodegoat" (case-insensitive).
pub fn get_manifest_for_app(app_name: &str) -> Option<&'static str> {
    match app_name.to_lowercase().as_str() {
        "dvwa" => Some(DVWA_MANIFEST),
        "webgoat" => Some(WEBGOAT_MANIFEST),
        "juiceshop" | "juice-shop" | "juice_shop" => Some(JUICESHOP_MANIFEST),
        "nodegoat" | "node-goat" | "node_goat" => Some(NODEGOAT_MANIFEST),
        _ => None,
    }
}

/// Write a bundled manifest to a temporary file and return the path.
///
/// The caller is responsible for keeping the `TempDir` alive for the duration
/// of the benchmark run.
pub fn write_manifest_to_tempfile(
    content: &str,
    app_name: &str,
) -> anyhow::Result<(tempfile::TempDir, std::path::PathBuf)> {
    let tmp = tempfile::TempDir::new()?;
    let path = tmp.path().join(format!("{}_manifest.md", app_name));
    std::fs::write(&path, content)?;
    Ok((tmp, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_manifest_for_app_dvwa() {
        let m = get_manifest_for_app("dvwa");
        assert!(m.is_some());
        assert!(m.unwrap().contains("DVWA"));
    }

    #[test]
    fn test_get_manifest_for_app_webgoat() {
        let m = get_manifest_for_app("webgoat");
        assert!(m.is_some());
        assert!(m.unwrap().contains("WebGoat"));
    }

    #[test]
    fn test_get_manifest_for_app_juiceshop() {
        let m = get_manifest_for_app("juiceshop");
        assert!(m.is_some());
        assert!(m.unwrap().contains("Juice Shop"));
    }

    #[test]
    fn test_get_manifest_for_app_nodegoat() {
        let m = get_manifest_for_app("nodegoat");
        assert!(m.is_some());
        assert!(m.unwrap().contains("NodeGoat"));
    }

    #[test]
    fn test_get_manifest_for_app_aliases() {
        assert!(get_manifest_for_app("juice-shop").is_some());
        assert!(get_manifest_for_app("DVWA").is_some());
        assert!(get_manifest_for_app("WebGoat").is_some());
    }

    #[test]
    fn test_get_manifest_for_app_unknown() {
        assert!(get_manifest_for_app("unknown-app").is_none());
    }
}

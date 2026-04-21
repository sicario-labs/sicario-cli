//! Content-addressable scan cache.
//!
//! Caches scan results keyed by SHA-256 of file contents. Cache entries are
//! stored as JSON files in `.sicario/cache/` named by content hash. A
//! `rule_set_hash` is included in each entry so that results are invalidated
//! when the loaded rules change.

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::engine::Vulnerability;
use crate::parser::Language;

/// Trait for scan caching operations.
pub trait ScanCaching {
    /// Look up cached results by file content hash.
    fn get(&self, file_hash: &str, rule_set_hash: &str) -> Option<CachedScanResult>;

    /// Store scan results for a file content hash.
    fn put(&self, file_hash: &str, result: &CachedScanResult) -> Result<()>;

    /// Invalidate all cache entries for a specific language.
    fn invalidate_language(&self, language: Language) -> Result<usize>;

    /// Remove all cache entries.
    fn clear(&self) -> Result<usize>;

    /// Return cache statistics.
    fn stats(&self) -> Result<CacheStats>;
}

/// A cached scan result for a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedScanResult {
    pub file_hash: String,
    pub rule_set_hash: String,
    pub findings: Vec<CachedFinding>,
    pub language: Option<String>,
    pub cached_at: chrono::DateTime<Utc>,
}

/// Minimal finding representation stored in cache (avoids storing full Vulnerability).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedFinding {
    pub rule_id: String,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub severity: String,
    pub cwe_id: Option<String>,
}

/// Cache statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub size_bytes: u64,
    pub cached_files: usize,
    pub oldest_entry: Option<chrono::DateTime<Utc>>,
}

/// File-system backed scan cache stored in `.sicario/cache/`.
pub struct ScanCache {
    cache_dir: PathBuf,
}

impl ScanCache {
    /// Create a new `ScanCache` rooted at the given project directory.
    /// The cache directory is `<project_root>/.sicario/cache/`.
    pub fn new(project_root: &Path) -> Result<Self> {
        let cache_dir = project_root.join(".sicario").join("cache");
        fs::create_dir_all(&cache_dir).with_context(|| {
            format!("Failed to create cache directory: {}", cache_dir.display())
        })?;
        Ok(Self { cache_dir })
    }

    /// Compute SHA-256 hash of file contents.
    pub fn hash_file_contents(contents: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(contents);
        format!("{:x}", hasher.finalize())
    }

    /// Compute SHA-256 hash of the rule set (concatenation of all rule file contents).
    pub fn hash_rule_set(rule_contents: &[&str]) -> String {
        let mut hasher = Sha256::new();
        for content in rule_contents {
            hasher.update(content.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    /// Path to the cache file for a given content hash.
    fn cache_path(&self, file_hash: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.json", file_hash))
    }

    /// Remove stale cache entries whose original files no longer exist.
    /// `known_files` is a map from content hash → original file path.
    pub fn remove_stale_entries(&self, known_files: &HashMap<String, PathBuf>) -> Result<usize> {
        let mut removed = 0;
        for (hash, original_path) in known_files {
            if !original_path.exists() {
                let cache_file = self.cache_path(hash);
                if cache_file.exists() {
                    fs::remove_file(&cache_file)?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
}

impl ScanCaching for ScanCache {
    fn get(&self, file_hash: &str, rule_set_hash: &str) -> Option<CachedScanResult> {
        let path = self.cache_path(file_hash);
        let data = fs::read_to_string(&path).ok()?;
        let cached: CachedScanResult = serde_json::from_str(&data).ok()?;

        // Invalidate if rule set changed
        if cached.rule_set_hash != rule_set_hash {
            return None;
        }

        Some(cached)
    }

    fn put(&self, file_hash: &str, result: &CachedScanResult) -> Result<()> {
        let path = self.cache_path(file_hash);
        let json = serde_json::to_string_pretty(result)?;
        fs::write(&path, json)
            .with_context(|| format!("Failed to write cache entry: {}", path.display()))?;
        Ok(())
    }

    fn invalidate_language(&self, language: Language) -> Result<usize> {
        let lang_str = format!("{:?}", language);
        let mut removed = 0;

        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "json") {
                    if let Ok(data) = fs::read_to_string(&path) {
                        if let Ok(cached) = serde_json::from_str::<CachedScanResult>(&data) {
                            if cached.language.as_deref() == Some(&lang_str) {
                                fs::remove_file(&path)?;
                                removed += 1;
                            }
                        }
                    }
                }
            }
        }

        Ok(removed)
    }

    fn clear(&self) -> Result<usize> {
        let mut removed = 0;

        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "json") {
                    fs::remove_file(&path)?;
                    removed += 1;
                }
            }
        }

        Ok(removed)
    }

    fn stats(&self) -> Result<CacheStats> {
        let mut size_bytes: u64 = 0;
        let mut cached_files: usize = 0;
        let mut oldest: Option<chrono::DateTime<Utc>> = None;

        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "json") {
                    if let Ok(meta) = fs::metadata(&path) {
                        size_bytes += meta.len();
                        cached_files += 1;
                    }
                    if let Ok(data) = fs::read_to_string(&path) {
                        if let Ok(cached) = serde_json::from_str::<CachedScanResult>(&data) {
                            match &oldest {
                                None => oldest = Some(cached.cached_at),
                                Some(o) if cached.cached_at < *o => oldest = Some(cached.cached_at),
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        Ok(CacheStats {
            size_bytes,
            cached_files,
            oldest_entry: oldest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_cache() -> (TempDir, ScanCache) {
        let tmp = TempDir::new().unwrap();
        let cache = ScanCache::new(tmp.path()).unwrap();
        (tmp, cache)
    }

    fn sample_result(hash: &str, rule_hash: &str) -> CachedScanResult {
        CachedScanResult {
            file_hash: hash.to_string(),
            rule_set_hash: rule_hash.to_string(),
            findings: vec![CachedFinding {
                rule_id: "test-rule".into(),
                line: 10,
                column: 1,
                snippet: "let x = 1;".into(),
                severity: "High".into(),
                cwe_id: None,
            }],
            language: Some("JavaScript".into()),
            cached_at: Utc::now(),
        }
    }

    #[test]
    fn test_put_and_get() {
        let (_tmp, cache) = make_cache();
        let result = sample_result("abc123", "rules_v1");
        cache.put("abc123", &result).unwrap();

        let cached = cache.get("abc123", "rules_v1");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().findings.len(), 1);
    }

    #[test]
    fn test_cache_miss_on_different_rule_hash() {
        let (_tmp, cache) = make_cache();
        let result = sample_result("abc123", "rules_v1");
        cache.put("abc123", &result).unwrap();

        let cached = cache.get("abc123", "rules_v2");
        assert!(cached.is_none());
    }

    #[test]
    fn test_cache_miss_on_nonexistent() {
        let (_tmp, cache) = make_cache();
        let cached = cache.get("nonexistent", "rules_v1");
        assert!(cached.is_none());
    }

    #[test]
    fn test_clear() {
        let (_tmp, cache) = make_cache();
        cache.put("a", &sample_result("a", "r")).unwrap();
        cache.put("b", &sample_result("b", "r")).unwrap();

        let removed = cache.clear().unwrap();
        assert_eq!(removed, 2);
        assert!(cache.get("a", "r").is_none());
        assert!(cache.get("b", "r").is_none());
    }

    #[test]
    fn test_stats() {
        let (_tmp, cache) = make_cache();
        cache.put("a", &sample_result("a", "r")).unwrap();
        cache.put("b", &sample_result("b", "r")).unwrap();

        let stats = cache.stats().unwrap();
        assert_eq!(stats.cached_files, 2);
        assert!(stats.size_bytes > 0);
        assert!(stats.oldest_entry.is_some());
    }

    #[test]
    fn test_invalidate_language() {
        let (_tmp, cache) = make_cache();
        cache.put("js1", &sample_result("js1", "r")).unwrap();

        let mut py_result = sample_result("py1", "r");
        py_result.language = Some("Python".into());
        cache.put("py1", &py_result).unwrap();

        let removed = cache.invalidate_language(Language::JavaScript).unwrap();
        assert_eq!(removed, 1);
        assert!(cache.get("js1", "r").is_none());
        assert!(cache.get("py1", "r").is_some());
    }

    #[test]
    fn test_hash_file_contents() {
        let h1 = ScanCache::hash_file_contents(b"hello world");
        let h2 = ScanCache::hash_file_contents(b"hello world");
        let h3 = ScanCache::hash_file_contents(b"different");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_remove_stale_entries() {
        let (_tmp, cache) = make_cache();
        cache.put("stale", &sample_result("stale", "r")).unwrap();

        let mut known = HashMap::new();
        known.insert("stale".to_string(), PathBuf::from("/nonexistent/file.js"));

        let removed = cache.remove_stale_entries(&known).unwrap();
        assert_eq!(removed, 1);
        assert!(cache.get("stale", "r").is_none());
    }
}

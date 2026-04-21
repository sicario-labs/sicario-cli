//! VulnerabilityDatabaseManager — SQLite-backed CVE cache
//!
//! Provides offline-first SCA lookups against a local SQLite database populated
//! from OSV.dev and GHSA. Supports concurrent reads from Rayon scan workers via
//! SQLite WAL mode.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use semver::{Version, VersionReq};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::engine::{OwaspCategory, Severity};
use super::known_vulnerability::{
    KnownVulnerability, CREATE_METADATA_TABLE_SQL, CREATE_TABLE_SQL,
};

/// Events emitted by the background sync thread.
#[derive(Debug, Clone)]
pub enum DbSyncEvent {
    SyncStarted,
    SyncComplete { new_entries: usize },
    SyncError(String),
}

/// Manages the local SQLite vulnerability cache.
///
/// Thread-safe: the inner `Connection` is wrapped in `Arc<Mutex<_>>` so that
/// the background sync thread and Rayon scan workers can share it safely.
pub struct VulnerabilityDatabaseManager {
    conn: Arc<Mutex<Connection>>,
    cache_dir: PathBuf,
}

impl VulnerabilityDatabaseManager {
    /// Open (or create) the vulnerability cache database at
    /// `cache_dir/vuln_cache.db` and run schema migrations.
    pub fn new(cache_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(cache_dir)
            .with_context(|| format!("Failed to create cache dir: {:?}", cache_dir))?;

        let db_path = cache_dir.join("vuln_cache.db");
        let conn = Connection::open(&db_path)
            .with_context(|| format!("Failed to open SQLite database at {:?}", db_path))?;

        // Enable WAL mode for concurrent read access from Rayon workers
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch("PRAGMA synchronous=NORMAL;")?;

        // Run schema migrations
        conn.execute_batch(CREATE_TABLE_SQL)?;
        conn.execute_batch(CREATE_METADATA_TABLE_SQL)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            cache_dir: cache_dir.to_path_buf(),
        })
    }

    /// Query the local cache for all known vulnerabilities affecting a specific
    /// package name and version. Returns an empty Vec when the package is clean.
    ///
    /// Version matching uses the `semver` crate to evaluate the installed version
    /// against stored semver range strings entirely in-process (no network I/O).
    pub fn query_package(
        &self,
        ecosystem: &str,
        package_name: &str,
        version: &str,
    ) -> Result<Vec<KnownVulnerability>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("Lock error: {}", e))?;

        let mut stmt = conn.prepare(
            "SELECT cve_id, ghsa_id, package_name, ecosystem, vulnerable_versions,
                    patched_version, summary, severity, owasp_category, last_synced_at
             FROM known_vulnerabilities
             WHERE ecosystem = ?1 AND package_name = ?2",
        )?;

        let rows = stmt.query_map(params![ecosystem, package_name], |row| {
            Ok(RawRow {
                cve_id: row.get(0)?,
                ghsa_id: row.get(1)?,
                package_name: row.get(2)?,
                ecosystem: row.get(3)?,
                vulnerable_versions_json: row.get(4)?,
                patched_version: row.get(5)?,
                summary: row.get(6)?,
                severity_str: row.get(7)?,
                owasp_category_str: row.get(8)?,
                last_synced_at_str: row.get(9)?,
            })
        })?;

        let installed = parse_version_lenient(version);
        let mut results = Vec::new();

        for row in rows {
            let raw = row?;
            let kv = raw_to_known_vulnerability(raw)?;

            // Check if the installed version falls within any vulnerable range
            if let Some(ref installed_ver) = installed {
                if is_version_affected(installed_ver, &kv.vulnerable_versions) {
                    results.push(kv);
                }
            } else {
                // If we can't parse the version, conservatively include the record
                results.push(kv);
            }
        }

        Ok(results)
    }

    /// Return the timestamp of the most recent successful sync.
    pub fn last_synced_at(&self) -> Result<Option<DateTime<Utc>>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("Lock error: {}", e))?;

        let result: rusqlite::Result<String> = conn.query_row(
            "SELECT value FROM metadata WHERE key = 'last_synced_at'",
            [],
            |row| row.get(0),
        );

        match result {
            Ok(ts_str) => {
                let dt = ts_str
                    .parse::<DateTime<Utc>>()
                    .with_context(|| format!("Failed to parse timestamp: {}", ts_str))?;
                Ok(Some(dt))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Update the last_synced_at timestamp in the metadata table.
    pub fn update_last_synced_at(&self, ts: DateTime<Utc>) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("Lock error: {}", e))?;
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_synced_at', ?1)",
            params![ts.to_rfc3339()],
        )?;
        Ok(())
    }

    /// Upsert a single `KnownVulnerability` record into the database.
    ///
    /// Uses `INSERT OR REPLACE` so that re-importing the same advisory updates
    /// the existing row rather than creating a duplicate.
    pub fn upsert(&self, kv: &KnownVulnerability) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("Lock error: {}", e))?;

        let versions_json = serde_json::to_string(&kv.vulnerable_versions)?;
        let severity_str = severity_to_str(kv.severity);
        let owasp_str = kv.owasp_category.map(owasp_to_str);
        let unique_key = kv.unique_key();

        conn.execute(
            "INSERT OR REPLACE INTO known_vulnerabilities
             (cve_id, ghsa_id, package_name, ecosystem, vulnerable_versions,
              patched_version, summary, severity, owasp_category, last_synced_at, unique_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                kv.cve_id,
                kv.ghsa_id,
                kv.package_name,
                kv.ecosystem,
                versions_json,
                kv.patched_version,
                kv.summary,
                severity_str,
                owasp_str,
                kv.last_synced_at.to_rfc3339(),
                unique_key,
            ],
        )?;
        Ok(())
    }

    /// Force an immediate synchronization from all configured upstream sources.
    /// Returns the count of new/updated entries.
    pub fn sync_now(&self) -> Result<usize> {
        use super::osv_import::OsvImporter;
        use super::ghsa_import::GhsaImporter;

        let mut total = 0usize;

        // OSV.dev bulk import for each ecosystem
        let osv = OsvImporter::new(Arc::clone(&self.conn));
        for ecosystem in &["npm", "PyPI", "crates.io", "Maven", "Go"] {
            match osv.import_ecosystem(ecosystem) {
                Ok(count) => total += count,
                Err(e) => {
                    tracing::warn!("OSV import failed for {}: {}", ecosystem, e);
                }
            }
        }

        // GHSA GraphQL import
        let ghsa = GhsaImporter::new(Arc::clone(&self.conn));
        match ghsa.import_all() {
            Ok(count) => total += count,
            Err(e) => {
                tracing::warn!("GHSA import failed: {}", e);
            }
        }

        self.update_last_synced_at(Utc::now())?;
        Ok(total)
    }

    /// Spawn the background sync thread.
    ///
    /// Sleeps for `interval` between sync cycles. Sends `DbSyncEvent` messages
    /// over the provided `mpsc::Sender`.
    pub fn start_background_sync(
        &self,
        interval: Duration,
        tx: std::sync::mpsc::Sender<DbSyncEvent>,
    ) -> JoinHandle<()> {
        let conn = Arc::clone(&self.conn);
        let cache_dir = self.cache_dir.clone();

        thread::spawn(move || {
            loop {
                thread::sleep(interval);

                let _ = tx.send(DbSyncEvent::SyncStarted);

                // Create a temporary manager using the shared connection
                let manager = VulnerabilityDatabaseManager {
                    conn: Arc::clone(&conn),
                    cache_dir: cache_dir.clone(),
                };

                match manager.sync_now() {
                    Ok(count) => {
                        let _ = tx.send(DbSyncEvent::SyncComplete { new_entries: count });
                    }
                    Err(e) => {
                        let _ = tx.send(DbSyncEvent::SyncError(e.to_string()));
                    }
                }
            }
        })
    }

    /// Return a clone of the inner connection Arc for use by importers.
    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

struct RawRow {
    cve_id: Option<String>,
    ghsa_id: Option<String>,
    package_name: String,
    ecosystem: String,
    vulnerable_versions_json: String,
    patched_version: Option<String>,
    summary: String,
    severity_str: String,
    owasp_category_str: Option<String>,
    last_synced_at_str: String,
}

fn raw_to_known_vulnerability(raw: RawRow) -> Result<KnownVulnerability> {
    let vulnerable_versions: Vec<String> =
        serde_json::from_str(&raw.vulnerable_versions_json)
            .unwrap_or_default();

    let severity = str_to_severity(&raw.severity_str);
    let owasp_category = raw.owasp_category_str.as_deref().and_then(str_to_owasp);
    let last_synced_at = raw
        .last_synced_at_str
        .parse::<DateTime<Utc>>()
        .unwrap_or_else(|_| Utc::now());

    Ok(KnownVulnerability {
        cve_id: raw.cve_id,
        ghsa_id: raw.ghsa_id,
        package_name: raw.package_name,
        ecosystem: raw.ecosystem,
        vulnerable_versions,
        patched_version: raw.patched_version,
        summary: raw.summary,
        severity,
        owasp_category,
        last_synced_at,
    })
}

/// Parse a version string leniently, stripping leading `v` and extra qualifiers.
fn parse_version_lenient(version: &str) -> Option<Version> {
    let cleaned = version.trim_start_matches('v');
    // Strip pre-release / build metadata suffixes that semver crate may reject
    let base = cleaned.split(['-', '+']).next().unwrap_or(cleaned);
    Version::parse(base).ok()
}

/// Check whether `version` falls within any of the provided semver range strings.
fn is_version_affected(version: &Version, ranges: &[String]) -> bool {
    for range_str in ranges {
        if let Ok(req) = VersionReq::parse(range_str) {
            if req.matches(version) {
                return true;
            }
        }
    }
    false
}

pub fn severity_to_str(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

pub fn str_to_severity(s: &str) -> Severity {
    match s {
        "Critical" => Severity::Critical,
        "High" => Severity::High,
        "Medium" => Severity::Medium,
        "Low" => Severity::Low,
        _ => Severity::Info,
    }
}

pub fn owasp_to_str(o: OwaspCategory) -> &'static str {
    match o {
        OwaspCategory::A01_BrokenAccessControl => "A01_BrokenAccessControl",
        OwaspCategory::A02_CryptographicFailures => "A02_CryptographicFailures",
        OwaspCategory::A03_Injection => "A03_Injection",
        OwaspCategory::A04_InsecureDesign => "A04_InsecureDesign",
        OwaspCategory::A05_SecurityMisconfiguration => "A05_SecurityMisconfiguration",
        OwaspCategory::A06_VulnerableComponents => "A06_VulnerableComponents",
        OwaspCategory::A07_IdentificationAuthFailures => "A07_IdentificationAuthFailures",
        OwaspCategory::A08_SoftwareDataIntegrityFailures => "A08_SoftwareDataIntegrityFailures",
        OwaspCategory::A09_SecurityLoggingFailures => "A09_SecurityLoggingFailures",
        OwaspCategory::A10_ServerSideRequestForgery => "A10_ServerSideRequestForgery",
    }
}

pub fn str_to_owasp(s: &str) -> Option<OwaspCategory> {
    match s {
        "A01_BrokenAccessControl" => Some(OwaspCategory::A01_BrokenAccessControl),
        "A02_CryptographicFailures" => Some(OwaspCategory::A02_CryptographicFailures),
        "A03_Injection" => Some(OwaspCategory::A03_Injection),
        "A04_InsecureDesign" => Some(OwaspCategory::A04_InsecureDesign),
        "A05_SecurityMisconfiguration" => Some(OwaspCategory::A05_SecurityMisconfiguration),
        "A06_VulnerableComponents" => Some(OwaspCategory::A06_VulnerableComponents),
        "A07_IdentificationAuthFailures" => Some(OwaspCategory::A07_IdentificationAuthFailures),
        "A08_SoftwareDataIntegrityFailures" => Some(OwaspCategory::A08_SoftwareDataIntegrityFailures),
        "A09_SecurityLoggingFailures" => Some(OwaspCategory::A09_SecurityLoggingFailures),
        "A10_ServerSideRequestForgery" => Some(OwaspCategory::A10_ServerSideRequestForgery),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_db() -> (VulnerabilityDatabaseManager, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = VulnerabilityDatabaseManager::new(dir.path()).unwrap();
        (db, dir)
    }

    fn make_kv(pkg: &str, eco: &str, ranges: Vec<&str>) -> KnownVulnerability {
        let mut kv = KnownVulnerability::new(
            pkg.to_string(),
            eco.to_string(),
            "Test vulnerability".to_string(),
            Severity::High,
        );
        kv.cve_id = Some(format!("CVE-2024-{}", pkg));
        kv.vulnerable_versions = ranges.into_iter().map(String::from).collect();
        kv
    }

    #[test]
    fn test_db_creation() {
        let (db, dir) = make_db();
        assert!(dir.path().join("vuln_cache.db").exists());
        let ts = db.last_synced_at().unwrap();
        assert!(ts.is_none());
    }

    #[test]
    fn test_upsert_and_query_affected() {
        let (db, _dir) = make_db();
        let kv = make_kv("lodash", "npm", vec![">=4.0.0, <4.17.21"]);
        db.upsert(&kv).unwrap();

        // Version within range → should be returned
        let results = db.query_package("npm", "lodash", "4.17.20").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].package_name, "lodash");
    }

    #[test]
    fn test_query_unaffected_version() {
        let (db, _dir) = make_db();
        let kv = make_kv("lodash", "npm", vec![">=4.0.0, <4.17.21"]);
        db.upsert(&kv).unwrap();

        // Patched version → should NOT be returned
        let results = db.query_package("npm", "lodash", "4.17.21").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_query_unknown_package() {
        let (db, _dir) = make_db();
        let results = db.query_package("npm", "nonexistent-pkg", "1.0.0").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_upsert_idempotent() {
        let (db, _dir) = make_db();
        let kv = make_kv("express", "npm", vec![">=4.0.0, <4.18.0"]);
        db.upsert(&kv).unwrap();
        db.upsert(&kv).unwrap(); // second upsert should not error

        let results = db.query_package("npm", "express", "4.17.0").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_last_synced_at_update() {
        let (db, _dir) = make_db();
        assert!(db.last_synced_at().unwrap().is_none());

        let now = Utc::now();
        db.update_last_synced_at(now).unwrap();

        let stored = db.last_synced_at().unwrap().unwrap();
        // Allow 1 second tolerance for timestamp serialization
        let diff = (stored - now).num_seconds().abs();
        assert!(diff <= 1, "Timestamp drift: {}s", diff);
    }

    #[test]
    fn test_parse_version_lenient() {
        assert!(parse_version_lenient("1.2.3").is_some());
        assert!(parse_version_lenient("v1.2.3").is_some());
        assert!(parse_version_lenient("1.2.3-beta.1").is_some());
        assert!(parse_version_lenient("not-a-version").is_none());
    }

    #[test]
    fn test_is_version_affected() {
        let v = Version::parse("4.17.20").unwrap();
        assert!(is_version_affected(&v, &[">=4.0.0, <4.17.21".to_string()]));
        assert!(!is_version_affected(&v, &[">=4.17.21".to_string()]));
        assert!(!is_version_affected(&v, &[]));
    }
}

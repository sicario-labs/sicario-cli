//! Property-based tests for the SCA engine
//!
//! Feature: sicario-cli-core
//! Properties:
//!   38 — CVE version range matching correctness
//!   39 — Background sync non-interference
//!   40 — Manifest parsing completeness

#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;
    use std::fs;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    use crate::engine::sca::known_vulnerability::KnownVulnerability;
    use crate::engine::sca::manifest_parser::{
        parse_cargo_toml, parse_package_json, parse_requirements_txt, Dependency, ManifestParser,
    };
    use crate::engine::sca::vuln_db::VulnerabilityDatabaseManager;
    use crate::engine::Severity;

    // ── Generators ────────────────────────────────────────────────────────────

    /// Generate a valid semver triple (major, minor, patch).
    fn arb_semver() -> impl Strategy<Value = (u32, u32, u32)> {
        (0u32..20u32, 0u32..20u32, 0u32..20u32)
    }

    /// Generate a semver string from a triple.
    fn semver_str(major: u32, minor: u32, patch: u32) -> String {
        format!("{}.{}.{}", major, minor, patch)
    }

    /// Generate a valid npm package name (lowercase letters and hyphens).
    fn arb_pkg_name() -> impl Strategy<Value = String> {
        "[a-z]{3,10}(-[a-z]{2,6}){0,2}".prop_map(|s| s)
    }

    /// Generate a valid Python package name.
    fn arb_py_pkg_name() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_]{2,12}".prop_map(|s| s)
    }

    /// Generate a valid Rust crate name.
    fn arb_crate_name() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_]{2,12}".prop_map(|s| s)
    }

    fn make_db() -> (VulnerabilityDatabaseManager, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = VulnerabilityDatabaseManager::new(dir.path()).unwrap();
        (db, dir)
    }

    fn make_kv(pkg: &str, eco: &str, ranges: Vec<String>) -> KnownVulnerability {
        let mut kv = KnownVulnerability::new(
            pkg.to_string(),
            eco.to_string(),
            "Test vulnerability".to_string(),
            Severity::High,
        );
        kv.cve_id = Some(format!("CVE-2024-{}", pkg));
        kv.vulnerable_versions = ranges;
        kv
    }

    // ── Property 38: CVE version range matching correctness ───────────────────
    //
    // Feature: sicario-cli-core, Property 38: CVE version range matching correctness
    // Validates: Requirements 5.1
    //
    // For any package name, ecosystem, and semver version string,
    // `query_package()` should return a finding if and only if the version falls
    // within a stored vulnerable range, and return empty when the version is
    // patched or unaffected.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        /// A version strictly below the lower bound of a range must NOT be flagged.
        #[test]
        fn prop38_version_below_range_is_not_affected(
            (maj, min, patch) in arb_semver(),
            pkg in arb_pkg_name(),
        ) {
            // Vulnerable range: >= (maj+1).0.0
            // Installed version: maj.min.patch  →  always below the range
            let (db, _dir) = make_db();
            let range = format!(">={}.0.0", maj + 1);
            let kv = make_kv(&pkg, "npm", vec![range]);
            db.upsert(&kv).unwrap();

            let installed = semver_str(maj, min, patch);
            let results = db.query_package("npm", &pkg, &installed).unwrap();
            prop_assert!(
                results.is_empty(),
                "Version {} should NOT be flagged by range >={}.0.0",
                installed, maj + 1
            );
        }

        /// A version within the vulnerable range MUST be flagged.
        #[test]
        fn prop38_version_within_range_is_affected(
            (maj, min, patch) in arb_semver(),
            pkg in arb_pkg_name(),
        ) {
            // Vulnerable range: >= maj.0.0, < (maj+1).0.0
            // Installed version: maj.min.patch  →  always within the range
            let (db, _dir) = make_db();
            let range = format!(">={}.0.0, <{}.0.0", maj, maj + 1);
            let kv = make_kv(&pkg, "npm", vec![range]);
            db.upsert(&kv).unwrap();

            let installed = semver_str(maj, min, patch);
            let results = db.query_package("npm", &pkg, &installed).unwrap();
            prop_assert!(
                !results.is_empty(),
                "Version {} SHOULD be flagged by range >={}.0.0, <{}.0.0",
                installed, maj, maj + 1
            );
        }

        /// A version at or above the patched version must NOT be flagged.
        #[test]
        fn prop38_patched_version_is_not_affected(
            (maj, min, patch) in arb_semver(),
            pkg in arb_pkg_name(),
        ) {
            // Vulnerable range: < maj.min.patch
            // Installed version: maj.min.patch  →  exactly at the boundary (not affected)
            let (db, _dir) = make_db();
            let range = format!("<{}.{}.{}", maj, min, patch);
            let kv = make_kv(&pkg, "npm", vec![range]);
            db.upsert(&kv).unwrap();

            let installed = semver_str(maj, min, patch);
            let results = db.query_package("npm", &pkg, &installed).unwrap();
            prop_assert!(
                results.is_empty(),
                "Version {} should NOT be flagged by range <{}.{}.{}",
                installed, maj, min, patch
            );
        }

        /// An unknown package must always return empty results.
        #[test]
        fn prop38_unknown_package_returns_empty(
            (maj, min, patch) in arb_semver(),
            pkg in arb_pkg_name(),
        ) {
            let (db, _dir) = make_db();
            // Do NOT insert any record for this package
            let installed = semver_str(maj, min, patch);
            let results = db.query_package("npm", &pkg, &installed).unwrap();
            prop_assert!(
                results.is_empty(),
                "Unknown package {} should return no results",
                pkg
            );
        }

        /// Upserting the same record twice must not produce duplicate results.
        #[test]
        fn prop38_upsert_idempotent_no_duplicates(
            (maj, min, patch) in arb_semver(),
            pkg in arb_pkg_name(),
        ) {
            let (db, _dir) = make_db();
            let range = format!(">={}.0.0, <{}.0.0", maj, maj + 1);
            let kv = make_kv(&pkg, "npm", vec![range]);

            db.upsert(&kv).unwrap();
            db.upsert(&kv).unwrap(); // second upsert must be idempotent

            let installed = semver_str(maj, min, patch);
            let results = db.query_package("npm", &pkg, &installed).unwrap();
            // At most one result per unique CVE record
            prop_assert!(
                results.len() <= 1,
                "Duplicate upsert should not produce multiple results, got {}",
                results.len()
            );
        }
    }

    // ── Property 39: Background sync non-interference ─────────────────────────
    //
    // Feature: sicario-cli-core, Property 39: Background sync non-interference
    // Validates: Requirements 5.1
    //
    // For any concurrent combination of `query_package()` calls and an in-progress
    // `sync_now()` (simulated as concurrent upserts), all queries should return
    // consistent results and never observe a partially-written record.
    //
    // We simulate the sync thread by spawning a thread that performs rapid upserts
    // while the main thread concurrently queries. SQLite WAL mode must ensure
    // readers never see partial writes.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        #[test]
        fn prop39_concurrent_reads_never_see_partial_writes(
            (maj, min, patch) in arb_semver(),
            pkg in arb_pkg_name(),
        ) {
            let dir = TempDir::new().unwrap();
            let db = Arc::new(VulnerabilityDatabaseManager::new(dir.path()).unwrap());

            let range = format!(">={}.0.0, <{}.0.0", maj, maj + 1);
            let kv = make_kv(&pkg, "npm", vec![range.clone()]);

            // Pre-populate so the reader has something to find
            db.upsert(&kv).unwrap();

            let db_writer = Arc::clone(&db);
            let pkg_clone = pkg.clone();
            let range_clone = range.clone();

            // Spawn a writer thread that repeatedly upserts the same record
            let writer = std::thread::spawn(move || {
                for i in 0..20u32 {
                    let mut kv2 = make_kv(&pkg_clone, "npm", vec![range_clone.clone()]);
                    // Vary the summary to force a real write each iteration
                    kv2.summary = format!("Updated summary iteration {}", i);
                    // Ignore errors — the point is to stress the WAL
                    let _ = db_writer.upsert(&kv2);
                }
            });

            // Concurrently read — every result must be a complete, valid record
            let installed = semver_str(maj, min, patch);
            for _ in 0..20 {
                let results = db.query_package("npm", &pkg, &installed).unwrap();
                // Each result must have a non-empty package_name (no partial rows)
                for r in &results {
                    prop_assert!(
                        !r.package_name.is_empty(),
                        "Concurrent read returned a record with empty package_name"
                    );
                    prop_assert!(
                        !r.ecosystem.is_empty(),
                        "Concurrent read returned a record with empty ecosystem"
                    );
                }
            }

            writer.join().unwrap();
        }

        /// After a sync completes, `last_synced_at` must be set and non-None.
        #[test]
        fn prop39_last_synced_at_set_after_update(
            (maj, min, patch) in arb_semver(),
        ) {
            let (db, _dir) = make_db();
            prop_assert!(db.last_synced_at().unwrap().is_none(), "Should start as None");

            let now = chrono::Utc::now();
            db.update_last_synced_at(now).unwrap();

            let stored = db.last_synced_at().unwrap();
            prop_assert!(stored.is_some(), "last_synced_at should be Some after update");

            let diff = (stored.unwrap() - now).num_seconds().abs();
            prop_assert!(diff <= 1, "Stored timestamp should match within 1 second");
        }
    }

    // ── Property 40: Manifest parsing completeness ────────────────────────────
    //
    // Feature: sicario-cli-core, Property 40: Manifest parsing completeness
    // Validates: Requirements 5.1
    //
    // For any generated `package.json`, `Cargo.toml`, or `requirements.txt`
    // containing a known set of dependencies, the manifest parser should extract
    // every declared package name and version without omission.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        /// For any set of npm packages written to package.json, all must be parsed back.
        #[test]
        fn prop40_package_json_completeness(
            pkgs in prop::collection::vec(
                (arb_pkg_name(), arb_semver()),
                1..8usize,
            ),
        ) {
            let dir = TempDir::new().unwrap();

            // Build a package.json with the generated packages
            let deps_json: String = pkgs
                .iter()
                .map(|(name, (maj, min, patch))| {
                    format!("\"{}\":\"^{}.{}.{}\"", name, maj, min, patch)
                })
                .collect::<Vec<_>>()
                .join(",");
            let content = format!("{{\"dependencies\":{{{}}}}}", deps_json);
            let path = dir.path().join("package.json");
            fs::write(&path, &content).unwrap();

            let parsed = parse_package_json(&path).unwrap();

            // Every generated package must appear in the parsed output
            for (name, (maj, min, patch)) in &pkgs {
                let expected_version = format!("{}.{}.{}", maj, min, patch);
                let found = parsed.iter().any(|d| {
                    d.package_name == *name && d.version == expected_version
                });
                prop_assert!(
                    found,
                    "Package {}@{} not found in parsed output. Parsed: {:?}",
                    name, expected_version, parsed
                );
            }
        }

        /// For any set of crates written to Cargo.toml, all must be parsed back.
        #[test]
        fn prop40_cargo_toml_completeness(
            crates in prop::collection::vec(
                (arb_crate_name(), arb_semver()),
                1..6usize,
            ),
        ) {
            let dir = TempDir::new().unwrap();

            let deps_toml: String = crates
                .iter()
                .map(|(name, (maj, min, patch))| {
                    format!("{} = \"{}.{}.{}\"\n", name, maj, min, patch)
                })
                .collect::<Vec<_>>()
                .join("");
            let content = format!(
                "[package]\nname = \"test\"\nversion = \"0.1.0\"\n\n[dependencies]\n{}",
                deps_toml
            );
            let path = dir.path().join("Cargo.toml");
            fs::write(&path, &content).unwrap();

            let parsed = parse_cargo_toml(&path).unwrap();

            for (name, (maj, min, patch)) in &crates {
                let expected_version = format!("{}.{}.{}", maj, min, patch);
                let found = parsed.iter().any(|d| {
                    d.package_name == *name && d.version == expected_version
                });
                prop_assert!(
                    found,
                    "Crate {}@{} not found in parsed output. Parsed: {:?}",
                    name, expected_version, parsed
                );
            }
        }

        /// For any set of PyPI packages written to requirements.txt, all must be parsed back.
        #[test]
        fn prop40_requirements_txt_completeness(
            pkgs in prop::collection::vec(
                (arb_py_pkg_name(), arb_semver()),
                1..8usize,
            ),
        ) {
            let dir = TempDir::new().unwrap();

            let content: String = pkgs
                .iter()
                .map(|(name, (maj, min, patch))| {
                    format!("{}=={}.{}.{}\n", name, maj, min, patch)
                })
                .collect::<Vec<_>>()
                .join("");
            let path = dir.path().join("requirements.txt");
            fs::write(&path, &content).unwrap();

            let parsed = parse_requirements_txt(&path).unwrap();

            for (name, (maj, min, patch)) in &pkgs {
                let expected_version = format!("{}.{}.{}", maj, min, patch);
                let found = parsed.iter().any(|d| {
                    d.package_name == *name && d.version == expected_version
                });
                prop_assert!(
                    found,
                    "Package {}=={} not found in parsed output. Parsed: {:?}",
                    name, expected_version, parsed
                );
            }
        }

        /// ManifestParser::parse_directory must find all packages across all manifest types.
        #[test]
        fn prop40_parse_directory_finds_all_manifest_types(
            npm_pkg in arb_pkg_name(),
            npm_ver in arb_semver(),
            py_pkg in arb_py_pkg_name(),
            py_ver in arb_semver(),
            rs_pkg in arb_crate_name(),
            rs_ver in arb_semver(),
        ) {
            let dir = TempDir::new().unwrap();

            // Write package.json
            fs::write(
                dir.path().join("package.json"),
                format!(
                    "{{\"dependencies\":{{\"{}\":\"{}.{}.{}\"}}}}",
                    npm_pkg, npm_ver.0, npm_ver.1, npm_ver.2
                ),
            ).unwrap();

            // Write requirements.txt
            fs::write(
                dir.path().join("requirements.txt"),
                format!("{}=={}.{}.{}\n", py_pkg, py_ver.0, py_ver.1, py_ver.2),
            ).unwrap();

            // Write Cargo.toml
            fs::write(
                dir.path().join("Cargo.toml"),
                format!(
                    "[package]\nname=\"test\"\nversion=\"0.1.0\"\n[dependencies]\n{} = \"{}.{}.{}\"\n",
                    rs_pkg, rs_ver.0, rs_ver.1, rs_ver.2
                ),
            ).unwrap();

            let all_deps = ManifestParser::parse_directory(dir.path()).unwrap();

            let npm_found = all_deps.iter().any(|d| d.package_name == npm_pkg && d.ecosystem == "npm");
            let py_found = all_deps.iter().any(|d| d.package_name == py_pkg && d.ecosystem == "PyPI");
            let rs_found = all_deps.iter().any(|d| d.package_name == rs_pkg && d.ecosystem == "crates.io");

            prop_assert!(npm_found, "npm package {} not found in {:?}", npm_pkg, all_deps);
            prop_assert!(py_found, "PyPI package {} not found in {:?}", py_pkg, all_deps);
            prop_assert!(rs_found, "crates.io package {} not found in {:?}", rs_pkg, all_deps);
        }
    }
}

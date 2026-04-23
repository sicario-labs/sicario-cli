//! Property-based tests for OWASP category mapping consistency and compliance
//! report completeness.
//!
//! Feature: sicario-cli-core
//! Property 36 — OWASP category mapping consistency
//! Property 37 — OWASP compliance report completeness
//!
//! Validates: Requirements 17.1, 17.2, 17.3, 17.4, 17.5

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    use crate::engine::{OwaspCategory, Severity, Vulnerability};
    use crate::reporting::owasp_report::{
        generate_compliance_report, group_by_owasp, report_to_json, report_to_markdown,
        ALL_OWASP_CATEGORIES,
    };

    // ── Generators ────────────────────────────────────────────────────────────

    fn arb_severity() -> impl Strategy<Value = Severity> {
        prop_oneof![
            Just(Severity::Critical),
            Just(Severity::High),
            Just(Severity::Medium),
            Just(Severity::Low),
            Just(Severity::Info),
        ]
    }

    fn arb_owasp_category() -> impl Strategy<Value = OwaspCategory> {
        prop_oneof![
            Just(OwaspCategory::A01_BrokenAccessControl),
            Just(OwaspCategory::A02_CryptographicFailures),
            Just(OwaspCategory::A03_Injection),
            Just(OwaspCategory::A04_InsecureDesign),
            Just(OwaspCategory::A05_SecurityMisconfiguration),
            Just(OwaspCategory::A06_VulnerableComponents),
            Just(OwaspCategory::A07_IdentificationAuthFailures),
            Just(OwaspCategory::A08_SoftwareDataIntegrityFailures),
            Just(OwaspCategory::A09_SecurityLoggingFailures),
            Just(OwaspCategory::A10_ServerSideRequestForgery),
        ]
    }

    fn arb_optional_owasp() -> impl Strategy<Value = Option<OwaspCategory>> {
        prop_oneof![Just(None), arb_owasp_category().prop_map(Some),]
    }

    fn arb_vulnerability(owasp: Option<OwaspCategory>, severity: Severity) -> Vulnerability {
        Vulnerability {
            id: Uuid::new_v4(),
            rule_id: "test-rule".to_string(),
            file_path: PathBuf::from("src/main.rs"),
            line: 1,
            column: 1,
            snippet: "unsafe_call()".to_string(),
            severity,
            reachable: true,
            cloud_exposed: None,
            cwe_id: None,
            owasp_category: owasp,
        }
    }

    fn arb_vuln_strategy() -> impl Strategy<Value = Vulnerability> {
        (arb_optional_owasp(), arb_severity())
            .prop_map(|(owasp, severity)| arb_vulnerability(owasp, severity))
    }

    // ── Property 36: OWASP category mapping consistency ──────────────────────
    //
    // Feature: sicario-cli-core, Property 36: OWASP category mapping consistency
    // Validates: Requirements 17.1, 17.2

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        /// For any set of vulnerabilities, the compliance report must always
        /// contain exactly 10 OWASP Top 10 categories.
        ///
        /// Feature: sicario-cli-core, Property 36: OWASP category mapping consistency
        /// Validates: Requirements 17.1, 17.2
        #[test]
        fn prop36_report_always_contains_all_10_categories(
            vulns in proptest::collection::vec(arb_vuln_strategy(), 0..=50),
        ) {
            let report = generate_compliance_report(&vulns);

            prop_assert_eq!(
                report.categories.len(),
                10,
                "Compliance report must always contain exactly 10 OWASP categories, \
                 got {} with {} input vulnerabilities",
                report.categories.len(),
                vulns.len()
            );
        }

        /// For any set of vulnerabilities, the total count in the report must
        /// equal the number of input vulnerabilities (categorized + uncategorized).
        ///
        /// Feature: sicario-cli-core, Property 36: OWASP category mapping consistency
        /// Validates: Requirements 17.1, 17.2
        #[test]
        fn prop36_total_count_equals_input_count(
            vulns in proptest::collection::vec(arb_vuln_strategy(), 0..=50),
        ) {
            let report = generate_compliance_report(&vulns);

            let sum_in_categories: usize = report.categories.iter().map(|c| c.total).sum();
            let total_accounted = sum_in_categories + report.uncategorized;

            prop_assert_eq!(
                total_accounted,
                vulns.len(),
                "Sum of category totals ({}) + uncategorized ({}) must equal \
                 input count ({})",
                sum_in_categories,
                report.uncategorized,
                vulns.len()
            );

            prop_assert_eq!(
                report.total_vulnerabilities,
                vulns.len(),
                "report.total_vulnerabilities must equal input count"
            );
        }

        /// For any vulnerability with an assigned OWASP category, it must appear
        /// in the correct category bucket in the compliance report — not in any
        /// other category and not in uncategorized.
        ///
        /// Feature: sicario-cli-core, Property 36: OWASP category mapping consistency
        /// Validates: Requirements 17.1, 17.2
        #[test]
        fn prop36_categorized_vulns_land_in_correct_bucket(
            category in arb_owasp_category(),
            severity in arb_severity(),
            extra_count in 0usize..=10usize,
        ) {
            // Build a list: one vuln with a known category + some uncategorized
            let mut vulns: Vec<Vulnerability> = (0..extra_count)
                .map(|_| arb_vulnerability(None, Severity::Low))
                .collect();
            vulns.push(arb_vulnerability(Some(category), severity));

            let report = generate_compliance_report(&vulns);

            let category_key = format!("{:?}", category);
            let bucket = report
                .categories
                .iter()
                .find(|c| c.category == category_key)
                .expect("Category bucket must exist in report");

            prop_assert!(
                bucket.total >= 1,
                "Category {:?} must have at least 1 finding after inserting one vuln",
                category
            );

            // Uncategorized count must equal extra_count (all extras have None)
            prop_assert_eq!(
                report.uncategorized,
                extra_count,
                "Uncategorized count must equal the number of None-category vulns"
            );
        }

        /// For any vulnerability with an assigned OWASP category, the severity
        /// breakdown in the report must accurately reflect the input severity.
        ///
        /// Feature: sicario-cli-core, Property 36: OWASP category mapping consistency
        /// Validates: Requirements 17.1, 17.2
        #[test]
        fn prop36_severity_counts_are_accurate(
            category in arb_owasp_category(),
            severity in arb_severity(),
        ) {
            let vuln = arb_vulnerability(Some(category), severity);
            let report = generate_compliance_report(&[vuln]);

            let category_key = format!("{:?}", category);
            let bucket = report
                .categories
                .iter()
                .find(|c| c.category == category_key)
                .unwrap();

            // Exactly one finding in the correct severity slot
            let (critical, high, medium, low, info) = (
                bucket.critical,
                bucket.high,
                bucket.medium,
                bucket.low,
                bucket.info,
            );

            match severity {
                Severity::Critical => prop_assert_eq!(critical, 1, "Critical count must be 1"),
                Severity::High     => prop_assert_eq!(high, 1,     "High count must be 1"),
                Severity::Medium   => prop_assert_eq!(medium, 1,   "Medium count must be 1"),
                Severity::Low      => prop_assert_eq!(low, 1,      "Low count must be 1"),
                Severity::Info     => prop_assert_eq!(info, 1,     "Info count must be 1"),
            }

            prop_assert_eq!(bucket.total, 1, "Total for category must be 1");
        }

        /// For any set of vulnerabilities, group_by_owasp() must return groups
        /// in canonical OWASP order (A01 before A02, ..., A09 before A10).
        ///
        /// Feature: sicario-cli-core, Property 36: OWASP category mapping consistency
        /// Validates: Requirements 17.1, 17.2
        #[test]
        fn prop36_group_by_owasp_preserves_canonical_order(
            vulns in proptest::collection::vec(arb_vuln_strategy(), 1..=30),
        ) {
            let groups = group_by_owasp(&vulns);

            // Verify the returned groups are in canonical OWASP order
            let canonical_order: Vec<String> = ALL_OWASP_CATEGORIES
                .iter()
                .map(|&c| format!("{:?}", c))
                .collect();

            let mut last_index = 0usize;
            for (cat, _) in &groups {
                let cat_key = format!("{:?}", cat);
                let pos = canonical_order
                    .iter()
                    .position(|k| k == &cat_key)
                    .expect("Returned category must be a valid OWASP category");

                prop_assert!(
                    pos >= last_index,
                    "group_by_owasp must return categories in canonical order. \
                     Got {:?} (pos {}) after position {}",
                    cat, pos, last_index
                );
                last_index = pos;
            }
        }

        /// For any set of vulnerabilities, the compliance report must serialise
        /// to valid JSON that round-trips back to an equivalent report.
        ///
        /// Feature: sicario-cli-core, Property 36: OWASP category mapping consistency
        /// Validates: Requirements 17.1, 17.2
        #[test]
        fn prop36_compliance_report_json_round_trip(
            vulns in proptest::collection::vec(arb_vuln_strategy(), 0..=30),
        ) {
            let report = generate_compliance_report(&vulns);
            let json = report_to_json(&report).expect("Report must serialise to JSON");
            let back: crate::reporting::owasp_report::ComplianceReport =
                serde_json::from_str(&json).expect("JSON must deserialise back to ComplianceReport");

            prop_assert_eq!(
                back.total_vulnerabilities,
                report.total_vulnerabilities,
                "Round-trip must preserve total_vulnerabilities"
            );
            prop_assert_eq!(
                back.categories_affected,
                report.categories_affected,
                "Round-trip must preserve categories_affected"
            );
            prop_assert_eq!(
                back.uncategorized,
                report.uncategorized,
                "Round-trip must preserve uncategorized count"
            );
            prop_assert_eq!(
                back.categories.len(),
                10,
                "Round-trip must preserve all 10 category entries"
            );
        }

        /// For any set of vulnerabilities, the Markdown report must contain
        /// labels for all 10 OWASP Top 10 categories.
        ///
        /// Feature: sicario-cli-core, Property 36: OWASP category mapping consistency
        /// Validates: Requirements 17.1, 17.2
        #[test]
        fn prop36_markdown_report_contains_all_owasp_labels(
            vulns in proptest::collection::vec(arb_vuln_strategy(), 0..=20),
        ) {
            let report = generate_compliance_report(&vulns);
            let md = report_to_markdown(&report);

            for i in 1..=10 {
                let label = format!("A{:02}:2021", i);
                prop_assert!(
                    md.contains(&label),
                    "Markdown report must contain OWASP label '{}' but it was missing",
                    label
                );
            }
        }
    }

    // ── Property 37: OWASP compliance report completeness ────────────────────
    //
    // Feature: sicario-cli-core, Property 37: OWASP compliance report completeness
    //
    // For any scan that detects vulnerabilities across multiple OWASP categories,
    // the compliance report should accurately group and count findings by category,
    // covering all applicable OWASP Top 10 2021 categories.
    //
    // Validates: Requirements 17.3, 17.4, 17.5

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        /// For any multi-category vulnerability set, per-category totals in the
        /// report must exactly match the number of vulnerabilities assigned to
        /// each category in the input.
        ///
        /// Feature: sicario-cli-core, Property 37: OWASP compliance report completeness
        /// Validates: Requirements 17.3, 17.4, 17.5
        #[test]
        fn prop37_per_category_totals_match_input(
            vulns in proptest::collection::vec(arb_vuln_strategy(), 0..=60),
        ) {
            // Count expected totals per category from the input
            let mut expected: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            for v in &vulns {
                if let Some(cat) = v.owasp_category {
                    *expected.entry(format!("{:?}", cat)).or_insert(0) += 1;
                }
            }

            let report = generate_compliance_report(&vulns);

            for cat_report in &report.categories {
                let exp = expected.get(&cat_report.category).copied().unwrap_or(0);
                prop_assert_eq!(
                    cat_report.total,
                    exp,
                    "Category {} total ({}) must match expected count ({})",
                    cat_report.category,
                    cat_report.total,
                    exp
                );
            }
        }

        /// For any vulnerability set spanning multiple distinct OWASP categories,
        /// categories_affected must equal the number of distinct categories present
        /// in the input.
        ///
        /// Feature: sicario-cli-core, Property 37: OWASP compliance report completeness
        /// Validates: Requirements 17.3, 17.4, 17.5
        #[test]
        fn prop37_categories_affected_equals_distinct_categories(
            vulns in proptest::collection::vec(arb_vuln_strategy(), 0..=50),
        ) {
            let distinct: std::collections::HashSet<String> = vulns
                .iter()
                .filter_map(|v| v.owasp_category.map(|c| format!("{:?}", c)))
                .collect();

            let report = generate_compliance_report(&vulns);

            prop_assert_eq!(
                report.categories_affected,
                distinct.len(),
                "categories_affected ({}) must equal the number of distinct OWASP \
                 categories in the input ({})",
                report.categories_affected,
                distinct.len()
            );
        }

        /// For any vulnerability set, the JSON export must contain an entry for
        /// every OWASP Top 10 category, including those with zero findings, so
        /// that compliance tooling can always rely on a complete 10-entry report.
        ///
        /// Feature: sicario-cli-core, Property 37: OWASP compliance report completeness
        /// Validates: Requirements 17.3, 17.4, 17.5
        #[test]
        fn prop37_json_export_contains_all_10_categories(
            vulns in proptest::collection::vec(arb_vuln_strategy(), 0..=30),
        ) {
            let report = generate_compliance_report(&vulns);
            let json = report_to_json(&report).expect("report_to_json must succeed");
            let value: serde_json::Value =
                serde_json::from_str(&json).expect("JSON must be valid");

            let categories = value["categories"]
                .as_array()
                .expect("'categories' must be a JSON array");

            prop_assert_eq!(
                categories.len(),
                10,
                "JSON export must contain exactly 10 category entries, got {}",
                categories.len()
            );

            // Every canonical category key must appear in the JSON
            for &cat in &ALL_OWASP_CATEGORIES {
                let key = format!("{:?}", cat);
                let found = categories
                    .iter()
                    .any(|c| c["category"].as_str() == Some(&key));
                prop_assert!(
                    found,
                    "JSON export must contain an entry for category '{}' but it was missing",
                    key
                );
            }
        }

        /// For any vulnerability set, the Markdown export must include a table row
        /// for every OWASP Top 10 category, and the total count shown in the
        /// summary header must equal the number of input vulnerabilities.
        ///
        /// Feature: sicario-cli-core, Property 37: OWASP compliance report completeness
        /// Validates: Requirements 17.3, 17.4, 17.5
        #[test]
        fn prop37_markdown_export_completeness(
            vulns in proptest::collection::vec(arb_vuln_strategy(), 0..=40),
        ) {
            let report = generate_compliance_report(&vulns);
            let md = report_to_markdown(&report);

            // All 10 OWASP category labels must appear in the Markdown table
            for &cat in &ALL_OWASP_CATEGORIES {
                let label_fragment = format!("A{:02}:2021", {
                    // Extract the numeric part from the category key
                    let key = format!("{:?}", cat);
                    // e.g. "A01_BrokenAccessControl" → "01"
                    key.trim_start_matches('A')
                        .chars()
                        .take(2)
                        .collect::<String>()
                        .parse::<u8>()
                        .unwrap_or(0)
                });
                prop_assert!(
                    md.contains(&label_fragment),
                    "Markdown must contain label fragment '{}' for category {:?}",
                    label_fragment,
                    cat
                );
            }

            // The total vulnerability count must appear in the header
            let total_str = format!("**Total vulnerabilities:** {}", vulns.len());
            prop_assert!(
                md.contains(&total_str),
                "Markdown header must show total count '{}' but got:\n{}",
                total_str,
                &md[..md.len().min(300)]
            );
        }

        /// For any vulnerability set, the sum of all per-category severity
        /// sub-counts (critical + high + medium + low + info) must equal the
        /// category total, ensuring no severity is double-counted or lost.
        ///
        /// Feature: sicario-cli-core, Property 37: OWASP compliance report completeness
        /// Validates: Requirements 17.3, 17.4, 17.5
        #[test]
        fn prop37_severity_subcounts_sum_to_category_total(
            vulns in proptest::collection::vec(arb_vuln_strategy(), 0..=50),
        ) {
            let report = generate_compliance_report(&vulns);

            for cat in &report.categories {
                let subcount_sum = cat.critical + cat.high + cat.medium + cat.low + cat.info;
                prop_assert_eq!(
                    subcount_sum,
                    cat.total,
                    "For category {}: critical({}) + high({}) + medium({}) + low({}) + \
                     info({}) = {} must equal total ({})",
                    cat.category,
                    cat.critical, cat.high, cat.medium, cat.low, cat.info,
                    subcount_sum,
                    cat.total
                );
            }
        }

        /// For any vulnerability set where every vulnerability has an OWASP
        /// category assigned, uncategorized must be zero.
        ///
        /// Feature: sicario-cli-core, Property 37: OWASP compliance report completeness
        /// Validates: Requirements 17.3, 17.4, 17.5
        #[test]
        fn prop37_fully_categorized_input_has_zero_uncategorized(
            entries in proptest::collection::vec(
                (arb_owasp_category(), arb_severity()),
                0..=40,
            ),
        ) {
            let vulns: Vec<Vulnerability> = entries
                .into_iter()
                .map(|(cat, sev)| arb_vulnerability(Some(cat), sev))
                .collect();

            let report = generate_compliance_report(&vulns);

            prop_assert_eq!(
                report.uncategorized,
                0,
                "When all vulnerabilities have an OWASP category, uncategorized must be 0"
            );
        }

        /// For any vulnerability set where no vulnerability has an OWASP category,
        /// all per-category totals must be zero and uncategorized must equal the
        /// total input count.
        ///
        /// Feature: sicario-cli-core, Property 37: OWASP compliance report completeness
        /// Validates: Requirements 17.3, 17.4, 17.5
        #[test]
        fn prop37_fully_uncategorized_input_has_zero_category_totals(
            severities in proptest::collection::vec(arb_severity(), 0..=30),
        ) {
            let vulns: Vec<Vulnerability> = severities
                .iter()
                .map(|&sev| arb_vulnerability(None, sev))
                .collect();

            let report = generate_compliance_report(&vulns);

            prop_assert_eq!(
                report.uncategorized,
                vulns.len(),
                "When no vulnerability has an OWASP category, uncategorized must equal input count"
            );

            for cat in &report.categories {
                prop_assert_eq!(
                    cat.total,
                    0,
                    "Category {} total must be 0 when all inputs are uncategorized",
                    cat.category
                );
            }
        }
    }
}

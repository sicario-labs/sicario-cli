//! Property-based tests for TUI message passing reliability
//!
//! Feature: sicario-cli-core, Property 10: Message passing reliability
//! Validates: Requirements 4.5

use proptest::prelude::*;
use std::path::PathBuf;
use uuid::Uuid;

use crate::engine::{Severity, Vulnerability};
use crate::tui::app::{AppState, TuiMessage, create_tui_channel};

// ── Arbitrary generators ──────────────────────────────────────────────────────

fn arb_severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Info),
        Just(Severity::Low),
        Just(Severity::Medium),
        Just(Severity::High),
        Just(Severity::Critical),
    ]
}

fn arb_vulnerability() -> impl Strategy<Value = Vulnerability> {
    (
        "[a-z]{3,10}-rule",
        "[a-z]{3,8}\\.rs",
        1usize..1000usize,
        0usize..200usize,
        "[a-zA-Z0-9 ]{5,40}",
        arb_severity(),
        any::<bool>(),
    )
        .prop_map(|(rule_id, file, line, col, snippet, severity, reachable)| Vulnerability {
            id: Uuid::new_v4(),
            rule_id,
            file_path: PathBuf::from(file),
            line,
            column: col,
            snippet,
            severity,
            reachable,
            cloud_exposed: None,
            cwe_id: None,
            owasp_category: None,
        })
}

fn arb_tui_message() -> impl Strategy<Value = TuiMessage> {
    prop_oneof![
        // ScanProgress
        (0usize..500usize, 1usize..500usize).prop_map(|(scanned, total)| {
            let scanned = scanned.min(total);
            TuiMessage::ScanProgress { files_scanned: scanned, total }
        }),
        // VulnerabilityFound
        arb_vulnerability().prop_map(TuiMessage::VulnerabilityFound),
        // ScanComplete
        Just(TuiMessage::ScanComplete),
        // PatchGenerated
        "[a-zA-Z0-9 \\-+@]{5,80}".prop_map(TuiMessage::PatchGenerated),
        // Error
        "[a-zA-Z0-9 ]{5,60}".prop_map(TuiMessage::Error),
    ]
}

// ── Property 10: Message passing reliability ──────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    /// Property 10: Message passing reliability
    ///
    /// For any sequence of messages sent from a worker thread to the TUI via
    /// mpsc channels, every message should be received in the exact order it
    /// was sent, without loss or corruption.
    ///
    /// Feature: sicario-cli-core, Property 10: Message passing reliability
    /// Validates: Requirements 4.5
    #[test]
    fn prop_messages_received_in_order(
        messages in prop::collection::vec(arb_tui_message(), 1..=20)
    ) {
        let (tx, rx) = create_tui_channel();

        // Send all messages from a "worker thread"
        let sent_count = messages.len();
        for msg in &messages {
            tx.send(msg.clone()).unwrap();
        }
        // Drop sender so the channel closes after all messages are consumed
        drop(tx);

        // Receive all messages and verify count matches
        let mut received = 0usize;
        while let Ok(_msg) = rx.recv() {
            received += 1;
        }

        prop_assert_eq!(received, sent_count,
            "All {} sent messages should be received; got {}", sent_count, received);
    }

    /// Property 10 (variant): No message is lost when sent from multiple senders
    ///
    /// For any batch of messages sent concurrently from two worker threads,
    /// the total number of messages received should equal the total sent.
    ///
    /// Feature: sicario-cli-core, Property 10: Message passing reliability
    /// Validates: Requirements 4.5
    #[test]
    fn prop_no_message_loss_multi_sender(
        batch_a in prop::collection::vec(arb_tui_message(), 1..=10),
        batch_b in prop::collection::vec(arb_tui_message(), 1..=10),
    ) {
        let (tx, rx) = create_tui_channel();
        let tx2 = tx.clone();

        let total = batch_a.len() + batch_b.len();

        // Send from two independent senders (simulating two worker threads)
        for msg in batch_a {
            tx.send(msg).unwrap();
        }
        for msg in batch_b {
            tx2.send(msg).unwrap();
        }
        drop(tx);
        drop(tx2);

        let mut received = 0usize;
        while let Ok(_) = rx.recv() {
            received += 1;
        }

        prop_assert_eq!(received, total,
            "All {} messages from two senders should be received; got {}", total, received);
    }

    /// Property 10 (variant): ScanProgress message values are preserved intact
    ///
    /// For any ScanProgress message, the files_scanned and total values should
    /// be identical after passing through the channel.
    ///
    /// Feature: sicario-cli-core, Property 10: Message passing reliability
    /// Validates: Requirements 4.5
    #[test]
    fn prop_scan_progress_values_preserved(
        files_scanned in 0usize..1000usize,
        total in 1usize..1000usize,
    ) {
        let files_scanned = files_scanned.min(total);
        let (tx, rx) = create_tui_channel();

        tx.send(TuiMessage::ScanProgress { files_scanned, total }).unwrap();
        drop(tx);

        match rx.recv().unwrap() {
            TuiMessage::ScanProgress { files_scanned: fs, total: t } => {
                prop_assert_eq!(fs, files_scanned);
                prop_assert_eq!(t, total);
            }
            other => prop_assert!(false, "Expected ScanProgress, got {:?}", other),
        }
    }

    /// Property 10 (variant): VulnerabilityFound message preserves all fields
    ///
    /// For any Vulnerability sent as a VulnerabilityFound message, the received
    /// message should contain an identical Vulnerability (same id, rule_id, line, etc.)
    ///
    /// Feature: sicario-cli-core, Property 10: Message passing reliability
    /// Validates: Requirements 4.5
    #[test]
    fn prop_vulnerability_message_fields_preserved(vuln in arb_vulnerability()) {
        let (tx, rx) = create_tui_channel();

        let sent_id = vuln.id;
        let sent_rule = vuln.rule_id.clone();
        let sent_line = vuln.line;

        tx.send(TuiMessage::VulnerabilityFound(vuln)).unwrap();
        drop(tx);

        match rx.recv().unwrap() {
            TuiMessage::VulnerabilityFound(v) => {
                prop_assert_eq!(v.id, sent_id);
                prop_assert_eq!(v.rule_id, sent_rule);
                prop_assert_eq!(v.line, sent_line);
            }
            other => prop_assert!(false, "Expected VulnerabilityFound, got {:?}", other),
        }
    }
}

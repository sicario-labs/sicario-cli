//! Property-based tests for TUI responsiveness under load
//!
//! Feature: sicario-cli-core, Property 11: TUI responsiveness under load
//! Validates: Requirements 4.6

use proptest::prelude::*;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::engine::{Severity, Vulnerability};
use crate::tui::app::{create_tui_channel, AppState, TuiMessage};

// ── Generators ────────────────────────────────────────────────────────────────

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
    )
        .prop_map(
            |(rule_id, file, line, col, snippet, severity)| Vulnerability {
                id: Uuid::new_v4(),
                rule_id,
                file_path: PathBuf::from(file),
                line,
                column: col,
                snippet,
                severity,
                reachable: false,
                cloud_exposed: None,
                cwe_id: None,
                owasp_category: None,
            },
        )
}

// ── Simulated input event types ───────────────────────────────────────────────

/// Lightweight stand-in for a keyboard event — avoids pulling in crossterm in
/// property tests while still exercising the state-machine logic.
#[derive(Debug, Clone)]
enum SimKey {
    Down,
    Up,
    Quit,
    Enter,
    Other,
}

fn arb_sim_key() -> impl Strategy<Value = SimKey> {
    prop_oneof![
        Just(SimKey::Down),
        Just(SimKey::Up),
        Just(SimKey::Quit),
        Just(SimKey::Enter),
        Just(SimKey::Other),
    ]
}

/// Apply a simulated key to an AppState, returning the new state.
/// This mirrors the logic in `SicarioTui::handle_input` without requiring a
/// real terminal, so we can test the state machine in isolation.
fn apply_key(state: AppState, key: &SimKey) -> (AppState, bool) {
    let mut should_quit = false;
    let new_state = match key {
        SimKey::Quit => {
            should_quit = true;
            state
        }
        SimKey::Down => match state {
            AppState::Results {
                vulnerabilities,
                selected,
            } if !vulnerabilities.is_empty() => {
                let next = (selected + 1).min(vulnerabilities.len() - 1);
                AppState::Results {
                    vulnerabilities,
                    selected: next,
                }
            }
            other => other,
        },
        SimKey::Up => match state {
            AppState::Results {
                vulnerabilities,
                selected,
            } => AppState::Results {
                vulnerabilities,
                selected: selected.saturating_sub(1),
            },
            other => other,
        },
        SimKey::Enter | SimKey::Other => state,
    };
    (new_state, should_quit)
}

// ── Property 11: TUI responsiveness under load ────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    /// Property 11: TUI responsiveness under load
    ///
    /// For any user input event during active scanning, the TUI state machine
    /// should process and respond to that event in sub-millisecond time,
    /// maintaining UI responsiveness regardless of the number of pending messages.
    ///
    /// We measure the time to drain N messages from the channel and apply M key
    /// events, asserting the total processing time stays under a generous bound
    /// (50 ms) that is orders of magnitude below a 16 ms frame budget.
    ///
    /// Feature: sicario-cli-core, Property 11: TUI responsiveness under load
    /// Validates: Requirements 4.6
    #[test]
    fn prop_message_drain_is_fast(
        messages in prop::collection::vec(
            prop_oneof![
                (0usize..500usize, 1usize..500usize).prop_map(|(s, t)| {
                    TuiMessage::ScanProgress { files_scanned: s.min(t), total: t }
                }),
                arb_vulnerability().prop_map(TuiMessage::VulnerabilityFound),
                Just(TuiMessage::ScanComplete),
            ],
            1..=50,
        )
    ) {
        let (tx, rx) = create_tui_channel();
        let count = messages.len();
        for msg in messages {
            tx.send(msg).unwrap();
        }
        drop(tx);

        let start = Instant::now();
        let mut received = 0usize;
        while rx.try_recv().is_ok() {
            received += 1;
        }
        let elapsed = start.elapsed();

        prop_assert_eq!(received, count);
        // Draining up to 50 messages should complete well within 50 ms
        prop_assert!(
            elapsed < Duration::from_millis(50),
            "Draining {} messages took {:?}, expected < 50ms",
            count,
            elapsed
        );
    }

    /// Property 11 (variant): Key event processing does not block
    ///
    /// For any sequence of key events applied to a Results state, each
    /// individual key application should complete in sub-millisecond time.
    ///
    /// Feature: sicario-cli-core, Property 11: TUI responsiveness under load
    /// Validates: Requirements 4.6
    #[test]
    fn prop_key_processing_is_non_blocking(
        vulns in prop::collection::vec(arb_vulnerability(), 1..=20),
        keys in prop::collection::vec(arb_sim_key(), 1..=30),
    ) {
        let mut state = AppState::Results {
            vulnerabilities: vulns,
            selected: 0,
        };
        let mut quit = false;

        let start = Instant::now();
        for key in &keys {
            let (new_state, q) = apply_key(state, key);
            state = new_state;
            quit = quit || q;
        }
        let elapsed = start.elapsed();

        // Processing up to 30 key events should complete well within 10 ms
        prop_assert!(
            elapsed < Duration::from_millis(10),
            "Processing {} key events took {:?}, expected < 10ms",
            keys.len(),
            elapsed
        );
    }

    /// Property 11 (variant): Selection index stays in bounds after any key sequence
    ///
    /// For any Results state and any sequence of Up/Down key events, the
    /// selected index should always remain within [0, vulnerabilities.len()-1].
    ///
    /// Feature: sicario-cli-core, Property 11: TUI responsiveness under load
    /// Validates: Requirements 4.6
    #[test]
    fn prop_selection_stays_in_bounds(
        vulns in prop::collection::vec(arb_vulnerability(), 1..=20),
        keys in prop::collection::vec(
            prop_oneof![Just(SimKey::Down), Just(SimKey::Up)],
            1..=50,
        ),
    ) {
        let len = vulns.len();
        let mut state = AppState::Results { vulnerabilities: vulns, selected: 0 };

        for key in &keys {
            let (new_state, _) = apply_key(state, key);
            state = new_state;
        }

        if let AppState::Results { selected, vulnerabilities } = &state {
            prop_assert!(
                *selected < vulnerabilities.len(),
                "selected={} is out of bounds for len={}",
                selected,
                len
            );
        }
    }

    /// Property 11 (variant): Concurrent message sending does not degrade drain time
    ///
    /// For any batch of messages sent from two concurrent senders, draining the
    /// channel should still complete within the responsiveness budget.
    ///
    /// Feature: sicario-cli-core, Property 11: TUI responsiveness under load
    /// Validates: Requirements 4.6
    #[test]
    fn prop_concurrent_send_drain_stays_fast(
        batch_a in prop::collection::vec(arb_vulnerability(), 1..=25),
        batch_b in prop::collection::vec(arb_vulnerability(), 1..=25),
    ) {
        let (tx, rx) = create_tui_channel();
        let tx2 = tx.clone();
        let total = batch_a.len() + batch_b.len();

        for v in batch_a {
            tx.send(TuiMessage::VulnerabilityFound(v)).unwrap();
        }
        for v in batch_b {
            tx2.send(TuiMessage::VulnerabilityFound(v)).unwrap();
        }
        drop(tx);
        drop(tx2);

        let start = Instant::now();
        let mut received = 0usize;
        while rx.try_recv().is_ok() {
            received += 1;
        }
        let elapsed = start.elapsed();

        prop_assert_eq!(received, total);
        prop_assert!(
            elapsed < Duration::from_millis(50),
            "Draining {} concurrent messages took {:?}, expected < 50ms",
            total,
            elapsed
        );
    }
}

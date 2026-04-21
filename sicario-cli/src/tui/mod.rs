//! Terminal User Interface module
//!
//! Provides a responsive, visually rich TUI using Ratatui.

pub mod app;
pub mod events;
pub mod ui;
pub mod worker;

#[cfg(test)]
mod message_passing_tests;

#[cfg(test)]
mod responsiveness_tests;

pub use app::{create_tui_channel, AppState, SicarioTui, TuiMessage};
pub use worker::{spawn_scan_worker, ScanJob};

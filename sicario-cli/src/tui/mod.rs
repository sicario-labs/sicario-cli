//! Terminal User Interface module
//!
//! Provides a responsive, visually rich TUI using Ratatui.

pub mod app;
pub mod ui;
pub mod events;
pub mod worker;

#[cfg(test)]
mod message_passing_tests;

#[cfg(test)]
mod responsiveness_tests;

pub use app::{AppState, SicarioTui, TuiMessage, create_tui_channel};
pub use worker::{ScanJob, spawn_scan_worker};

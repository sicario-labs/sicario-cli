//! Proof-of-Concept (PoC) generation module.
//!
//! Activated by `--prove` on `sicario scan`. Generates safe, localhost-only
//! exploit payloads for confirmed findings to help developers verify
//! vulnerabilities in controlled environments.
//!
//! # Safety Invariants
//! - All generated URLs must resolve to `127.0.0.1` or `::1` only.
//! - No destructive SQL keywords (`DROP`, `DELETE`, `TRUNCATE`, `UPDATE`,
//!   `INSERT`, `ALTER`) are ever included in generated payloads.
//! - `SsrfProbeListener` is inbound-only — no outbound network requests.

pub mod generator;

pub use generator::{PocGenerator, PocPayload, SsrfProbeListener};

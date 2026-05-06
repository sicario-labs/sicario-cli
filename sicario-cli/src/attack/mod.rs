//! Shadow Pen-Tester (`sicario attack --local`) module.
//!
//! This module provides AST-based route discovery, payload generation,
//! and HTTP execution for local penetration testing against localhost targets.
//!
//! # Safety Invariants
//! 1. All attack targets must resolve to `127.0.0.1` or `::1` (localhost only).
//! 2. No destructive SQL keywords (`DROP`, `DELETE`, `TRUNCATE`, `UPDATE`,
//!    `INSERT`, `ALTER`) are ever included in generated payloads.
//! 3. All HTTP requests are sequential (not parallel) to preserve timing accuracy.

pub mod payload_generator;
pub mod route_extractor;
pub mod runner;

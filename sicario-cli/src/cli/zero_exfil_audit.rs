//! CLI arguments for the `sicario audit` subcommand.
//!
//! `sicario audit show` — print human-readable summary of most recent audit log.
//! `sicario audit verify` — assert no unauthorized LLM transmissions.
//! `sicario audit suppression` — scan directory for all `sicario-ignore` comments,
//!   report file/line/rule/committer (Task 52.6).
//!
//! Requirements: Req 21 — Zero-Exfiltration Audit Log (Tasks 21.4, 21.5)
//!               Req 52 — Inline Suppression Comments (Task 52.6)

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
pub struct AuditCommand {
    #[command(subcommand)]
    pub action: AuditAction,
}

#[derive(Subcommand, Debug)]
pub enum AuditAction {
    /// Print human-readable summary of the most recent audit log entry.
    Show,
    /// Assert no unauthorized LLM transmissions across all audit log entries.
    /// Exits 1 if any finding_metadata entry has lines_of_code_transmitted > 0
    /// without explicit --publish-with-snippet consent.
    Verify,
    /// Scan directory for all `sicario-ignore` comments and report
    /// file, line, rule ID, and git committer attribution (Task 52.6).
    Suppression(SuppressionAuditArgs),
}

/// Arguments for `sicario audit suppression`.
#[derive(Parser, Debug)]
pub struct SuppressionAuditArgs {
    /// Directory to scan for suppression comments (default: current directory)
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: String,

    /// Output format
    #[arg(long, value_enum, default_value = "text")]
    pub format: SuppressionAuditFormat,

    /// Filter by author email (git blame attribution)
    #[arg(long)]
    pub author: Option<String>,
}

/// Output format for `sicario audit suppression`.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SuppressionAuditFormat {
    Text,
    Json,
    Csv,
}

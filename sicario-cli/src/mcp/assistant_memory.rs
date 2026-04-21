//! Assistant Memory — stores historical triage decisions in a local SQLite
//! database so the MCP server can autonomously dismiss previously approved
//! vulnerability patterns in future scans.
//!
//! Requirements: 6.5

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, info};

/// A triage decision recorded by the developer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriageDecision {
    /// The developer approved (dismissed) this finding as a false positive.
    Approved,
    /// The developer confirmed this as a real vulnerability.
    Confirmed,
}

impl TriageDecision {
    fn as_str(&self) -> &'static str {
        match self {
            TriageDecision::Approved => "approved",
            TriageDecision::Confirmed => "confirmed",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "approved" => Some(TriageDecision::Approved),
            "confirmed" => Some(TriageDecision::Confirmed),
            _ => None,
        }
    }
}

/// A historical triage record.
#[derive(Debug, Clone)]
pub struct TriageRecord {
    pub rule_id: String,
    /// Normalised code snippet (trimmed, whitespace-collapsed).
    pub snippet_hash: String,
    pub decision: TriageDecision,
    pub created_at: String,
}

/// Persistent store for triage decisions.
///
/// Uses an embedded SQLite database so decisions survive across CLI invocations.
pub struct AssistantMemory {
    conn: Mutex<Connection>,
}

impl AssistantMemory {
    /// Open (or create) the Assistant Memory database at `db_path`.
    pub fn new(db_path: &Path) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {:?}", parent))?;
        }

        let conn = Connection::open(db_path)
            .with_context(|| format!("Failed to open Assistant Memory DB at {:?}", db_path))?;

        // Enable WAL mode for concurrent access
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        // Create schema
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS triage_decisions (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id       TEXT    NOT NULL,
                snippet_hash  TEXT    NOT NULL,
                decision      TEXT    NOT NULL CHECK(decision IN ('approved','confirmed')),
                created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
                UNIQUE(rule_id, snippet_hash)
            );
            CREATE INDEX IF NOT EXISTS idx_triage_rule_snippet
                ON triage_decisions(rule_id, snippet_hash);",
        )
        .context("Failed to create Assistant Memory schema")?;

        info!("Assistant Memory initialised at {:?}", db_path);

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create an in-memory database (useful for tests).
    pub fn in_memory() -> Result<Self> {
        let conn =
            Connection::open_in_memory().context("Failed to open in-memory Assistant Memory DB")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS triage_decisions (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id       TEXT    NOT NULL,
                snippet_hash  TEXT    NOT NULL,
                decision      TEXT    NOT NULL CHECK(decision IN ('approved','confirmed')),
                created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
                UNIQUE(rule_id, snippet_hash)
            );
            CREATE INDEX IF NOT EXISTS idx_triage_rule_snippet
                ON triage_decisions(rule_id, snippet_hash);",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Record a triage decision for a (rule_id, snippet) pair.
    ///
    /// If a decision already exists for this pair it is updated (upsert).
    pub fn record_decision(
        &self,
        rule_id: &str,
        snippet: &str,
        decision: TriageDecision,
    ) -> Result<()> {
        let hash = normalise_snippet(snippet);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO triage_decisions (rule_id, snippet_hash, decision)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(rule_id, snippet_hash) DO UPDATE SET
                 decision   = excluded.decision,
                 created_at = datetime('now')",
            params![rule_id, hash, decision.as_str()],
        )
        .context("Failed to record triage decision")?;

        debug!(
            "Recorded triage decision {:?} for rule '{}' snippet hash '{}'",
            decision, rule_id, hash
        );
        Ok(())
    }

    /// Return `true` if the (rule_id, snippet) pair has been previously approved
    /// (i.e. dismissed as a false positive).
    pub fn is_approved(&self, rule_id: &str, snippet: &str) -> bool {
        let hash = normalise_snippet(snippet);
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT decision FROM triage_decisions
             WHERE rule_id = ?1 AND snippet_hash = ?2",
            params![rule_id, hash],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|d| TriageDecision::from_str(&d))
        .map(|d| d == TriageDecision::Approved)
        .unwrap_or(false)
    }

    /// Return all triage records for a given rule ID.
    pub fn get_decisions_for_rule(&self, rule_id: &str) -> Result<Vec<TriageRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT rule_id, snippet_hash, decision, created_at
             FROM triage_decisions
             WHERE rule_id = ?1
             ORDER BY created_at DESC",
        )?;

        let records = stmt
            .query_map(params![rule_id], |row| {
                let decision_str: String = row.get(2)?;
                let decision = match decision_str.as_str() {
                    "approved" => TriageDecision::Approved,
                    _ => TriageDecision::Confirmed,
                };
                Ok(TriageRecord {
                    rule_id: row.get(0)?,
                    snippet_hash: row.get(1)?,
                    decision,
                    created_at: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Failed to query triage decisions")?;

        Ok(records)
    }

    /// Return the total number of stored triage decisions.
    pub fn count(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM triage_decisions", [], |row| {
            row.get(0)
        })?;
        Ok(n as usize)
    }

    /// Clear all triage decisions (useful for testing).
    pub fn clear(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM triage_decisions", [])?;
        Ok(())
    }
}

/// Normalise a code snippet for stable hashing:
/// - Trim leading/trailing whitespace
/// - Collapse internal whitespace runs to a single space
fn normalise_snippet(snippet: &str) -> String {
    snippet.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> AssistantMemory {
        AssistantMemory::in_memory().unwrap()
    }

    #[test]
    fn test_record_and_query_approved() {
        let m = mem();
        m.record_decision(
            "sql-injection",
            "SELECT * FROM users WHERE id = 'x'",
            TriageDecision::Approved,
        )
        .unwrap();
        assert!(m.is_approved("sql-injection", "SELECT * FROM users WHERE id = 'x'"));
    }

    #[test]
    fn test_confirmed_is_not_approved() {
        let m = mem();
        m.record_decision("xss", "innerHTML = userInput", TriageDecision::Confirmed)
            .unwrap();
        assert!(!m.is_approved("xss", "innerHTML = userInput"));
    }

    #[test]
    fn test_unknown_snippet_is_not_approved() {
        let m = mem();
        assert!(!m.is_approved("any-rule", "some code snippet"));
    }

    #[test]
    fn test_upsert_updates_decision() {
        let m = mem();
        m.record_decision("rule-1", "code snippet", TriageDecision::Confirmed)
            .unwrap();
        assert!(!m.is_approved("rule-1", "code snippet"));

        // Update to approved
        m.record_decision("rule-1", "code snippet", TriageDecision::Approved)
            .unwrap();
        assert!(m.is_approved("rule-1", "code snippet"));
    }

    #[test]
    fn test_whitespace_normalisation() {
        let m = mem();
        m.record_decision("rule-1", "  foo   bar  ", TriageDecision::Approved)
            .unwrap();
        // Different whitespace, same normalised form
        assert!(m.is_approved("rule-1", "foo bar"));
        assert!(m.is_approved("rule-1", "  foo   bar  "));
    }

    #[test]
    fn test_count() {
        let m = mem();
        assert_eq!(m.count().unwrap(), 0);
        m.record_decision("r1", "s1", TriageDecision::Approved)
            .unwrap();
        m.record_decision("r2", "s2", TriageDecision::Confirmed)
            .unwrap();
        assert_eq!(m.count().unwrap(), 2);
    }

    #[test]
    fn test_clear() {
        let m = mem();
        m.record_decision("r1", "s1", TriageDecision::Approved)
            .unwrap();
        m.clear().unwrap();
        assert_eq!(m.count().unwrap(), 0);
    }

    #[test]
    fn test_get_decisions_for_rule() {
        let m = mem();
        m.record_decision("rule-x", "snippet-a", TriageDecision::Approved)
            .unwrap();
        m.record_decision("rule-x", "snippet-b", TriageDecision::Confirmed)
            .unwrap();
        m.record_decision("rule-y", "snippet-c", TriageDecision::Approved)
            .unwrap();

        let records = m.get_decisions_for_rule("rule-x").unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| r.rule_id == "rule-x"));
    }

    #[test]
    fn test_different_rules_same_snippet_independent() {
        let m = mem();
        m.record_decision("rule-a", "snippet", TriageDecision::Approved)
            .unwrap();
        m.record_decision("rule-b", "snippet", TriageDecision::Confirmed)
            .unwrap();

        assert!(m.is_approved("rule-a", "snippet"));
        assert!(!m.is_approved("rule-b", "snippet"));
    }
}

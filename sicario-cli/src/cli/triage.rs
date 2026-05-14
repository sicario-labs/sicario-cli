use anyhow::Result;
use clap::Parser;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::cli::scan::ScanArgs;
use crate::engine::sast_engine::SastEngine;

#[derive(Parser, Debug)]
pub struct TriageArgs {
    /// Directory to scan and triage
    #[arg(default_value = ".")]
    pub dir: String,
}

pub fn cmd_triage(args: TriageArgs) -> Result<()> {
    let dir = PathBuf::from(&args.dir);
    println!("🔍 Scanning {} for triage...", dir.display());

    let mut eng = SastEngine::new(&dir)?;
    eng.load_default_rules();

    let mut vulns = eng.scan_directory(&dir)?;

    // Sort by priority_score descending
    vulns.sort_by(|a, b| {
        let score_a = crate::confidence::scorer::compute_priority_score(
            a.severity,
            a.confidence_score,
            a.reachable,
            a.cloud_exposed,
            false,
        );
        let score_b = crate::confidence::scorer::compute_priority_score(
            b.severity,
            b.confidence_score,
            b.reachable,
            b.cloud_exposed,
            false,
        );
        score_b
            .partial_cmp(&score_a)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if vulns.is_empty() {
        println!("✅ No findings to triage!");
        return Ok(());
    }

    println!(
        "📋 Found {} findings. Starting interactive triage...",
        vulns.len()
    );
    println!();

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for (i, vuln) in vulns.iter().enumerate() {
        let score = crate::confidence::scorer::compute_priority_score(
            vuln.severity,
            vuln.confidence_score,
            vuln.reachable,
            vuln.cloud_exposed,
            false,
        );
        println!("Finding {} of {}", i + 1, vulns.len());
        println!("  Rule:      {}", vuln.rule_id);
        println!("  File:      {}:{}", vuln.file_path.display(), vuln.line);
        println!(
            "  Severity:  {} (Priority Score: {:.1})",
            vuln.severity, score
        );
        println!("  Snippet:   {}", vuln.snippet.trim());
        println!();

        loop {
            print!("What to do? [i]gnore, [s]kip, [q]uit: ");
            stdout.flush()?;

            let mut input = String::new();
            stdin.read_line(&mut input)?;
            let input = input.trim().to_lowercase();

            match input.as_str() {
                "i" | "ignore" => {
                    println!(
                        "📝 To ignore, add `// sicario-ignore: {}` above the line in the file.",
                        vuln.rule_id
                    );
                    println!();
                    break;
                }
                "s" | "skip" => {
                    println!("⏭️ Skipped.");
                    println!();
                    break;
                }
                "q" | "quit" => {
                    println!("🚪 Exiting triage.");
                    return Ok(());
                }
                _ => {
                    println!("❌ Invalid input. Please enter i, s, or q.");
                }
            }
        }
    }

    println!("🎉 Triage complete!");
    Ok(())
}

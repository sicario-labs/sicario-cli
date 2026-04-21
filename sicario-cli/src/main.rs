mod parser;
mod scanner;
mod engine;
mod tui;
mod auth;
mod remediation;
mod mcp;
mod onboarding;
mod cloud;
mod reporting;

// New modules added by CLI overhaul
mod cli;
mod output;
mod diff;
mod confidence;
mod baseline;
mod suppression_learner;
mod verification;
mod cache;
mod hook;
mod lsp;
mod benchmark;
mod rule_harness;
mod key_manager;
mod publish;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

use cli::{Command, CompletionsArgs, SicarioCli};
use cli::exit_code::ExitCode;

fn main() {
    // Silence tracing noise — only show warnings+
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    let cli = SicarioCli::parse();

    let result = run(cli);

    match result {
        Ok(code) => std::process::exit(code as i32),
        Err(e) => {
            eprintln!("sicario: {e}");
            std::process::exit(ExitCode::InternalError as i32);
        }
    }
}

fn run(cli: SicarioCli) -> Result<ExitCode> {
    match cli.command {
        None => {
            // Default: launch TUI for backward compatibility
            let scan_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            run_interactive_tui(scan_dir)?;
            Ok(ExitCode::Clean)
        }
        Some(cmd) => dispatch(cmd),
    }
}

fn dispatch(cmd: Command) -> Result<ExitCode> {
    match cmd {
        Command::Scan(args) => cmd_scan(args),
        Command::Init => {
            eprintln!("sicario init: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Report(args) => {
            cmd_report_handler(&args.dir, args.output.as_deref())?;
            Ok(ExitCode::Clean)
        }
        Command::Fix(_args) => {
            eprintln!("sicario fix: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Baseline(_args) => {
            eprintln!("sicario baseline: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Config(_args) => {
            eprintln!("sicario config: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Suppressions(_args) => {
            eprintln!("sicario suppressions: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Completions(args) => {
            cmd_completions(args);
            Ok(ExitCode::Clean)
        }
        Command::Login => {
            eprintln!("sicario login: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Logout => {
            eprintln!("sicario logout: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Publish => {
            eprintln!("sicario publish: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Whoami => {
            eprintln!("sicario whoami: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Tui(args) => {
            let scan_dir = PathBuf::from(&args.dir);
            run_interactive_tui(scan_dir)?;
            Ok(ExitCode::Clean)
        }
        Command::Hook(_args) => {
            eprintln!("sicario hook: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Lsp(_args) => {
            eprintln!("sicario lsp: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Benchmark(_args) => {
            eprintln!("sicario benchmark: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Rules(_args) => {
            eprintln!("sicario rules: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Cache(_args) => {
            eprintln!("sicario cache: not yet implemented");
            Ok(ExitCode::Clean)
        }
    }
}

// ─── Scan command ─────────────────────────────────────────────────────────────

fn cmd_scan(args: cli::scan::ScanArgs) -> Result<ExitCode> {
    use cli::exit_code::FindingSummary;
    use cli::scan::OutputFormat;
    use engine::sast_engine::SastEngine;
    use engine::vulnerability::Severity;
    use output::formatter::{FormatterConfig, render_findings_table, render_finding_text};
    use output::branded::{ScanSummary, print_scan_summary};
    use output::sarif::emit_sarif;

    let scan_start = std::time::Instant::now();
    let dir = PathBuf::from(&args.dir);

    let formatter_config = FormatterConfig::from_flags(
        args.no_color,
        args.force_color,
        args.max_lines_per_finding,
        args.max_chars_per_line,
    );

    let explicit: Vec<PathBuf> = args.rules.iter().map(PathBuf::from).collect();
    let rule_files = if explicit.is_empty() {
        discover_bundled_rules()
    } else {
        explicit
    };

    let mut eng = SastEngine::new(&dir)?;
    let mut rules_loaded = 0usize;
    for f in &rule_files {
        if let Err(e) = eng.load_rules(f) {
            eprintln!("warning: could not load {:?}: {e}", f);
        } else {
            rules_loaded += 1;
        }
    }

    let vulns = eng.scan_directory(&dir)?;
    let scan_duration = scan_start.elapsed();

    // Emit primary output in the requested format
    let mut stdout = std::io::stdout();
    match args.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&vulns)?);
        }
        OutputFormat::Text => {
            if args.quiet {
                // Quiet mode: just the summary line
            } else {
                render_findings_table(&vulns, &formatter_config, &mut stdout)?;
            }
            let summary = ScanSummary::from_vulns(&vulns, scan_duration, 0, rules_loaded);
            print_scan_summary(
                &summary,
                formatter_config.unicode_enabled,
                formatter_config.color_enabled,
                &mut stdout,
            )?;
        }
        OutputFormat::Sarif => {
            let tool_version = env!("CARGO_PKG_VERSION");
            let sarif_doc = emit_sarif(&vulns, tool_version);
            println!("{}", serde_json::to_string_pretty(&sarif_doc)?);
        }
    }

    // Write simultaneous multi-format output to files
    if let Some(ref json_path) = args.json_output {
        let json_str = serde_json::to_string_pretty(&vulns)?;
        std::fs::write(json_path, json_str)?;
        if !args.quiet {
            eprintln!("JSON output written to {json_path}");
        }
    }

    if let Some(ref sarif_path) = args.sarif_output {
        let tool_version = env!("CARGO_PKG_VERSION");
        let sarif_doc = emit_sarif(&vulns, tool_version);
        let sarif_str = serde_json::to_string_pretty(&sarif_doc)?;
        std::fs::write(sarif_path, sarif_str)?;
        if !args.quiet {
            eprintln!("SARIF output written to {sarif_path}");
        }
    }

    if let Some(ref text_path) = args.text_output {
        let mut buf = Vec::new();
        for v in &vulns {
            render_finding_text(v, &formatter_config, &mut buf)?;
        }
        let summary = ScanSummary::from_vulns(&vulns, scan_duration, 0, rules_loaded);
        print_scan_summary(
            &summary,
            false, // no unicode in file output
            false, // no color in file output
            &mut buf,
        )?;
        std::fs::write(text_path, buf)?;
        if !args.quiet {
            eprintln!("Text output written to {text_path}");
        }
    }

    // Compute exit code
    let severity_threshold: Severity = args.severity_threshold.into();
    let summaries: Vec<FindingSummary> = vulns
        .iter()
        .map(|v| FindingSummary {
            severity: v.severity,
            confidence_score: 1.0, // confidence scoring not yet wired
            suppressed: false,     // suppression not yet wired
        })
        .collect();

    Ok(ExitCode::from_findings(
        &summaries,
        severity_threshold,
        args.confidence_threshold,
    ))
}

// ─── Shell completions ────────────────────────────────────────────────────────

fn cmd_completions(args: CompletionsArgs) {
    use clap::CommandFactory;
    use clap_complete::generate;

    let mut cmd = SicarioCli::command();
    generate(args.shell, &mut cmd, "sicario", &mut std::io::stdout());
}

// ─── Interactive TUI ──────────────────────────────────────────────────────────

fn run_interactive_tui(scan_dir: PathBuf) -> Result<()> {
    use tui::app::{SicarioTui, create_tui_channel};
    use tui::worker::{ScanJob, spawn_scan_worker};

    let (tx, rx) = create_tui_channel();
    let mut app = SicarioTui::new(rx)?;

    // Wire the patch sender so the TUI can apply patches from worker threads
    app.patch_tx = Some(tx.clone());

    // Kick off a background scan immediately so the user sees results fast
    let rule_files = discover_bundled_rules();
    let job = ScanJob {
        directory: scan_dir.clone(),
        rule_files,
    };
    spawn_scan_worker(job, tx.clone());

    // Transition straight to Scanning state — skip the static Welcome screen
    app.state = tui::app::AppState::Scanning {
        progress: 0.0,
        files_scanned: 0,
        total_files: 0,
    };

    // Run the blocking TUI event loop
    let result = app.run();

    // Always restore the terminal even on error
    if let Err(ref e) = result {
        eprintln!("sicario: {e}");
    }

    result
}

// ─── Bundled rule discovery ───────────────────────────────────────────────────

/// Find YAML rule files shipped alongside the binary.
///
/// Search order:
///   1. `<binary_dir>/rules/`
///   2. `<cwd>/sicario-cli/rules/`   (source-tree / dev mode)
///   3. `<cwd>/rules/`
fn discover_bundled_rules() -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("rules"));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("sicario-cli").join("rules"));
        candidates.push(cwd.join("rules"));
    }

    for dir in candidates {
        if dir.is_dir() {
            let files: Vec<PathBuf> = std::fs::read_dir(&dir)
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e == "yaml" || e == "yml")
                        .unwrap_or(false)
                })
                .collect();
            if !files.is_empty() {
                return files;
            }
        }
    }
    Vec::new()
}

// ─── Report handler (preserved from original) ────────────────────────────────

fn cmd_report_handler(dir_str: &str, output: Option<&str>) -> Result<()> {
    use reporting::{generate_compliance_report, write_compliance_reports};
    use engine::sast_engine::SastEngine;

    let dir = PathBuf::from(dir_str);
    let output_dir = output
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.join(".sicario").join("reports"));

    let mut eng = SastEngine::new(&dir)?;
    for f in discover_bundled_rules() {
        if let Err(e) = eng.load_rules(&f) {
            eprintln!("warning: could not load {:?}: {e}", f);
        }
    }

    let vulns = eng.scan_directory(&dir)?;
    let report = generate_compliance_report(&vulns);
    let (json_path, md_path) = write_compliance_reports(&report, &output_dir)?;

    println!("OWASP report: {}", json_path.display());
    println!("Markdown:     {}", md_path.display());
    println!(
        "Total: {}  |  Categories affected: {}/10",
        report.total_vulnerabilities, report.categories_affected
    );
    Ok(())
}

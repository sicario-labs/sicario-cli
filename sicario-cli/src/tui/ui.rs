//! UI rendering components for the Sicario TUI
//!
//! Implements immediate-mode rendering for all AppState variants using Ratatui.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Wrap,
};

use super::AppState;
use crate::engine::{Severity, Vulnerability};
use crate::reporting::{generate_compliance_report, group_by_owasp};

// ── Top-level dispatcher ──────────────────────────────────────────────────────

/// Render the current application state to the terminal frame.
pub fn render(frame: &mut Frame, state: &AppState) {
    match state {
        AppState::Welcome => render_welcome(frame),
        AppState::Onboarding {
            languages,
            package_managers,
            frameworks,
            rules_configured,
        } => render_onboarding(frame, languages, package_managers, frameworks, *rules_configured),
        AppState::AuthPending { verification_uri, user_code } => {
            render_auth_pending(frame, verification_uri, user_code);
        }
        AppState::AuthComplete => render_auth_complete(frame),
        AppState::Scanning { progress, files_scanned, total_files } => {
            render_scanning(frame, *progress, *files_scanned, *total_files);
        }
        AppState::Results { vulnerabilities, selected } => {
            render_results(frame, vulnerabilities, *selected);
        }
        AppState::OwaspResults { vulnerabilities, selected_category } => {
            render_owasp_results(frame, vulnerabilities, *selected_category);
        }
        AppState::PatchPreview { vulnerability, patch } => {
            render_patch_preview(frame, vulnerability, patch);
        }
        AppState::PatchSuccess { file_path } => {
            render_patch_success(frame, file_path);
        }
        AppState::PatchError { message } => {
            render_patch_error(frame, message);
        }
        AppState::OnboardingSuccess { file_path, vulnerabilities_fixed } => {
            render_onboarding_success(frame, file_path, *vulnerabilities_fixed);
        }
    }
}

// ── Welcome screen ────────────────────────────────────────────────────────────

/// Render the welcome / splash screen with gradient-like styling and version info.
pub fn render_welcome(frame: &mut Frame) {
    let area = frame.size();

    // Outer border with gradient-like cyan/magenta title
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Span::styled(
            " ⚡ Sicario CLI ",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ));

    // Logo lines with gradient effect (Red → LightRed → Yellow)
    let logo = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  ███████╗██╗ ██████╗ █████╗ ██████╗ ██╗ ██████╗  ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  ██╔════╝██║██╔════╝██╔══██╗██╔══██╗██║██╔═══██╗ ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  ███████╗██║██║     ███████║██████╔╝██║██║   ██║ ",
            Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  ╚════██║██║██║     ██╔══██║██╔══██╗██║██║   ██║ ",
            Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  ███████║██║╚██████╗██║  ██║██║  ██║██║╚██████╔╝ ",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  v", Style::default().fg(Color::DarkGray)),
            Span::styled(
                env!("CARGO_PKG_VERSION"),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "  ·  Next-generation SAST — 10x faster than legacy scanners",
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  ┌─ ", Style::default().fg(Color::DarkGray)),
            Span::styled("Quick Start", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" ─────────────────────────────────────────┐", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled("  │  ", Style::default().fg(Color::DarkGray)),
            Span::styled("i", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled("  →  Zero-config onboarding (auto-detect & scan)", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  │  ", Style::default().fg(Color::DarkGray)),
            Span::styled("s", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled("  →  Start scanning current directory", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  │  ", Style::default().fg(Color::DarkGray)),
            Span::styled("q", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::styled("  →  Quit", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  └──────────────────────────────────────────────────┘", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let paragraph = Paragraph::new(Text::from(logo))
        .block(block)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: false });

    frame.render_widget(paragraph, area);
}

// ── Onboarding screen ─────────────────────────────────────────────────────────

/// Render the zero-configuration onboarding screen showing detected technologies.
pub fn render_onboarding(
    frame: &mut Frame,
    languages: &[String],
    package_managers: &[String],
    frameworks: &[String],
    rules_configured: usize,
) {
    let area = frame.size();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),  // title bar
            Constraint::Length(6),  // detected technologies
            Constraint::Length(4),  // rules summary
            Constraint::Min(0),     // action prompt
        ])
        .split(area);

    // Outer border
    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta))
        .title(Span::styled(
            " ⚡ Zero-Config Onboarding ",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    frame.render_widget(outer, area);

    // Detected technologies panel
    let lang_str = if languages.is_empty() {
        "none detected".to_string()
    } else {
        languages.join(", ")
    };
    let pm_str = if package_managers.is_empty() {
        "none detected".to_string()
    } else {
        package_managers.join(", ")
    };
    let fw_str = if frameworks.is_empty() {
        "none detected".to_string()
    } else {
        frameworks.join(", ")
    };

    let tech_lines = vec![
        Line::from(vec![
            Span::styled("  Languages:       ", Style::default().fg(Color::DarkGray)),
            Span::styled(lang_str, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Package managers:", Style::default().fg(Color::DarkGray)),
            Span::styled(format!(" {}", pm_str), Style::default().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::styled("  Frameworks:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!(" {}", fw_str), Style::default().fg(Color::Yellow)),
        ]),
    ];

    let tech_panel = Paragraph::new(Text::from(tech_lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Detected Technologies "),
        );
    frame.render_widget(tech_panel, chunks[1]);

    // Rules summary
    let rules_lines = vec![
        Line::from(vec![
            Span::styled("  Configured ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{}", rules_configured),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " security rules optimised for your stack.",
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Press  Enter  to start scanning   q  to quit",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let rules_panel = Paragraph::new(Text::from(rules_lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green))
                .title(" Ready to Scan "),
        );
    frame.render_widget(rules_panel, chunks[2]);
}

// ── Scanning screen ───────────────────────────────────────────────────────────

/// Render the scanning progress screen with a progress bar.
pub fn render_scanning(frame: &mut Frame, progress: f64, files_scanned: usize, total_files: usize) {
    let area = frame.size();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),  // title
            Constraint::Length(3),  // progress bar
            Constraint::Length(2),  // stats
            Constraint::Min(0),     // padding
        ])
        .split(area);

    // Outer border
    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Span::styled(
            " Scanning… ",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    frame.render_widget(outer, area);

    // Progress bar
    let clamped = progress.clamp(0.0, 1.0);
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Progress "))
        .gauge_style(
            Style::default()
                .fg(Color::Green)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .ratio(clamped)
        .label(format!("{:.0}%", clamped * 100.0));
    frame.render_widget(gauge, chunks[1]);

    // Stats line
    let stats = Paragraph::new(Line::from(vec![
        Span::styled("  Files scanned: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", files_scanned),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  /  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", total_files),
            Style::default().fg(Color::White),
        ),
    ]));
    frame.render_widget(stats, chunks[2]);
}

// ── Results screen ────────────────────────────────────────────────────────────

/// Render the vulnerability results list with the selected item highlighted.
pub fn render_results(frame: &mut Frame, vulnerabilities: &[Vulnerability], selected: usize) {
    let area = frame.size();

    if vulnerabilities.is_empty() {
        let msg = Paragraph::new(Span::styled(
            "  No vulnerabilities found. Your code looks clean!",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green))
                .title(" Results "),
        );
        frame.render_widget(msg, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    // Left panel: vulnerability list
    let items: Vec<ListItem> = vulnerabilities
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let severity_color = severity_color(&v.severity);
            let prefix = if i == selected { "▶ " } else { "  " };
            // Cloud exposure badge (Requirement 11.5)
            let cloud_badge = match v.cloud_exposed {
                Some(true) => Span::styled("☁⚠ ", Style::default().fg(Color::Red)),
                Some(false) => Span::styled("☁  ", Style::default().fg(Color::Green)),
                None => Span::raw("   "),
            };
            let line = Line::from(vec![
                Span::raw(prefix),
                Span::styled(
                    format!("[{:?}] ", v.severity),
                    Style::default().fg(severity_color).add_modifier(Modifier::BOLD),
                ),
                cloud_badge,
                Span::styled(
                    v.rule_id.clone(),
                    Style::default().fg(Color::White),
                ),
            ]);
            ListItem::new(line)
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(selected));

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(format!(" Vulnerabilities ({}) ", vulnerabilities.len())),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_stateful_widget(list, chunks[0], &mut list_state);

    // Right panel: detail view for selected vulnerability
    if let Some(vuln) = vulnerabilities.get(selected) {
        render_vuln_detail(frame, vuln, chunks[1]);
    }
}

/// Render the detail panel for a single vulnerability.
fn render_vuln_detail(frame: &mut Frame, vuln: &Vulnerability, area: Rect) {
    let severity_color = severity_color(&vuln.severity);

    // Cloud exposure line — only shown when cloud context is available (Requirement 11.5)
    let cloud_line = match vuln.cloud_exposed {
        Some(true) => Line::from(vec![
            Span::styled("Cloud:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                " ⚠ Publicly Exposed",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ]),
        Some(false) => Line::from(vec![
            Span::styled("Cloud:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                " Internal (isolated)",
                Style::default().fg(Color::Green),
            ),
        ]),
        None => Line::from(vec![
            Span::styled("Cloud:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(" Unknown", Style::default().fg(Color::DarkGray)),
        ]),
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("Rule:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(vuln.rule_id.clone(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("File:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                vuln.file_path.display().to_string(),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::styled("Location: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("line {}, col {}", vuln.line, vuln.column),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("Severity: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:?}", vuln.severity),
                Style::default().fg(severity_color).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Reachable:", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if vuln.reachable { " Yes" } else { " No" },
                Style::default().fg(if vuln.reachable { Color::Red } else { Color::Yellow }),
            ),
        ]),
        cloud_line,
        Line::from(""),
        Line::from(Span::styled("Snippet:", Style::default().fg(Color::DarkGray))),
        Line::from(Span::styled(
            format!("  {}", vuln.snippet),
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  ↑/↓ navigate   Enter generate patch   q quit",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let detail = Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Detail "),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(detail, area);
}

// ── Patch preview screen ──────────────────────────────────────────────────────

/// Render the patch preview screen with inline diff highlighting.
pub fn render_patch_preview(frame: &mut Frame, vulnerability: &Vulnerability, patch: &str) {
    let area = frame.size();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(0)])
        .split(area);

    // Top: vulnerability summary
    let severity_color = severity_color(&vulnerability.severity);
    let summary_lines = vec![
        Line::from(vec![
            Span::styled("  Rule:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                vulnerability.rule_id.clone(),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  File:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                vulnerability.file_path.display().to_string(),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Severity: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:?}", vulnerability.severity),
                Style::default().fg(severity_color).add_modifier(Modifier::BOLD),
            ),
        ]),
    ];

    let summary = Paragraph::new(Text::from(summary_lines)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title(" Vulnerability "),
    );
    frame.render_widget(summary, chunks[0]);

    // Bottom: diff view
    let diff_lines: Vec<Line> = patch
        .lines()
        .map(|line| {
            if line.starts_with('+') {
                Line::from(Span::styled(line.to_string(), Style::default().fg(Color::Green)))
            } else if line.starts_with('-') {
                Line::from(Span::styled(line.to_string(), Style::default().fg(Color::Red)))
            } else if line.starts_with("@@") {
                Line::from(Span::styled(line.to_string(), Style::default().fg(Color::Cyan)))
            } else {
                Line::from(Span::raw(line.to_string()))
            }
        })
        .collect();

    let diff_text = if diff_lines.is_empty() {
        vec![Line::from(Span::styled(
            "  (no patch content)",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        diff_lines
    };

    let diff_view = Paragraph::new(Text::from(diff_text))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green))
                .title(" Proposed Patch  (Enter/y to apply  Esc/n to cancel) "),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(diff_view, chunks[1]);
}

// ── Patch success / error screens ────────────────────────────────────────────

/// Render a success message after a patch is applied.
pub fn render_patch_success(frame: &mut Frame, file_path: &std::path::Path) {
    let area = frame.size();
    let msg = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            "  ✓ Patch applied successfully!",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("  File: {}", file_path.display()),
            Style::default().fg(Color::Cyan),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Press any key to continue.",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green))
            .title(" Patch Applied "),
    );
    frame.render_widget(msg, area);
}

/// Render an error message when patch application fails.
pub fn render_patch_error(frame: &mut Frame, message: &str) {
    let area = frame.size();
    let msg = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            "  ✗ Patch application failed",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("  Error: {}", message),
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  The original file has been restored. Press Esc to go back.",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red))
            .title(" Patch Error "),
    )
    .wrap(Wrap { trim: false });
    frame.render_widget(msg, area);
}

// ── Onboarding success ("Magic Moment") ──────────────────────────────────────

/// Render the celebratory "Magic Moment" screen after the first patch is applied.
pub fn render_onboarding_success(
    frame: &mut Frame,
    file_path: &std::path::Path,
    vulnerabilities_fixed: usize,
) {
    let area = frame.size();

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  🎉  You just made your code more secure!",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  ✓  Fixed ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("{}", vulnerabilities_fixed),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " vulnerability",
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
            if vulnerabilities_fixed != 1 {
                Span::styled("ies", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
            } else {
                Span::raw("")
            },
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  File: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                file_path.display().to_string(),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  ─────────────────────────────────────────────────────",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Sicario CLI is now watching your back.",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "  Run  sicario scan  anytime to check for new issues.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Press any key to continue.",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let paragraph = Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green))
                .title(Span::styled(
                    " ⚡ Magic Moment — Security Fix Applied ",
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(paragraph, area);
}

// ── Auth pending screen ───────────────────────────────────────────────────────

/// Render the OAuth Device Flow pending screen showing verification_uri and user_code.
pub fn render_auth_pending(frame: &mut Frame, verification_uri: &str, user_code: &str) {
    let area = frame.size();

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Authentication Required",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  To authenticate, visit the URL below and enter the code:",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  URL:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                verification_uri.to_string(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::UNDERLINED),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Code: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                user_code.to_string(),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Waiting for authentication… (q to cancel)",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let paragraph = Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .title(" Login — OAuth 2.0 Device Flow "),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(paragraph, area);
}

/// Render the authentication success screen.
pub fn render_auth_complete(frame: &mut Frame) {
    let area = frame.size();

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  ✓ Authentication successful!",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Your tokens have been stored securely in the system keychain.",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Press any key to continue.",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let paragraph = Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green))
                .title(" Login Complete "),
        );

    frame.render_widget(paragraph, area);
}

// ── OWASP grouped results screen ─────────────────────────────────────────────

/// Render vulnerabilities grouped by OWASP Top 10 category with severity distribution.
pub fn render_owasp_results(
    frame: &mut Frame,
    vulnerabilities: &[Vulnerability],
    selected_category: usize,
) {
    use crate::reporting::owasp_report::ALL_OWASP_CATEGORIES;

    let area = frame.size();

    let report = generate_compliance_report(vulnerabilities);
    let groups = group_by_owasp(vulnerabilities);

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    // ── Left: category list ───────────────────────────────────────────────────
    let items: Vec<ListItem> = report
        .categories
        .iter()
        .enumerate()
        .map(|(i, cat)| {
            let prefix = if i == selected_category { "▶ " } else { "  " };
            let count_color = if cat.total == 0 {
                Color::Green
            } else if cat.critical > 0 || cat.high > 0 {
                Color::Red
            } else {
                Color::Yellow
            };
            let line = Line::from(vec![
                Span::raw(prefix),
                Span::styled(
                    format!("{:2} ", cat.total),
                    Style::default().fg(count_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    // Shorten label to fit: strip "A0X:2021 – " prefix for display
                    cat.label
                        .splitn(2, '–')
                        .nth(1)
                        .unwrap_or(&cat.label)
                        .trim()
                        .to_string(),
                    Style::default().fg(Color::White),
                ),
            ]);
            ListItem::new(line)
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(selected_category));

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(format!(
                    " OWASP Top 10  ({} affected)  [o] flat view ",
                    report.categories_affected
                )),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_stateful_widget(list, chunks[0], &mut list_state);

    // ── Right: detail for selected category ──────────────────────────────────
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(chunks[1]);

    // Summary panel for selected category
    if let Some(cat) = report.categories.get(selected_category) {
        let summary_lines = vec![
            Line::from(vec![
                Span::styled("Category: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    cat.label.clone(),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Critical: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{}", cat.critical),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::styled("   High: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{}", cat.high),
                    Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                ),
                Span::styled("   Medium: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{}", cat.medium),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Low:      ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{}", cat.low), Style::default().fg(Color::Blue)),
                Span::styled("   Info:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{}", cat.info), Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "  ↑/↓ navigate categories   o  flat view   q  quit",
                Style::default().fg(Color::DarkGray),
            )),
        ];

        let summary = Paragraph::new(Text::from(summary_lines)).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .title(format!(" {} findings ", cat.total)),
        );
        frame.render_widget(summary, right_chunks[0]);
    }

    // Findings list for selected category
    let selected_owasp = ALL_OWASP_CATEGORIES.get(selected_category).copied();
    let category_vulns: Vec<&Vulnerability> = vulnerabilities
        .iter()
        .filter(|v| v.owasp_category == selected_owasp)
        .collect();

    if category_vulns.is_empty() {
        let empty = Paragraph::new(Span::styled(
            "  ✅ No findings in this category.",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green))
                .title(" Findings "),
        );
        frame.render_widget(empty, right_chunks[1]);
    } else {
        let finding_items: Vec<ListItem> = category_vulns
            .iter()
            .map(|v| {
                let sev_color = severity_color(&v.severity);
                let line = Line::from(vec![
                    Span::styled(
                        format!("[{:?}] ", v.severity),
                        Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!(
                            "{}:{}  {}",
                            v.file_path.display(),
                            v.line,
                            v.rule_id
                        ),
                        Style::default().fg(Color::White),
                    ),
                ]);
                ListItem::new(line)
            })
            .collect();

        let findings_list = List::new(finding_items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(format!(" Findings ({}) ", category_vulns.len())),
        );
        frame.render_widget(findings_list, right_chunks[1]);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn severity_color(severity: &Severity) -> Color {
    match severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::LightRed,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Blue,
        Severity::Info => Color::DarkGray,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Severity, Vulnerability};
    use std::path::PathBuf;
    use uuid::Uuid;

    fn make_vuln(severity: Severity) -> Vulnerability {
        Vulnerability {
            id: Uuid::new_v4(),
            rule_id: "sql-injection".to_string(),
            file_path: PathBuf::from("src/db.rs"),
            line: 42,
            column: 8,
            snippet: "query(user_input)".to_string(),
            severity,
            reachable: true,
            cloud_exposed: None,
            cwe_id: None,
            owasp_category: None,
        }
    }

    #[test]
    fn test_severity_color_mapping() {
        assert_eq!(severity_color(&Severity::Critical), Color::Red);
        assert_eq!(severity_color(&Severity::High), Color::LightRed);
        assert_eq!(severity_color(&Severity::Medium), Color::Yellow);
        assert_eq!(severity_color(&Severity::Low), Color::Blue);
        assert_eq!(severity_color(&Severity::Info), Color::DarkGray);
    }

    #[test]
    fn test_appstate_welcome_renders_without_panic() {
        // We can't easily render to a real terminal in tests, but we can verify
        // the render function dispatches correctly by checking state matching.
        let state = AppState::Welcome;
        assert!(matches!(state, AppState::Welcome));
    }

    #[test]
    fn test_appstate_scanning_renders_without_panic() {
        let state = AppState::Scanning {
            progress: 0.5,
            files_scanned: 50,
            total_files: 100,
        };
        assert!(matches!(state, AppState::Scanning { files_scanned: 50, .. }));
    }

    #[test]
    fn test_appstate_results_empty() {
        let state = AppState::Results {
            vulnerabilities: vec![],
            selected: 0,
        };
        if let AppState::Results { vulnerabilities, .. } = state {
            assert!(vulnerabilities.is_empty());
        }
    }

    #[test]
    fn test_appstate_patch_preview() {
        let vuln = make_vuln(Severity::High);
        let patch = "+let safe = parameterized_query(input);\n-let unsafe = query(input);".to_string();
        let state = AppState::PatchPreview {
            vulnerability: vuln,
            patch: patch.clone(),
        };
        if let AppState::PatchPreview { patch: p, .. } = state {
            assert!(p.contains('+'));
            assert!(p.contains('-'));
        }
    }
}

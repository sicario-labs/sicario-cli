# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Multi-language SAST engine with tree-sitter parsing (Go, Java, JavaScript/TypeScript, Python, Rust)
- YAML-based security rule system with 40+ built-in rules
- Secret scanning with regex, entropy detection, and provider-specific verifiers
- SCA module with OSV and GHSA advisory database integration
- Data-flow reachability analysis to reduce false positives
- AI-powered remediation engine with Cerebras LLM integration
- Safe backup/rollback system for automated code fixes
- Interactive TUI dashboard built with Ratatui
- Professional CLI with Clap (scan, fix, report, baseline, rules, config, etc.)
- SARIF output for GitHub Code Scanning integration
- OWASP Top 10 compliance report generation (JSON + Markdown)
- OAuth 2.0 device flow authentication with PKCE
- MCP (Model Context Protocol) server for AI assistant integration
- Git-aware diff scanning for PR workflows
- Baseline management for tracking new vs. known findings
- Confidence scoring system for finding prioritization
- Cloud priority scoring with internet exposure analysis
- Scan result caching for incremental runs
- Shell completions (bash, zsh, fish, PowerShell)
- Cross-platform builds: Linux (musl static), macOS (Intel + Apple Silicon), Windows (MSVC)
- Homebrew formula for macOS/Linux installation
- Curl-based installer script
- GitHub Actions CI/CD pipeline with cross-compilation and automated releases

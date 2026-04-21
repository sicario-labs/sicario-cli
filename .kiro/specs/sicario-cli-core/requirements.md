# Requirements Document

## Introduction

The Sicario CLI is a next-generation static application security testing (SAST) tool engineered in Rust to deliver 10x performance improvements over legacy Python and Node.js-based security scanners. The system provides ultra-fast vulnerability detection, active credential verification, framework-aware data-flow analysis, and autonomous code remediation capabilities through a sophisticated Terminal User Interface (TUI).

## Glossary

- **Sicario_CLI**: The command-line security scanning application
- **Tree_Sitter_Engine**: The Rust-based parsing engine utilizing tree-sitter for AST generation
- **Ratatui_TUI**: The Terminal User Interface built with the Ratatui framework
- **Secret_Scanner**: The pre-commit module for detecting hardcoded credentials
- **SAST_Engine**: The static application security testing core that analyzes source code
- **MCP_Server**: The Model Context Protocol server enabling AI agent integration
- **Auth_Module**: The OAuth 2.0 Device Flow authentication system
- **Remediation_Engine**: The component that generates and applies security patches
- **Convex_Backend**: The real-time backend infrastructure for telemetry and rulesets
- **Reachability_Analyzer**: The data-flow analysis component that traces tainted variables

## Requirements

### Requirement 1: Ultra-Fast Secret Scanning

**User Story:** As a developer, I want to detect hardcoded credentials before committing code, so that I never accidentally leak secrets into version control.

#### Acceptance Criteria

1. WHEN a developer stages files for commit, THE Secret_Scanner SHALL scan all staged files within 100 milliseconds for repositories under 10,000 files
2. WHEN a potential secret is detected, THE Secret_Scanner SHALL use regex compilation to identify credential patterns matching AWS keys, Stripe tokens, GitHub PATs, and database connection strings
3. WHEN a credential pattern is matched, THE Secret_Scanner SHALL perform active verification by querying the origin API endpoint to confirm the credential is mathematically valid and actively authorizing requests
4. IF a verified active credential is detected, THEN THE Secret_Scanner SHALL block the commit and display the credential location with context
5. WHEN scanning git history, THE Secret_Scanner SHALL traverse all commits and branches without requiring full repository clones

### Requirement 2: Rust-Based AST Parsing Engine

**User Story:** As a security engineer, I want the SAST engine to parse source code at native speeds, so that security scans complete in seconds rather than minutes.

#### Acceptance Criteria

1. THE Tree_Sitter_Engine SHALL parse source files and generate concrete syntax trees (CSTs) using tree-sitter compiled to native machine code
2. THE Tree_Sitter_Engine SHALL maintain AST representations entirely within Rust memory space without JSON serialization overhead
3. WHEN processing multiple files, THE Tree_Sitter_Engine SHALL utilize the Rayon crate to distribute parsing across all available CPU cores
4. THE Tree_Sitter_Engine SHALL cache parsed ASTs in memory to avoid redundant parsing when applying multiple security rules
5. THE Tree_Sitter_Engine SHALL support JavaScript, TypeScript, Python, Go, Rust, and Java source files
6. WHEN compared to Python-based parsers, THE Tree_Sitter_Engine SHALL demonstrate at least 10x performance improvement for repositories exceeding 100,000 lines of code

### Requirement 3: YAML-Based Security Rules

**User Story:** As a security engineer, I want to write custom security rules in YAML, so that I can target framework-specific vulnerabilities unique to my organization.

#### Acceptance Criteria

1. THE SAST_Engine SHALL load security rules from YAML configuration files
2. WHEN a YAML rule is defined, THE SAST_Engine SHALL parse the rule syntax and compile it into AST pattern matchers
3. THE SAST_Engine SHALL support pattern matching for function calls, variable assignments, import statements, and control flow structures
4. WHEN a rule matches code patterns, THE SAST_Engine SHALL capture metadata including file path, line number, matched code snippet, and severity level
5. WHERE custom rules are provided, THE SAST_Engine SHALL merge them with default rulesets without conflicts

### Requirement 4: Award-Winning Terminal User Interface

**User Story:** As a developer, I want a responsive and visually rich terminal interface, so that I can interact with security findings without blocking the scan process.

#### Acceptance Criteria

1. THE Ratatui_TUI SHALL render an immediate-mode interface with real-time updates at 60 frames per second
2. WHEN the scan is running, THE Ratatui_TUI SHALL display a multi-threaded progress bar showing files scanned and vulnerabilities detected
3. THE Ratatui_TUI SHALL execute parsing and rule-matching on dedicated worker threads separate from the UI event loop
4. WHEN vulnerabilities are detected, THE Ratatui_TUI SHALL display an interactive tree view allowing developers to expand findings, view code context, and filter by severity
5. THE Ratatui_TUI SHALL communicate with worker threads via asynchronous message passing using Rust mpsc channels
6. WHEN the developer scrolls through findings, THE Ratatui_TUI SHALL remain responsive without blocking or frame drops

### Requirement 5: Data-Flow Reachability Analysis

**User Story:** As a developer, I want the scanner to identify only exploitable vulnerabilities, so that I don't waste time on false positives from unused dependencies.

#### Acceptance Criteria

1. WHEN analyzing dependencies, THE Reachability_Analyzer SHALL track data flow from external input sources to vulnerable function calls
2. THE Reachability_Analyzer SHALL trace tainted variables across function boundaries and multiple files
3. WHEN a vulnerable dependency is detected, THE Reachability_Analyzer SHALL determine if attacker-controlled input can reach the vulnerable code path
4. IF a vulnerability is not reachable from external input, THEN THE SAST_Engine SHALL mark it as low priority or suppress it
5. THE Reachability_Analyzer SHALL understand framework-specific patterns including Django decorators, FastAPI middleware, and React component props

### Requirement 6: Model Context Protocol Integration

**User Story:** As an AI coding assistant, I want to query the Sicario CLI for security analysis, so that I can validate generated code before presenting it to developers.

#### Acceptance Criteria

1. THE MCP_Server SHALL implement the Model Context Protocol specification as defined by Anthropic
2. WHEN an MCP client connects, THE MCP_Server SHALL expose security scanning capabilities through standardized protocol methods
3. THE MCP_Server SHALL accept source code or file paths as input and return vulnerability findings in structured JSON format
4. WHEN an AI agent invokes the MCP_Server, THE MCP_Server SHALL execute background security traces without blocking the client connection
5. THE MCP_Server SHALL support Assistant Memory features by ingesting historical triage decisions to autonomously dismiss previously approved patterns

### Requirement 7: OAuth 2.0 Device Flow Authentication

**User Story:** As a developer, I want to authenticate the CLI securely without copying tokens, so that I can sync telemetry and rulesets safely.

#### Acceptance Criteria

1. WHEN a developer executes the login command, THE Auth_Module SHALL initiate the OAuth 2.0 Device Authorization Grant flow per RFC 8628
2. THE Auth_Module SHALL request a device_code, user_code, and verification_uri from the authorization server
3. THE Auth_Module SHALL display the verification_uri and user_code in the terminal and instruct the developer to complete authentication in a browser
4. WHILE the user authenticates, THE Auth_Module SHALL asynchronously poll the token endpoint at 5-second intervals
5. WHEN the user grants permission, THE Auth_Module SHALL receive a JWT access token and refresh token
6. THE Auth_Module SHALL implement Proof Key for Code Exchange (PKCE) per RFC 7636 by generating a code_verifier, hashing it to create a code_challenge, and validating the exchange
7. THE Auth_Module SHALL store tokens securely in the system keychain and never write them to plaintext files

### Requirement 8: Convex Backend Integration

**User Story:** As a security team, I want vulnerability telemetry synced to a real-time database, so that we can monitor security posture across all developers.

#### Acceptance Criteria

1. THE Sicario_CLI SHALL connect to the Convex_Backend using WebSocket connections with JWT authentication
2. WHEN vulnerabilities are detected, THE Sicario_CLI SHALL push telemetry data to Convex including file paths, vulnerability types, severity, and timestamps
3. THE Convex_Backend SHALL validate JWT signatures using WorkOS AuthKit public keys
4. WHEN organizational rulesets are updated in Convex, THE Sicario_CLI SHALL receive real-time updates via WebSocket subscriptions
5. THE Convex_Backend SHALL integrate with WorkOS AuthKit for zero-configuration identity management

### Requirement 9: Autonomous Code Remediation

**User Story:** As a developer, I want the CLI to automatically fix vulnerabilities, so that I can secure code without manually writing patches.

#### Acceptance Criteria

1. WHEN a vulnerability is detected, THE Remediation_Engine SHALL compute the mathematically correct code transformation required to patch it
2. THE Remediation_Engine SHALL generate formatted, syntax-correct patch diffs using AST manipulation
3. THE Remediation_Engine SHALL display the proposed patch in the TUI with inline diff highlighting
4. WHEN the developer approves a patch, THE Remediation_Engine SHALL apply the changes directly to the local working directory
5. WHERE git integration is available, THE Remediation_Engine SHALL offer to create a pull request with the patch via the Git provider API

### Requirement 10: Zero-Configuration Onboarding

**User Story:** As a new user, I want to start scanning immediately without configuration, so that I experience value within seconds of installation.

#### Acceptance Criteria

1. WHEN the developer executes the initialization command, THE Sicario_CLI SHALL display an interactive Ratatui welcome screen
2. THE Sicario_CLI SHALL automatically detect programming languages, package managers, and web frameworks in the current directory
3. THE Sicario_CLI SHALL configure optimal security rule subsets based on detected technologies without requiring user input
4. WHEN the initial scan completes, THE Sicario_CLI SHALL present the first actionable auto-generated fix as the "Magic Moment"
5. THE Sicario_CLI SHALL provide a single-keystroke prompt to apply the first patch and display a celebratory success state

### Requirement 11: Cloud-to-Code Traceability

**User Story:** As a security engineer, I want vulnerabilities prioritized by runtime exposure, so that I focus on publicly accessible services first.

#### Acceptance Criteria

1. THE Sicario_CLI SHALL integrate with cloud-native telemetry including Kubernetes configurations and CSPM data
2. WHEN analyzing vulnerabilities, THE Sicario_CLI SHALL query runtime posture to determine if affected services are publicly exposed
3. THE Sicario_CLI SHALL assign critical priority to vulnerabilities in microservices exposed to the public internet
4. THE Sicario_CLI SHALL deprioritize identical vulnerabilities in internal, isolated services
5. THE Sicario_CLI SHALL display cloud context metadata alongside vulnerability findings in the TUI

### Requirement 12: Cross-Platform Binary Distribution

**User Story:** As a developer, I want to install the CLI with a single command, so that I can start using it immediately.

#### Acceptance Criteria

1. THE Sicario_CLI SHALL compile to a statically linked native binary for Linux, macOS, and Windows
2. THE Sicario_CLI SHALL be distributed via Homebrew for macOS and Linux users
3. THE Sicario_CLI SHALL provide a shell script installer that downloads the appropriate binary for the detected platform
4. THE Sicario_CLI SHALL have a binary footprint under 50MB without requiring runtime dependencies
5. WHEN installed, THE Sicario_CLI SHALL be available globally in the system PATH

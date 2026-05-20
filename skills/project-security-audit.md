# Sicario Skill: Project Security Audit

This skill guides the AI in performing a comprehensive security posture assessment of an entire project using Sicario's local-first engine.

## Workflow

1. **Discovery**: List all files in the project and identify high-value targets (e.g., API routes, database models, authentication controllers).
   - *Supported Languages:* JS/TS, Python, Go, Rust, Java, Ruby, PHP, C#.

2. **Parallel Scan**: Iteratively call `analyze_ast_security` on identified files.
   - *Focus:* Priority on `Critical` and `High` severity findings first.

3. **Identify Patterns**: Look for project-wide security anti-patterns (e.g., inconsistent input validation, global state for sensitive tokens).

4. **Summarize Risks**: Generate a security audit report using the `log_telemetry_audit` tool format (metadata-only) to give the developer a "Dashboard-ready" summary.
   - *Tool:* `log_telemetry_audit({ "project_id": "...", "scan_results": [...] })`

5. **Roadmap**: Propose a remediation roadmap, starting with the most critical fixes that can be handled via `request_remediation_patch`.

## Best Practices
- **Prioritization**: Don't overwhelming the developer with `Info` level findings. Focus on the Top 5 most actionable risks.
- **Explain Impact**: For each finding, explain the potential exploit scenario (e.g., "This could lead to an account takeover via SQL injection").

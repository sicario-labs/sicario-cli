---
sidebar:
  badge:
    text: Capabilities
---

# MCP Server

> The Model Context Protocol (MCP) server allows AI assistants like Claude Desktop and Cursor IDE to interact directly with Sicario's security analysis engine. Through JSON-RPC 2.0 over stdio or TCP, AI agents can scan files, analyze vulnerabilities, and generate patches — all without leaving the assistant's interface.

## What is the Model Context Protocol?

MCP is an open standard developed by Anthropic that defines how AI applications connect to external tools and data sources. It uses JSON-RPC 2.0 as its wire format and supports both stdio (for local processes) and TCP (for network services) transports.

Sicario implements MCP to expose its security scanning capabilities to AI assistants, enabling:

- **Claude Desktop** — scan projects directly from Claude's chat interface
- **Cursor IDE** — analyze code security without leaving the editor
- **Custom AI applications** — integrate Sicario into any MCP-compatible tool

## How Sicario's MCP Server Works

### Architecture

```
AI Assistant (Claude Desktop / Cursor IDE)
    │
    │  JSON-RPC 2.0 (stdio or TCP)
    ▼
Sicario MCP Server
    │
    ├── SastEngine      ← SAST rule matching
    ├── AssistantMemory ← Persistent SQLite memory for AI context
    └── FindingsCache   ← In-memory cache of recent scan results
```

### Transport Options

| Transport | Command | Use Case |
|---|---|---|
| stdio | `sicario mcp` (built-in) | Local AI assistants, embedded in editor |
| TCP | `npx sicario-mcp` (via npm) | Network-accessible, CI integration |

The stdio transport is the default when running `sicario mcp` from the CLI. It reads JSON-RPC requests from stdin and writes responses to stdout (all logging goes to stderr, preserving the protocol stream).

## Supported AI Assistants

### Claude Desktop

Configure Claude Desktop to use Sicario's MCP server by editing `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sicario": {
      "command": "npx",
      "args": [
        "-y",
        "@sicario-labs/mcp",
        "--project",
        "/path/to/your/project"
      ],
      "env": {}
    }
  }
}
```

**Location of config file:**

| Platform | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

After adding the configuration, restart Claude Desktop. You should see a hammer icon 🔨 in the input area indicating that Sicario tools are available.

**Example interaction with Claude:**

```
User: "Scan my project for SQL injection vulnerabilities"

Claude: "I'll use the Sicario MCP tools to scan your project."

[Claude calls analyze_ast_security on src/db/queries.js]
[Claude calls analyze_ast_security on src/routes/user.js]

Claude: "I found 2 SQL injection vulnerabilities:

1. src/routes/user.js:42 — `query("SELECT * FROM users WHERE id = " + userId)`
   - Severity: High | CWE-89 | Reachable: Yes
   
2. src/db/queries.js:87 — `cursor.execute(f"INSERT INTO logs VALUES ({userInput})")`
   - Severity: High | CWE-89 | Reachable: Yes

Would you like me to generate patches for these?"
```

### Cursor IDE

Cursor IDE supports MCP tools natively. Configure Sicario in Cursor's MCP settings:

```json
{
  "mcpServers": {
    "sicario": {
      "command": "npx",
      "args": [
        "-y",
        "@sicario-labs/mcp"
      ],
      "env": {}
    }
  }
}
```

Once configured, Sicario's scanning tools appear in Cursor's command palette and can be invoked during development.

## Tools Exposed via MCP

Sicario exposes three primary tools over MCP:

### `analyze_ast_security`

Scans a specific file for vulnerabilities:

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `filePath` | string | Yes | Path to the file to scan (absolute or relative to project root) |

**Response:**

```json
{
  "file_path": "src/controllers/user.js",
  "vulnerabilities": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "rule_id": "js/sql-injection",
      "file_path": "src/controllers/user.js",
      "line": 42,
      "column": 10,
      "snippet": "connection.query(\"SELECT * FROM users WHERE id = \" + userId)",
      "severity": "High",
      "cwe_id": "CWE-89",
      "owasp_category": "A03_Injection"
    }
  ],
  "total": 1,
  "scan_engine": "tree-sitter"
}
```

> **Security note:** Snippets are truncated to 100 characters maximum. Full source code is never transmitted over the wire — this is part of Sicario's zero-exfiltration invariant.

### `request_remediation_patch`

Generates a deterministic patch for a specific vulnerability:

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `vulnerabilityId` | string | Yes | UUID of the vulnerability from a previous scan |
| `filePath` | string | Yes | Path to the file containing the vulnerability |

**Response:**

```json
{
  "vulnerability_id": "550e8400-e29b-41d4-a716-446655440000",
  "file_path": "src/controllers/user.js",
  "patch": "--- a/src/controllers/user.js\n+++ b/src/controllers/user.js\n@@ -42,5 +42,6 @@\n-connection.query(\"SELECT * FROM users WHERE id = \" + userId)\n+connection.query(\"SELECT * FROM users WHERE id = $1\", [userId])",
  "status": "queued",
  "message": "Patch generated. Review and apply with 'sicario fix --revert <id>' if needed."
}
```

> **Security note:** Patches are always `"queued"` — never auto-applied. The AI assistant must prompt the user to manually apply the patch, ensuring human oversight.

### `log_telemetry_audit`

Logs scan results to the zero-exfiltration audit trail:

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `projectId` | string | Yes | Project identifier |
| `scanResults` | array | Yes | Array of telemetry scan results |

**Telemetry scan result entry:**

```json
{
  "rule_id": "js/sql-injection",
  "severity": "High",
  "file_path": "src/controllers/user.js",
  "line": 42,
  "cwe_id": "CWE-89",
  "owasp_category": "A03_Injection"
}
```

> **Security note:** Telemetry entries contain only metadata (rule ID, severity, location) — no source code or payload data. The audit log is write-only and append-only.

## Running the MCP Server

### Via the CLI (built-in)

```bash
# Start the built-in MCP server (stdio mode)
sicario mcp
```

The built-in MCP server:
- Uses `stdin`/`stdout` for JSON-RPC communication
- Scans the current working directory by default
- All diagnostic output goes to `stderr`

### Via npx (npm package)

```bash
# Run the MCP server from npm
npx @sicario-labs/mcp

# With a custom project root
npx @sicario-labs/mcp --project /path/to/project

# With a custom port
npx @sicario-labs/mcp --port 8932
```

### Via the Sicario Cloud npm package

```bash
# Install globally
npm install -g @sicario-labs/mcp

# Run the MCP server
sicario-mcp --project /path/to/project
```

### TCP Mode (Advanced)

The MCP server also supports TCP transport for advanced use cases:

```bash
# Start TCP server on the default port (8931)
npx @sicario-labs/mcp --tcp

# Custom port
npx @sicario-labs/mcp --tcp --port 9000
```

In TCP mode, the server binds to `127.0.0.1` only — it is never accessible from remote hosts.

## Configuration Options

### CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--project` | `.` | Project root directory |
| `--port` | `8931` | TCP port (TCP mode only) |
| `--memory-db` | `.sicario/mcp_memory.db` | Path to Assistant Memory SQLite database |
| `--tcp` | `false` | Enable TCP transport instead of stdio |
| `--verbose` | `false` | Enable verbose logging to stderr |

### Environment Variables

| Variable | Description |
|---|---|
| `SICARIO_OLLAMA_ENDPOINT` | Custom Ollama endpoint for local AI remediation |
| `SICARIO_LLM_ENDPOINT` | Custom LLM endpoint for cloud AI remediation |
| `SICARIO_LLM_API_KEY` | API key for cloud LLM provider |
| `OPENAI_API_KEY` | OpenAI-specific API key (fallback) |
| `ANTHROPIC_API_KEY` | Anthropic-specific API key (fallback) |

## Security Considerations

### Local-Only Binding

The MCP server **always** binds to `127.0.0.1` (localhost) when running in TCP mode:

```rust
let addr = format!("127.0.0.1:{}", self.port);
let listener = TcpListener::bind(&addr)?;
```

This ensures the server is never accessible from the network. Only processes on the same machine can connect.

### No Remote Access

- The MCP server does **not** support TLS, authentication, or authorization
- It is designed for local AI assistant integration only
- Never expose the MCP server to a network socket (use a reverse proxy with authentication if remote access is required)

### Zero-Exfiltration in MCP Tools

All MCP tool responses respect Sicario's zero-exfiltration guarantees:

- **Snippets are truncated** to 100 characters maximum
- **Full source code is never returned** in scan results
- **Patches are always queued** — never auto-applied
- **Telemetry contains metadata only** — no source code or payload data

### Shell Execution Guard

The MCP server includes a `ShellExecutionGuard` that monitors for and blocks attempts to execute shell commands from within MCP tool responses, preventing prompt injection attacks.

## Assistant Memory

The `AssistantMemory` module provides persistent storage for AI assistant context across sessions:

```rust
pub struct AssistantMemory {
    db: Connection,  // SQLite
}
```

- Stores conversation context and tool usage history
- Persists across AI assistant restarts
- Located at `.sicario/mcp_memory.db` by default

This allows the AI assistant to remember previous scans, understand project context, and provide more relevant responses over time.

## Troubleshooting

### MCP Connection Issues

| Symptom | Likely Cause | Solution |
|---|---|---|
| Tools not showing up in Claude Desktop | Incorrect `claude_desktop_config.json` path | Verify config file location and JSON syntax |
| "Could not start MCP server" | `npx` not installed or network issue | Install Node.js, run `npx --version` |
| No response from tools | Project root path invalid | Check `--project` path exists |
| JSON-RPC parse error | Contaminant output on stdout | All pipeline errors must go to stderr |

### Debugging MCP Connections

```bash
# Start the MCP server with verbose logging
npx @sicario-labs/mcp --verbose

# Test with a manual JSON-RPC request
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | npx @sicario-labs/mcp
```

Expected output for `tools/list`:

```json
{"jsonrpc":"2.0","id":1,"result":{"tools":[
  {"name":"analyze_ast_security","description":"Scan a file for AST-based security vulnerabilities","inputSchema":{"type":"object","properties":{"filePath":{"type":"string"}},"required":["filePath"]}},
  {"name":"request_remediation_patch","description":"Generate a patch for a specific vulnerability","inputSchema":{"type":"object","properties":{"vulnerabilityId":{"type":"string"},"filePath":{"type":"string"}},"required":["vulnerabilityId","filePath"]}},
  {"name":"log_telemetry_audit","description":"Log scan results to the zero-exfiltration audit trail","inputSchema":{"type":"object","properties":{"projectId":{"type":"string"},"scanResults":{"type":"array","items":{"type":"object"}}},"required":["projectId","scanResults"]}}
]}}
```

### Assistant Not Recognizing Tools

1. **Restart the AI assistant** — Claude Desktop and Cursor need to reconnect to the MCP server
2. **Check the config path** — `claude_desktop_config.json` must be in the correct location
3. **Verify the command works** — run the command in a terminal first
4. **Check for errors in the assistant's logs** — Claude Desktop shows MCP errors in its developer console

### Logging

Since MCP uses stdout for JSON-RPC, all diagnostic output goes to stderr:

```bash
# Capture MCP diagnostics
npx @sicario-labs/mcp 2> mcp-debug.log
```

## Extending: Custom MCP Tools

The MCP server is designed to be extensible. To add custom tools, extend the dispatch function in `kiro_tools.rs`:

```rust
// Register a new tool handler
fn dispatch(&self, request: &JsonRpcRequest) -> String {
    match request.method.as_str() {
        "tools/list" => self.handle_tools_list(),
        "tools/call" => self.handle_tools_call(request),
        "analyze_ast_security" => self.handle_analyze_ast(request),
        "request_remediation_patch" => self.handle_remediation_patch(request),
        "log_telemetry_audit" => self.handle_telemetry_audit(request),
        // Add new tools here
        _ => serialize_error(request.id, -32601, "Method not found"),
    }
}
```

Each tool handler receives the parsed JSON-RPC request and returns a response string. The handler can access the SAST engine, vulnerability cache, and assistant memory through the server's shared state.

## Best Practices

### For AI Assistant Users

1. **Use specific file paths** — `analyze_ast_security` only scans one file at a time; be specific about which file to scan
2. **Review patches before applying** — patches are always queued for review
3. **Run full scans via CLI** — for comprehensive audits, use `sicario scan .` directly
4. **Keep project root consistent** — always use the same `--project` path to maintain assistant memory continuity

### For Developers Integrating MCP

1. **Prefer stdio over TCP** — stdio is simpler, more secure, and easier to debug
2. **Never expose MCP over the network** — the server has no authentication
3. **Monitor stderr for diagnostics** — stdout is strictly for JSON-RPC
4. **Use `--verbose` during development** — see every request/response pair
5. **Initialize the SAST engine once** — the engine is thread-safe and cached for performance

## Related

- [SAST Scanning](sast-scanning.md) — the engine behind `analyze_ast_security`
- [Auto-Remediation](auto-remediation.md) — the engine behind `request_remediation_patch`
- [Reporting](reporting.md) — the engine behind `log_telemetry_audit`
- [Secret Detection](secrets-detection.md) — available via SAST engine scan

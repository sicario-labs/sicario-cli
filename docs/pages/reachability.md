---
sidebar:
  badge:
    text: Capabilities
---

# Reachability Analysis

> Reachability analysis determines whether a vulnerability can actually be exploited by tracking the flow of untrusted data from external input sources to vulnerable sink functions. Sicario's inter-procedural taint analysis eliminates false positives from code that is never exposed to attacker-controlled input.

## Overview

A SQL injection in a function that is only called from an admin-only internal dashboard is **not exploitable** by an external attacker — it's a code quality issue, not a security vulnerability. But a SQL injection in an API endpoint that accepts user input is a critical exploit risk.

Sicario's reachability analyzer distinguishes between these cases by:

1. **Building an inter-procedural call graph** — maps every function and its callers across all source files
2. **Identifying taint sources** — framework-specific patterns for HTTP requests, environment variables, and file reads
3. **Performing forward data-flow analysis** — BFS from taint sources through all reachable functions
4. **Marking findings** — each vulnerability is annotated as reachable or not reachable

## Data-Flow Reachability

### What Reachability Tells You

| Finding | Reachable | Meaning |
|---|---|---|
| SQL injection in `handleUserRequest(req)` | ✅ Yes | User input can reach this function — **exploitable** |
| SQL injection in `internalReportGenerator()` | ❌ No | No external input path — **not exploitable in default config** |
| Command injection `buildQuery(body)` | ✅ Yes | HTTP request body flows to sink |
| XSS in `formatErrorMessage(msg)` | ✅ Yes | Error message includes user input |

### How It Reduces False Positives

Without reachability, every pattern match is a finding. With reachability, findings are **prioritized** by exploitability:

```text
Without reachability:  150 findings (50 Critical, 60 High, 40 Medium)
With reachability:     45 findings (30 Critical, 12 High, 3 Medium)
                           ↓                        ↓
                   105 false positives eliminated  Focus on actionable
```

## Inter-Procedural Taint Analysis

### Architecture

```
Source Files
    ↓
Language::from_path()  → detect language per file
    ↓
extract_functions_from_file()  → parse AST, find function definitions
    ↓
build_call_graph()  → connect callers to callees (cross-file)
    ↓
mark_taint_sources()  → identify framework input points
    ↓
is_reachable()  → BFS from taint sources to vulnerability sink
    ↓
reachable: true/false
```

### The Call Graph

The `CallGraph` is a directed graph where:

- **Nodes** are `FunctionNode` structs (name, file, line, parameters, taint status)
- **Edges** are call relationships (caller → callee)
- **Taint sources** are functions that receive external input

```rust
pub struct FunctionNode {
    pub id: FunctionId,
    pub name: String,
    pub file_path: PathBuf,
    pub line: usize,
    pub calls: Vec<FunctionId>,       // Functions this one calls
    pub called_by: Vec<FunctionId>,   // Functions that call this one
    pub parameters: Vec<Parameter>,
    pub is_taint_source: bool,        // Receives external input
}

pub struct CallGraph {
    pub nodes: HashMap<FunctionId, FunctionNode>,
    pub edges: Vec<(FunctionId, FunctionId)>,
}
```

### Cross-File Edge Resolution

Call edges are resolved across file boundaries. When function `handler` in `routes.js` calls `buildQuery` in `db.js`, the analyzer:

1. Parses `routes.js` — finds `handler` function and its call to `buildQuery`
2. Parses `db.js` — finds `buildQuery` function definition
3. Creates an edge: `handler` → `buildQuery`

```javascript
// routes.js
function handler(req) {
    const result = buildQuery(req.body);  // → cross-file call to db.js
    return result;
}
```

```javascript
// db.js
function buildQuery(params) {
    return "SELECT * FROM users WHERE id = " + params.id;  // SQL injection sink
}
```

If a function name is defined in **multiple** files, the analyzer conservatively skips the edge (no ambiguous resolution):

```rust
// Only wire the edge if exactly one callee candidate exists across all files
let matching_nodes: Vec<FunctionId> = self.call_graph.nodes.values()
    .filter(|n| n.name == callee_name)
    .map(|n| n.id)
    .collect();

let callee_id = if matching_nodes.len() == 1 {
    Some(matching_nodes[0])
} else {
    None  // Ambiguous → skip (conservative)
};
```

## Source-to-Sink Tracing

### Taint Sources

Sicario detects taint sources across multiple languages and frameworks:

| Source Type | Language | Pattern | Examples |
|---|---|---|---|
| HTTP Request | Python | `request.GET` / `request.POST` attribute access | Django views |
| HTTP Request | Python | FastAPI typed parameters (`Request`, `Body`, `Query`) | FastAPI endpoints |
| HTTP Request | JS/TS | `req.query`, `req.body`, `req.params` | Express/Node.js |
| User Input | JS/TS | React props (`value`, `onChange`, `onInput`) | React components |
| HTTP Call | JS/TS | `fetch()`, `axios.get()`, `request()` | HTTP clients |
| Environment Var | JS/TS | `process.env.SOMETHING` | Node.js |
| Environment Var | Python | `os.environ` / `os.getenv()` | Python |
| File Read | JS/TS/Python | `fs.readFile()`, `open()` | I/O operations |

### Taint Source Detection

Taint sources are detected using language-specific Tree-sitter query patterns:

```rust
// Python / Django: request.GET/post attribute access
TaintSource {
    source_type: SourceType::HttpRequest,
    pattern: r#"(attribute
        object: (identifier) @obj
        attribute: (identifier) @attr
    ) @django_input"#,
}

// JavaScript: process.env access
TaintSource {
    source_type: SourceType::EnvironmentVariable,
    pattern: r#"(member_expression
        object: (member_expression
            object: (identifier) @proc (#match? @proc "process")
            property: (property_identifier) @env (#match? @env "env")
        )
    ) @env_read_js"#,
}
```

### Sinks

Vulnerable functions (sinks) are identified by the SAST rule engine. Common sinks include:

| Rule | Sink Function |
|---|---|
| SQL Injection | `connection.query()`, `cursor.execute()`, `db.exec()` |
| Command Injection | `exec()`, `execSync()`, `spawn()`, `child_process` |
| XSS | `innerHTML`, `dangerouslySetInnerHTML`, `document.write()` |
| Path Traversal | `fs.readFile()`, `path.join()`, file open calls |

## Taint Propagation

Taint propagates through:

- **Assignments**: `const x = userInput;` — x is tainted
- **Function calls**: `process(userInput)` — callee receives taint
- **Returns**: `return taintedValue;` — caller receives taint
- **Object properties**: `req.body.name` — property access preserves taint

### Worklist Algorithm

The reachability analyzer uses a **BFS worklist** with fixed-point iteration:

```rust
fn reachable_from_sources(&self) -> HashSet<FunctionId> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();

    // Seed with all taint sources
    for id in self.call_graph.taint_source_ids() {
        if visited.insert(id) { queue.push_back(id); }
    }

    // Forward BFS through call edges
    while let Some(current) = queue.pop_front() {
        if let Some(node) = self.call_graph.nodes.get(&current) {
            for &callee in &node.calls {
                if visited.insert(callee) {
                    queue.push_back(callee);
                }
            }
        }
    }
    visited
}
```

## Confidence Scoring with Reachability

Reachability data feeds into the confidence scoring system:

| Condition | Confidence Boost | Interpretation |
|---|---|---|
| Pattern matched + reachable | Full confidence | Exploitable vulnerability |
| Pattern matched + not reachable | Reduced confidence | Code quality issue |
| Pattern matched + reachable + cloud-exposed | Maximum confidence | Publicly exploitable |
| Taint path fully traced | Evidence available | Exact exploit path mapped |

### Cloud Exposure Detection

When `--no-cloud` is not set, Sicario detects cloud exposure by scanning for Kubernetes manifests and other deployment configurations. A finding that is both reachable and cloud-exposed is marked as the highest priority:

```json
{
  "reachable": true,
  "cloud_exposed": true
}
```

## Understanding Reachability Output

### Terminal Output

With `--trace`, findings include a box-drawing taint trace:

```text
  ┌─ TAINT TRACE: sql-injection in src/db/queries.js:42 ─────────────────────
  │
  │  [1] src/routes/user.js:12  handleUserRequest
  │      ↳ External input enters here
  │
  │  [2] src/services/user.js:34  getUserById
  │      ↳ Tainted data flows through `getUserById`
  │
  │  [3] src/db/queries.js:42  buildQuery  ← SINK
  │      ↳ Tainted value reaches SQL query construction
  │
  │  Attack vector: 3 functions across 3 files
  └───────────────────────────────────────────────────────────────────────────
```

### JSON Output with Taint Data

```json
{
  "findings": [
    {
      "rule_id": "js/sql-injection",
      "reachable": true,
      "cloud_exposed": true,
      "taint_path": [
        {
          "file": "src/routes/user.js",
          "line": 12,
          "function": "handleUserRequest",
          "description": "External input enters here"
        },
        {
          "file": "src/db/queries.js",
          "line": 42,
          "function": "buildQuery",
          "description": "Tainted value reaches SQL query construction"
        }
      ]
    }
  ]
}
```

### Taint Trace Rendering

The `TaintTrace::render()` method produces the box-drawing output:

```rust
pub fn render(&self) -> String {
    let width = 76usize;
    let header = format!("TAINT TRACE: {} in {}:{}",
        self.sink_rule_id, self.sink_file.display(), self.sink_line);

    let mut out = String::new();
    out.push_str(&format!("  ┌─ {} {}\n", header_display, "─".repeat(top_fill)));
    out.push_str(&format!("  │{}\n", " ".repeat(width)));

    for (i, step) in self.steps.iter().enumerate() {
        let is_sink = i == self.steps.len() - 1;
        let sink_marker = if is_sink { "  ← SINK" } else { "" };
        out.push_str(&format!("  [{}] {}:{}  {}{}\n",
            i + 1, step.file.display(), step.line, step.function_name, sink_marker));
        out.push_str(&format!("  │      ↳ {}\n", step.description));
    }
    // ...
}
```

## Advanced: Custom Sources and Sinks

### Configuring Custom Taint Sources

Custom taint sources can be added via configuration:

```yaml
# .sicario/config.yaml
reachability:
  taint_sources:
    - source_type: HttpRequest
      language: JavaScript
      pattern: "(call_expression function: (identifier) @fn (#eq? @fn \"myCustomParser\")) @src"
    - source_type: FileRead
      language: Python
      pattern: "(call function: (attribute object: (identifier) @mod (#eq? @mod \"myapp\") attribute: (identifier) @fn (#eq? @fn \"read_input\"))) @src"
```

### Custom Sinks

You can mark additional functions as sinks in your custom SAST rules. Any function that receives tainted data and is flagged by a rule becomes a sink node in the call graph.

## Best Practices for Triage

### Prioritization Matrix

| Reachable | Cloud-Exposed | Action |
|---|---|---|
| ✅ Yes | ✅ Yes | **Fix immediately** — publicly exploitable |
| ✅ Yes | ❌ No | **Fix this sprint** — exploitable in default config |
| ❌ No | ✅ Yes | **Review** — not directly on input path but cloud-exposed |
| ❌ No | ❌ No | **Defer or suppress** — code quality issue |

### Using `--fail-on-reachable`

For strict CI/CD pipelines, use `--fail-on-reachable` to only fail on vulnerabilities that are actually exploitable:

```bash
# Only fail on reachable SCA vulnerabilities
sicario scan . --sca --fail-on-reachable

# Only surface reachable findings
sicario scan . --taint --min-severity high
```

### Performance Considerations

Building the call graph requires parsing all source files. For large codebases:

```bash
# Disable taint analysis for faster scans
sicario scan . --no-cloud
```

## Troubleshooting

### Missing Traces

| Symptom | Likely Cause | Solution |
|---|---|---|
| `taint_path` is empty | Taint analysis not enabled | Add `--taint` flag |
| No trace for clearly reachable vuln | Cross-file call ambiguity | Check if callee name is unique across files |
| Trace stops at module boundary | Static analysis limitation | Sicario traces pure function calls; dynamic dispatch (callbacks, method overrides) may not be captured |

### False Negatives in Complex Flows

Sicario's taint analysis is **trade-off optimized for correctness over completeness**:

- **Conservative edge creation** — ambiguous callees (same name in multiple files) are skipped rather than guessed
- **No dynamic dispatch analysis** — polymorphic calls, decorators, and monkey-patching are assumed opaque
- **No array/object path tracking** — `arr[0].field` is not traced beyond the immediate assignment

### False Positives

- **Entry point function not recognized** — if the call graph doesn't include the framework entry point (e.g., `app.get('/route', handler)` doesn't automatically link `'/route'` as a taint source), the handler is marked unreachable
- **To fix**: ensure framework entry points are included in the scanned files, or add custom taint source patterns

### Debugging Reachability

```bash
# Enable verbose output to see call graph construction
sicario scan . --taint --verbose

# Check which functions are detected as taint sources
# (look for "External input enters here" in traces)
```

## Related

- [SAST Scanning](sast-scanning.md) — the vulnerability detection engine
- [SCA Scanning](sca-scanning.md) — reachability-gated dependency analysis
- [Auto-Remediation](auto-remediation.md) — prioritizing fixes by reachability
- [Reporting](reporting.md) — SARIF output includes reachability data

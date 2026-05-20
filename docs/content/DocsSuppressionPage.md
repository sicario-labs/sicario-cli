> **Integration**

# Suppressions

Suppressions allow you to mark specific findings as ignored directly in your source code using inline comments. This is useful for:

- **Acceptable risk**: A finding is a known false positive or is in non-production code
- **Third-party code**: Vendored dependencies that you cannot modify
- **Documented exceptions**: Findings that have been reviewed and approved by the security team
- **Legacy code**: Pre-existing issues that will be fixed in a future sprint

---

## Inline Suppression Directives

Sicario supports four types of inline suppression directives, each with a different scope.

### Directive Reference

| Directive | Scope | Example |
|-----------|-------|---------|
| `// sicario-ignore` | Suppress **all rules** for the **entire file** | `// sicario-ignore` at the top of the file |
| `// sicario-ignore-next-line` | Suppress **all rules** for the **next line** | `// sicario-ignore-next-line` followed by the vulnerable line |
| `// sicario-ignore:<rule-id>` | Suppress a **specific rule** for the **entire file** | `// sicario-ignore:js/sql-injection` |
| `// sicario-ignore:<rule-id>,<rule-id>` | Suppress **multiple specific rules** for the **entire file** | `// sicario-ignore:js/sql-injection,js/xss` |

> **Note**: The `// sicario-ignore` directive (without a rule ID) applies to **all rules** and suppresses **every finding** in the file. Use it sparingly — it is a blunt instrument. Prefer `// sicario-ignore:<rule-id>` when you only need to suppress a specific rule.

### Comment Syntax by Language

Sicario recognizes the comment syntax appropriate for each language:

**JavaScript / TypeScript**
```javascript
// sicario-ignore-next-line
eval(userInput);

// sicario-ignore:js/sql-injection
const query = "SELECT * FROM users WHERE id = " + id;
```

**Python**
```python
# sicario-ignore-next-line
import pickle

# sicario-ignore:py/insecure-deserialization
data = pickle.loads(user_input)
```

**Go**
```go
// sicario-ignore
package legacy

// sicario-ignore-next-line
password := "hardcoded"
```

**Java**
```java
// sicario-ignore-next-line
Process p = Runtime.getRuntime().exec(cmd);

// sicario-ignore:java/command-injection
String result = executeCommand(userInput);
```

**Rust**
```rust
// sicario-ignore:rust/insecure-hash
let hash = std::collections::hash_map::DefaultHasher::new();

// sicario-ignore-next-line
let password = "hunter2";
```

**Ruby**
```ruby
# sicario-ignore-next-line
system(params[:cmd])

# sicario-ignore:ruby/command-injection
result = `#{user_input}`
```

**PHP**
```php
// sicario-ignore:php/sql-injection
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

// sicario-ignore-next-line
eval($_POST['code']);
```

**C#**
```csharp
// sicario-ignore-next-line
Process.Start(userInput);

// sicario-ignore:csharp/command-injection
var result = await RunCommandAsync(userInput);
```

**HTML / Templates**
```html
<!-- sicario-ignore -->
<script>var x = <%= data %></script>

<!-- sicario-ignore-next-line -->
<div>{{ userInput }}</div>
```

### Rule ID Format

Rule IDs follow the convention `<language>/<vulnerability-type>`:

| Language Prefix | Example Rule ID |
|-----------------|-----------------|
| `js/` | `js/sql-injection` |
| `ts/` | `ts/any-type` |
| `py/` | `py/insecure-deserialization` |
| `go/` | `go/command-injection` |
| `java/` | `java/xxe` |
| `rs/` | `rs/insecure-hash` |
| `rb/` | `rb/sql-injection` |
| `php/` | `php/ssrf` |
| `cs/` | `cs/insecure-deserialization` |
| `secrets/` | `secrets/aws-access-key` |
| `sca/` | `sca/CVE-2024-1234` |

To find the exact rule ID for a finding, run a scan and look at the rule ID in the output:

```bash
sicario scan .
# Output shows: [js/sql-injection] src/api/users.ts:142  High
```

---

## Suppressions in Config File vs Inline

You can also suppress findings using the project config file (`./sicario/config.yaml`):

```yaml
# .sicario/config.yaml
ignore:
  patterns:
    - "tests/**"
    - "vendor/**"

  findings:
    - rule: js/no-console
      paths:
        - "src/cli/**"
        - "scripts/**"
```

### When to Use Each

| Method | Use Case | Pros | Cons |
|--------|----------|------|------|
| **Inline** `// sicario-ignore` | Specific lines or files | Self-documenting (co-located with code), survives file moves | Scattered across codebase, harder to audit centrally |
| **Config file** `ignore.findings` | Entire directories or patterns | Centralized management, easier to bulk-suppress | May suppress findings unexpectedly after refactors |
| **Config file** `ignore.patterns` | Whole file types or directories | Clean, no code changes needed | Blunt — suppresses everything in matched paths |

> **Recommendation**: Use inline suppressions for targeted, line-specific exceptions. Use config file suppressions for entire directories (e.g., tests, vendor code). Always document **why** a suppression is applied.

---

## Best Practices

### 1. Always Comment Why

A suppression without a reason is a ticking time bomb. Always add a comment explaining why the finding is acceptable:

```javascript
// sicario-ignore-next-line
// Safe: userInput is validated by the middleware layer before reaching this handler
eval(userInput);
```

```python
# sicario-ignore:py/insecure-deserialization
# Accepted risk: This function only processes internal queue messages
# from a trusted source (validated by HMAC signature)
data = pickle.loads(msg.payload)
```

### 2. Audit Suppressions Periodically

Use the `sicario suppressions audit` command to review all active suppressions with git attribution:

```bash
# List all suppressions with git blame information
sicario suppressions audit

# Export to CSV for tracking
sicario suppressions audit --format csv --output suppression-audit.csv

# Filter suppressions by author
sicario suppressions audit --author "jane@company.com"

# Filter suppressions since a specific date
sicario suppressions audit --since 2025-01-01
```

Audit output example:

```json
[
  {
    "file": "src/api/legacy.ts",
    "line": 42,
    "rule_id": "js/sql-injection",
    "directive": "// sicario-ignore-next-line",
    "author": "jane@company.com",
    "date": "2024-03-15",
    "commit": "a1b2c3d4",
    "comment": "Safe: input validated by middleware"
  },
  {
    "file": "src/worker/tasks.py",
    "line": 67,
    "rule_id": "py/insecure-deserialization",
    "directive": "# sicario-ignore:py/insecure-deserialization",
    "author": "bob@company.com",
    "date": "2023-11-20",
    "commit": "e5f6g7h8",
    "comment": null
  }
]
```

> **Warning**: The third entry has `"comment": null` — this suppression was added without a justification and should be reviewed immediately.

### 3. Review Suppressions in Code Review

When a developer adds a `// sicario-ignore` directive, it should be treated as a code review item:

- **Is the suppression justified?** (false positive, acceptable risk, third-party code)
- **Is the scope appropriate?** (specific rule vs all rules, single line vs entire file)
- **Is there a tracking issue?** (e.g., a Jira ticket to resolve the underlying issue)

### 4. Set Expiration Dates

Consider adding an expiration convention to your suppression comments:

```javascript
// sicario-ignore-next-line
// TODO: Fix by Q3 2025 — https://jira.company.com/browse/SEC-1234
eval(userInput);
```

### 5. Use `--no-ignore-comments` for Security Audits

During security audits or penetration tests, override all suppressions to ensure nothing is hidden:

```bash
# Force all suppressions to be ignored in the output
sicario scan . --no-ignore-comments
```

This sets `suppressed = false` on every suppressed finding, so they appear in the output and affect the exit code.

---

## Viewing Suppressed Findings

By default, suppressed findings are **excluded** from output and do not affect the exit code. To see which findings are suppressed:

### JSON Output

Suppressed findings still appear in JSON output but with `suppressed: true`:

```json
[
  {
    "rule_id": "js/sql-injection",
    "file": "src/api/legacy.ts",
    "line": 42,
    "severity": "High",
    "suppressed": true,
    "suppression_comment": "// sicario-ignore-next-line"
  }
]
```

### Audit Command

The `sicario suppressions audit` command provides a comprehensive report of all suppressions:

```bash
sicario suppressions audit
```

### Text Output with `--no-ignore-comments`

```bash
sicario scan . --no-ignore-comments
```

This will include previously-suppressed findings in the text output flagged with a note about their suppression.

---

## Troubleshooting

### Suppression Not Working

**Problem**: A `// sicario-ignore` directive is not suppressing a finding.

**Solutions**:

1. **Check the comment syntax**:
   - Is it the correct comment style for the language? (e.g., `#` in Python, `//` in JS, `<!-- -->` in HTML)
   - Is there a space after the comment marker? `// sicario-ignore` ✅ vs `//sicario-ignore` ❌
   - Is the directive on the correct line? `// sicario-ignore-next-line` must be immediately before the suppressed line

2. **Check the rule ID**: If using `// sicario-ignore:<rule-id>`, verify the rule ID is correct:
   ```bash
   sicario scan . --format json | jq '.[].rule_id' | sort -u
   ```

3. **Check for typos**: `sicario-ignore` (not `sicario-ignore` — note the 'i' in 'sicario')

4. **Check for inline suppression conflicts**: If `--no-ignore-comments` was passed, all suppressions are overridden

### Wrong Rule ID

**Problem**: The rule ID in `// sicario-ignore:<rule-id>` doesn't match any rule.

**Finding the correct rule ID**:

```bash
# Scan a single file and extract rule IDs
sicario scan src/file.js --format json | jq '.[].rule_id'
```

```bash
# List all available rules
sicario rules list
```

### Suppression Affects Too Many Findings

**Problem**: Using `// sicario-ignore` (without a rule ID) is suppressing more findings than intended.

**Solution**: Be more specific. Use `// sicario-ignore:<rule-id>` to target a specific rule, or use `// sicario-ignore-next-line` to target a single line.

### Suppression Audit Shows Unexpected Suppressions

**Problem**: Running `sicario suppressions audit` reveals suppressions that were not intentionally added (e.g., from a library or template).

**Solutions**:

1. Add the file patterns to your `.sicarioignore` file or project config's `ignore.patterns`
2. The audit output includes the git author and commit — use this to track down the source

---

## Security Considerations

### Don't Suppress Without Review

A suppression is a security decision. Every suppression should be:

1. **Reviewed** by at least one other team member
2. **Documented** with a comment explaining the rationale
3. **Tracked** with an issue or ticket for follow-up
4. **Time-boxed** with an expected resolution date

### Suppressions Are Not Security Fixes

A suppressed finding is still a potential vulnerability. Suppression means you have accepted the risk, not that the risk has been eliminated.

### Periodic Suppression Audits

Use the `sicario suppressions audit` command in your CI/CD pipeline or as a recurring task:

```yaml
# .github/workflows/suppression-audit.yml
name: Suppression Audit
on:
  schedule:
    - cron: '0 0 1 * *'  # Monthly
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for git blame
      - name: Install Sicario
        run: curl -fsSL https://usesicario.xyz/install.sh | sh
      - name: Run Suppression Audit
        run: |
          sicario suppressions audit --format csv --output suppression-audit.csv
      - name: Upload Audit Report
        uses: actions/upload-artifact@v4
        with:
          name: suppression-audit
          path: suppression-audit.csv
```

---

## Related

- [Baseline Management](./baseline) — Suppressing known issues across versions
- [Configuration](./configuration) — Project-level ignore patterns
- [CI/CD Integration](./ci-cd) — Using `--no-ignore-comments` in CI
- [CLI Reference](./cli-reference) — Full `suppressions` subcommand reference

---

## Next Steps

1. Review [existing suppressions](./#viewing-suppressed-findings) in your project with `sicario suppressions audit`
2. Establish a [suppression policy](./#security-considerations) for your team
3. Configure [project-level ignore patterns](./#suppressions-in-config-file-vs-inline) for test and vendor directories
4. Add the [suppression audit](./#periodic-suppression-audits) to your CI/CD schedule
5. Discuss suppression best practices during your next security review

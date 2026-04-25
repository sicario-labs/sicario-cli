import { describe, it, expect } from "vitest";
import { PR_SAST_RULES } from "../prSastRules";
import { scanFiles, type FileToScan } from "../prSastEngine";

// ── Helper ──────────────────────────────────────────────────────────────────

const META = { repository: "test/repo", branch: "main", commitSha: "abc123" };

/**
 * Run a single rule against a code snippet and return findings.
 */
function testRule(
  ruleId: string,
  code: string,
  language: string,
  filePath: string,
) {
  const rule = PR_SAST_RULES.find((r) => r.id === ruleId);
  if (!rule) throw new Error(`Rule not found: ${ruleId}`);

  const files: FileToScan[] = [{ path: filePath, content: code, language }];
  const report = scanFiles(files, [rule], META);
  return report.findings;
}

// ── JavaScript Rules ────────────────────────────────────────────────────────

describe("JavaScript rule matching", () => {
  describe("js-sql-string-concat", () => {
    it("TruePositive: detects SQL string concatenation", () => {
      const findings = testRule(
        "js-sql-string-concat",
        'const query = "SELECT * FROM users WHERE id = " + userId;',
        "JavaScript",
        "src/db.js",
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it("TrueNegative: ignores parameterized query", () => {
      const findings = testRule(
        "js-sql-string-concat",
        'const query = "SELECT * FROM users WHERE id = ?";',
        "JavaScript",
        "src/db.js",
      );
      expect(findings.length).toBe(0);
    });
  });

  describe("js-xss-innerhtml-assignment", () => {
    it("TruePositive: detects innerHTML assignment", () => {
      const findings = testRule(
        "js-xss-innerhtml-assignment",
        "element.innerHTML = userInput;",
        "JavaScript",
        "src/render.js",
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it("TrueNegative: ignores textContent assignment", () => {
      const findings = testRule(
        "js-xss-innerhtml-assignment",
        "element.textContent = userInput;",
        "JavaScript",
        "src/render.js",
      );
      expect(findings.length).toBe(0);
    });
  });

  describe("js-eval-usage", () => {
    it("TruePositive: detects eval call", () => {
      const findings = testRule(
        "js-eval-usage",
        "eval(userInput);",
        "JavaScript",
        "src/exec.js",
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it("TrueNegative: ignores JSON.parse", () => {
      const findings = testRule(
        "js-eval-usage",
        "JSON.parse(userInput);",
        "JavaScript",
        "src/exec.js",
      );
      expect(findings.length).toBe(0);
    });
  });
});

// ── Python Rules ────────────────────────────────────────────────────────────

describe("Python rule matching", () => {
  describe("py-os-system", () => {
    it("TruePositive: detects os.system call", () => {
      const findings = testRule(
        "py-os-system",
        'os.system("rm -rf " + user_input)',
        "Python",
        "scripts/run.py",
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it("TrueNegative: ignores subprocess.run with list args", () => {
      const findings = testRule(
        "py-os-system",
        "subprocess.run(['rm', '-rf', path])",
        "Python",
        "scripts/run.py",
      );
      expect(findings.length).toBe(0);
    });
  });

  describe("py-exec-usage", () => {
    it("TruePositive: detects exec call", () => {
      const findings = testRule(
        "py-exec-usage",
        "exec(\"os.system('rm -rf /')\")",
        "Python",
        "scripts/danger.py",
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it("TrueNegative: ignores print call", () => {
      const findings = testRule(
        "py-exec-usage",
        'print("done")',
        "Python",
        "scripts/safe.py",
      );
      expect(findings.length).toBe(0);
    });
  });

  describe("py-pickle-loads", () => {
    it("TruePositive: detects pickle.loads", () => {
      const findings = testRule(
        "py-pickle-loads",
        "pickle.loads(data)",
        "Python",
        "scripts/deser.py",
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it("TrueNegative: ignores json.loads", () => {
      const findings = testRule(
        "py-pickle-loads",
        "json.loads(data)",
        "Python",
        "scripts/deser.py",
      );
      expect(findings.length).toBe(0);
    });
  });
});

// ── Java Rules ──────────────────────────────────────────────────────────────

describe("Java rule matching", () => {
  describe("java-sqli-statement-concat", () => {
    it("TruePositive: detects executeQuery with concatenation", () => {
      const findings = testRule(
        "java-sqli-statement-concat",
        'stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);',
        "Java",
        "src/Dao.java",
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it("TrueNegative: ignores prepared statement executeQuery", () => {
      const findings = testRule(
        "java-sqli-statement-concat",
        "pstmt.executeQuery();",
        "Java",
        "src/Dao.java",
      );
      expect(findings.length).toBe(0);
    });
  });

  describe("java-runtime-exec", () => {
    it("TruePositive: detects Runtime.exec", () => {
      const findings = testRule(
        "java-runtime-exec",
        "Runtime.getRuntime().exec(command);",
        "Java",
        "src/Exec.java",
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it("TrueNegative: ignores ProcessBuilder", () => {
      const findings = testRule(
        "java-runtime-exec",
        "ProcessBuilder pb = new ProcessBuilder(args);",
        "Java",
        "src/Exec.java",
      );
      expect(findings.length).toBe(0);
    });
  });

  describe("java-deserialization", () => {
    it("TruePositive: detects ObjectInputStream", () => {
      const findings = testRule(
        "java-deserialization",
        "ObjectInputStream ois = new ObjectInputStream(input);",
        "Java",
        "src/Deser.java",
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it("TrueNegative: ignores BufferedReader", () => {
      const findings = testRule(
        "java-deserialization",
        "BufferedReader reader = new BufferedReader(input);",
        "Java",
        "src/Deser.java",
      );
      expect(findings.length).toBe(0);
    });
  });
});

// ── Go Rules ────────────────────────────────────────────────────────────────

describe("Go rule matching", () => {
  describe("go-sql-string-concat", () => {
    it("TruePositive: detects Query with concatenation", () => {
      const findings = testRule(
        "go-sql-string-concat",
        'db.Query("SELECT * FROM users WHERE id = " + id)',
        "Go",
        "main.go",
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it("TrueNegative: ignores parameterized query", () => {
      const findings = testRule(
        "go-sql-string-concat",
        'db.Query("SELECT * FROM users WHERE id = $1", id)',
        "Go",
        "main.go",
      );
      expect(findings.length).toBe(0);
    });
  });

  describe("go-cmd-exec", () => {
    it("TruePositive: detects exec.Command", () => {
      const findings = testRule(
        "go-cmd-exec",
        'exec.Command("bash", "-c", userInput)',
        "Go",
        "cmd/run.go",
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it("TrueNegative: ignores os.Getenv", () => {
      const findings = testRule(
        "go-cmd-exec",
        'os.Getenv("PATH")',
        "Go",
        "cmd/run.go",
      );
      expect(findings.length).toBe(0);
    });
  });

  describe("go-tls-insecure", () => {
    it("TruePositive: detects InsecureSkipVerify true", () => {
      const findings = testRule(
        "go-tls-insecure",
        "InsecureSkipVerify: true",
        "Go",
        "tls/config.go",
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it("TrueNegative: ignores InsecureSkipVerify false", () => {
      const findings = testRule(
        "go-tls-insecure",
        "InsecureSkipVerify: false",
        "Go",
        "tls/config.go",
      );
      expect(findings.length).toBe(0);
    });
  });
});

// ── Rust Rules ──────────────────────────────────────────────────────────────

describe("Rust rule matching", () => {
  describe("rs-sql-format", () => {
    it("TruePositive: detects format! with SQL", () => {
      const findings = testRule(
        "rs-sql-format",
        'format!("SELECT * FROM users WHERE id = {}", id)',
        "Rust",
        "src/db.rs",
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it("TrueNegative: ignores parameterized sqlx query", () => {
      const findings = testRule(
        "rs-sql-format",
        'sqlx::query("SELECT * FROM users WHERE id = $1")',
        "Rust",
        "src/db.rs",
      );
      expect(findings.length).toBe(0);
    });
  });

  describe("rs-command-exec", () => {
    it("TruePositive: detects Command::new", () => {
      const findings = testRule(
        "rs-command-exec",
        'Command::new("bash")',
        "Rust",
        "src/exec.rs",
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it("TrueNegative: ignores PathBuf::from", () => {
      const findings = testRule(
        "rs-command-exec",
        'let path = PathBuf::from("bash");',
        "Rust",
        "src/exec.rs",
      );
      expect(findings.length).toBe(0);
    });
  });

  describe("rs-unsafe-block", () => {
    it("TruePositive: detects unsafe block", () => {
      const findings = testRule(
        "rs-unsafe-block",
        "unsafe { ptr::read(addr) }",
        "Rust",
        "src/mem.rs",
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it("TrueNegative: ignores safe function call", () => {
      const findings = testRule(
        "rs-unsafe-block",
        "let safe_val = some_fn();",
        "Rust",
        "src/mem.rs",
      );
      expect(findings.length).toBe(0);
    });
  });
});

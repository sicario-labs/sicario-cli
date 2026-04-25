import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import {
  detectLanguage,
  scanFiles,
  type SastRule,
  type FileToScan,
} from "../prSastEngine";

// ── Test fixture rules ──────────────────────────────────────────────────────
// Simple regex rules that match common patterns so the property test can
// generate findings reliably.

const TEST_RULES: SastRule[] = [
  {
    id: "test-console-log",
    name: "Console Log Usage",
    description: "Detects console.log statements",
    severity: "Low",
    languages: ["JavaScript", "TypeScript"],
    pattern: /console\.log/,
    cweId: "CWE-200",
    owaspCategory: "A09_Logging",
  },
  {
    id: "test-eval-usage",
    name: "Eval Usage",
    description: "Detects eval() calls",
    severity: "Critical",
    languages: ["JavaScript", "TypeScript"],
    pattern: /eval\s*\(/,
    cweId: "CWE-95",
    owaspCategory: "A03_Injection",
  },
  {
    id: "test-exec-usage",
    name: "Exec Usage",
    description: "Detects exec() calls in Python",
    severity: "High",
    languages: ["Python"],
    pattern: /exec\s*\(/,
    cweId: "CWE-78",
    owaspCategory: "A03_Injection",
  },
];

// ── Generators ──────────────────────────────────────────────────────────────

const languageExtensions: Record<string, string[]> = {
  JavaScript: [".js", ".jsx"],
  TypeScript: [".ts", ".tsx"],
  Python: [".py"],
};

const supportedLanguages = Object.keys(languageExtensions);

/** Generate a valid file path with a supported extension. */
/** Arbitrary alphanumeric segment for path components. */
const arbSegment = fc
  .array(fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz0123456789_"), {
    minLength: 1,
    maxLength: 12,
  })
  .map((chars) => chars.join(""));

const arbFilePath = fc
  .tuple(
    // directory segments (0-3 segments)
    fc.array(arbSegment, { minLength: 0, maxLength: 3 }),
    // filename (without extension)
    arbSegment,
    // language choice
    fc.constantFrom(...supportedLanguages),
    // extension index
    fc.nat(),
  )
  .map(([dirs, name, lang, extIdx]) => {
    const exts = languageExtensions[lang];
    const ext = exts[extIdx % exts.length];
    const pathParts = [...dirs, `${name}${ext}`];
    return { path: pathParts.join("/"), language: lang };
  });

/** Generate file content that may or may not contain matchable patterns. */
const arbFileContent = fc.oneof(
  // Content with console.log (matches JS/TS rule)
  fc.constant('const x = 1;\nconsole.log("hello");\nconst y = 2;'),
  // Content with eval (matches JS/TS rule)
  fc.constant('const input = "code";\neval(input);\n'),
  // Content with exec (matches Python rule)
  fc.constant('import os\nexec("cmd")\nprint("done")'),
  // Benign content (no matches)
  fc.constant("const a = 1;\nconst b = 2;\n"),
  // Arbitrary lines
  fc.array(fc.string({ minLength: 0, maxLength: 80 }), {
    minLength: 1,
    maxLength: 10,
  }).map((lines) => lines.join("\n")),
);

/** Generate a FileToScan with a valid path and language. */
const arbFileToScan: fc.Arbitrary<FileToScan> = fc
  .tuple(arbFilePath, arbFileContent)
  .map(([{ path, language }, content]) => ({
    path,
    content,
    language,
  }));

// ── Property Tests ──────────────────────────────────────────────────────────

describe("Feature: pr-scan-workflow, Property 1: Finding file paths reference input file paths", () => {
  /**
   * **Validates: Requirements 3.2**
   *
   * For any set of input files with arbitrary file paths and contents,
   * every finding produced by scanFiles SHALL have a filePath that
   * exactly matches one of the input file paths.
   */
  it("every finding filePath must exactly match one of the input file paths", () => {
    fc.assert(
      fc.property(
        fc.array(arbFileToScan, { minLength: 1, maxLength: 10 }),
        (files) => {
          const inputPaths = new Set(files.map((f) => f.path));

          const report = scanFiles(files, TEST_RULES, {
            repository: "test/repo",
            branch: "main",
            commitSha: "abc123",
          });

          for (const finding of report.findings) {
            expect(inputPaths.has(finding.filePath)).toBe(true);
          }
        },
      ),
      { numRuns: 200 },
    );
  });
});

describe("Feature: pr-scan-workflow, Property 2: Scan report contains all required metadata", () => {
  /**
   * **Validates: Requirements 3.3**
   *
   * For any set of input files and metadata (repository, branch, commitSha),
   * the ScanReport returned by scanFiles SHALL contain non-null values for
   * repository, branch, commitSha, timestamp, durationMs, rulesLoaded,
   * filesScanned, languageBreakdown, and tags, and filesScanned SHALL equal
   * the number of input files.
   */

  /** Arbitrary non-empty string for metadata fields. */
  const arbNonEmptyString = fc.string({ minLength: 1, maxLength: 50 });

  it("scan report contains all required metadata fields with correct values", () => {
    fc.assert(
      fc.property(
        fc.array(arbFileToScan, { minLength: 0, maxLength: 10 }),
        arbNonEmptyString,
        arbNonEmptyString,
        arbNonEmptyString,
        (files, repository, branch, commitSha) => {
          const report = scanFiles(files, TEST_RULES, {
            repository,
            branch,
            commitSha,
          });

          const m = report.metadata;

          // All required metadata fields are non-null / defined
          expect(m.repository).toBeDefined();
          expect(m.repository).not.toBeNull();
          expect(m.branch).toBeDefined();
          expect(m.branch).not.toBeNull();
          expect(m.commitSha).toBeDefined();
          expect(m.commitSha).not.toBeNull();
          expect(m.timestamp).toBeDefined();
          expect(m.timestamp).not.toBeNull();
          expect(m.durationMs).toBeDefined();
          expect(m.durationMs).not.toBeNull();
          expect(m.rulesLoaded).toBeDefined();
          expect(m.rulesLoaded).not.toBeNull();
          expect(m.filesScanned).toBeDefined();
          expect(m.filesScanned).not.toBeNull();
          expect(m.languageBreakdown).toBeDefined();
          expect(m.languageBreakdown).not.toBeNull();
          expect(m.tags).toBeDefined();
          expect(m.tags).not.toBeNull();

          // Metadata values match inputs
          expect(m.repository).toBe(repository);
          expect(m.branch).toBe(branch);
          expect(m.commitSha).toBe(commitSha);

          // timestamp is a valid ISO string
          expect(typeof m.timestamp).toBe("string");
          expect(m.timestamp.length).toBeGreaterThan(0);

          // durationMs is a non-negative number
          expect(typeof m.durationMs).toBe("number");
          expect(m.durationMs).toBeGreaterThanOrEqual(0);

          // rulesLoaded equals the number of rules passed in
          expect(m.rulesLoaded).toBe(TEST_RULES.length);

          // filesScanned equals the number of input files
          expect(m.filesScanned).toBe(files.length);

          // languageBreakdown is an object
          expect(typeof m.languageBreakdown).toBe("object");

          // tags is a non-empty array
          expect(Array.isArray(m.tags)).toBe(true);
          expect(m.tags.length).toBeGreaterThan(0);
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ── Unit Tests: detectLanguage ──────────────────────────────────────────────

describe("detectLanguage", () => {
  it.each([
    [".js", "JavaScript"],
    [".jsx", "JavaScript"],
    [".ts", "TypeScript"],
    [".tsx", "TypeScript"],
    [".py", "Python"],
    [".java", "Java"],
    [".go", "Go"],
    [".rs", "Rust"],
    [".rb", "Ruby"],
    [".php", "PHP"],
    [".c", "C"],
    [".h", "C"],
    [".cpp", "C++"],
    [".cc", "C++"],
    [".cs", "C#"],
    [".swift", "Swift"],
    [".kt", "Kotlin"],
    [".scala", "Scala"],
  ])("maps %s to %s", (ext, expected) => {
    expect(detectLanguage(`src/app/main${ext}`)).toBe(expected);
  });

  it("detects Dockerfile by filename", () => {
    expect(detectLanguage("Dockerfile")).toBe("Docker");
    expect(detectLanguage("path/to/Dockerfile")).toBe("Docker");
  });

  it("returns null for unknown extensions", () => {
    expect(detectLanguage("file.xyz")).toBeNull();
    expect(detectLanguage("data.csv")).toBeNull();
  });

  it("returns null for files with no extension", () => {
    expect(detectLanguage("Makefile")).toBeNull();
    expect(detectLanguage("README")).toBeNull();
  });
});

// ── Unit Tests: scanFiles ───────────────────────────────────────────────────

describe("scanFiles unit tests", () => {
  const SQL_INJECTION_RULE: SastRule = {
    id: "sql-injection-concat",
    name: "SQL Query with String Concatenation",
    description: "Detects SQL queries built via string concatenation",
    severity: "High",
    languages: ["JavaScript", "TypeScript"],
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s.*\+\s/i,
    cweId: "CWE-89",
    owaspCategory: "A03_Injection",
  };

  const XSS_INNERHTML_RULE: SastRule = {
    id: "xss-innerhtml",
    name: "XSS via innerHTML",
    description: "Detects direct innerHTML assignment",
    severity: "High",
    languages: ["JavaScript", "TypeScript"],
    pattern: /\.innerHTML\s*=/,
    cweId: "CWE-79",
    owaspCategory: "A03_Injection",
  };

  const VULN_RULES: SastRule[] = [
    SQL_INJECTION_RULE,
    XSS_INNERHTML_RULE,
    // Reuse the exec rule from TEST_RULES for Python tests
    TEST_RULES[2], // test-exec-usage
  ];

  const META = { repository: "test/repo", branch: "main", commitSha: "abc123" };

  it("detects SQL injection via string concatenation", () => {
    const files: FileToScan[] = [
      {
        path: "src/db.js",
        content: 'const q = "SELECT * FROM users WHERE id=" + userId;',
        language: "JavaScript",
      },
    ];
    const report = scanFiles(files, VULN_RULES, META);
    expect(report.findings.length).toBe(1);
    expect(report.findings[0].ruleId).toBe("sql-injection-concat");
    expect(report.findings[0].filePath).toBe("src/db.js");
  });

  it("detects XSS via innerHTML assignment", () => {
    const files: FileToScan[] = [
      {
        path: "src/render.ts",
        content: "element.innerHTML = userInput;",
        language: "TypeScript",
      },
    ];
    const report = scanFiles(files, VULN_RULES, META);
    expect(report.findings.length).toBe(1);
    expect(report.findings[0].ruleId).toBe("xss-innerhtml");
    expect(report.findings[0].filePath).toBe("src/render.ts");
  });

  it("produces zero findings for benign code", () => {
    const files: FileToScan[] = [
      {
        path: "src/utils.js",
        content: "const x = 1;\nconst y = 2;",
        language: "JavaScript",
      },
    ];
    const report = scanFiles(files, VULN_RULES, META);
    expect(report.findings.length).toBe(0);
  });

  it("detects Python exec pattern", () => {
    const files: FileToScan[] = [
      {
        path: "scripts/run.py",
        content: 'exec("os.system(\'rm -rf /\')")',
        language: "Python",
      },
    ];
    const report = scanFiles(files, VULN_RULES, META);
    expect(report.findings.length).toBe(1);
    expect(report.findings[0].ruleId).toBe("test-exec-usage");
    expect(report.findings[0].filePath).toBe("scripts/run.py");
  });

  it("reports correct 1-indexed line numbers", () => {
    const files: FileToScan[] = [
      {
        path: "src/app.ts",
        content: "const safe = true;\nconst q = \"SELECT * FROM t WHERE id=\" + id;\nconst end = 1;",
        language: "TypeScript",
      },
    ];
    const report = scanFiles(files, VULN_RULES, META);
    expect(report.findings.length).toBe(1);
    // The SQL injection is on the second line → line number should be 2
    expect(report.findings[0].line).toBe(2);
  });
});

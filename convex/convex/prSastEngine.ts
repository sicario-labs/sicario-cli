// ── Interfaces ──────────────────────────────────────────────────────────────

export interface SastRule {
  id: string;
  name: string;
  description: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  languages: string[];
  pattern: RegExp;
  cweId?: string;
  owaspCategory?: string;
}

export interface ScanFinding {
  ruleId: string;
  ruleName: string;
  filePath: string;
  line: number;
  column: number;
  snippet: string;
  severity: string;
  cweId?: string;
  owaspCategory?: string;
  fingerprint: string;
}

export interface ScanReport {
  metadata: {
    repository: string;
    branch: string;
    commitSha: string;
    timestamp: string;
    durationMs: number;
    rulesLoaded: number;
    filesScanned: number;
    languageBreakdown: Record<string, number>;
    tags: string[];
  };
  findings: ScanFinding[];
}

export interface FileToScan {
  path: string;
  content: string;
  language: string;
}

// ── Language Detection ──────────────────────────────────────────────────────

const EXTENSION_MAP: Record<string, string> = {
  ".js": "JavaScript",
  ".jsx": "JavaScript",
  ".ts": "TypeScript",
  ".tsx": "TypeScript",
  ".py": "Python",
  ".java": "Java",
  ".go": "Go",
  ".rs": "Rust",
  ".rb": "Ruby",
  ".php": "PHP",
  ".c": "C",
  ".h": "C",
  ".cpp": "C++",
  ".cc": "C++",
  ".cs": "C#",
  ".swift": "Swift",
  ".kt": "Kotlin",
  ".scala": "Scala",
  ".yaml": "YAML",
  ".yml": "YAML",
  ".json": "JSON",
  ".xml": "XML",
  ".html": "HTML",
  ".css": "CSS",
  ".sh": "Shell",
  ".sql": "SQL",
  ".tf": "Terraform",
  ".dockerfile": "Docker",
};

/**
 * Detect the programming language from a file path based on its extension.
 * Also handles special filenames like "Dockerfile".
 */
export function detectLanguage(filePath: string): string | null {
  const lower = filePath.toLowerCase();

  // Handle special filenames
  const basename = lower.split("/").pop() ?? "";
  if (basename === "dockerfile") return "Docker";

  const dotIdx = basename.lastIndexOf(".");
  if (dotIdx === -1) return null;

  const ext = basename.slice(dotIdx);
  return EXTENSION_MAP[ext] ?? null;
}

// ── Fingerprint ─────────────────────────────────────────────────────────────

/**
 * Compute a deterministic fingerprint for a finding.
 * Uses a fast string hash suitable for deduplication (not cryptographic).
 */
export function computeFingerprint(
  ruleId: string,
  filePath: string,
  snippet: string,
): string {
  const input = `${ruleId}:${filePath}:${snippet}`;
  // FNV-1a inspired hash producing a 64-char hex string for compatibility
  let h1 = 0x811c9dc5 >>> 0;
  let h2 = 0x01000193 >>> 0;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ c, 0x811c9dc5) >>> 0;
  }
  // Repeat to fill 64 hex chars
  const seg1 = h1.toString(16).padStart(8, "0");
  const seg2 = h2.toString(16).padStart(8, "0");
  const seg3 = (h1 ^ h2).toString(16).padStart(8, "0");
  const seg4 = Math.imul(h1, h2).toString(16).padStart(8, "0");
  return (seg1 + seg2 + seg3 + seg4 + seg1 + seg2 + seg3 + seg4).slice(0, 64);
}

// ── Threshold Evaluation ────────────────────────────────────────────────────

const SEVERITY_LEVELS: Record<string, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Info: 0,
};

/**
 * Evaluate findings against a severity threshold.
 * Returns passed: true only if NO finding has severity >= threshold level.
 */
export function evaluateThreshold(
  findings: ScanFinding[],
  threshold: string,
): { passed: boolean; criticalCount: number; highCount: number; totalCount: number } {
  const thresholdLevel = SEVERITY_LEVELS[threshold] ?? SEVERITY_LEVELS["High"];

  let criticalCount = 0;
  let highCount = 0;
  let hasViolation = false;

  for (const f of findings) {
    const level = SEVERITY_LEVELS[f.severity] ?? 0;
    if (f.severity === "Critical") criticalCount++;
    if (f.severity === "High") highCount++;
    if (level >= thresholdLevel) hasViolation = true;
  }

  return {
    passed: !hasViolation,
    criticalCount,
    highCount,
    totalCount: findings.length,
  };
}

// ── Scan Engine ─────────────────────────────────────────────────────────────

/**
 * Scan a set of files against SAST rules and produce a report.
 * Rules are filtered by language match before scanning each file.
 * Regex patterns are run line-by-line; findings include 1-indexed line numbers,
 * 0-indexed column from the regex match, and the trimmed matched line as snippet.
 */
export function scanFiles(
  files: FileToScan[],
  rules: SastRule[],
  metadata: { repository: string; branch: string; commitSha: string },
): ScanReport {
  const startTime = Date.now();
  const findings: ScanFinding[] = [];
  const languageBreakdown: Record<string, number> = {};

  for (const file of files) {
    // Track language breakdown
    languageBreakdown[file.language] = (languageBreakdown[file.language] ?? 0) + 1;

    // Filter rules applicable to this file's language
    const applicableRules = rules.filter((r) =>
      r.languages.some((lang) => lang.toLowerCase() === file.language.toLowerCase()),
    );

    if (applicableRules.length === 0) continue;

    const lines = file.content.split("\n");

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];

      for (const rule of applicableRules) {
        // Reset regex state for global/sticky patterns
        const regex = new RegExp(rule.pattern.source, rule.pattern.flags.replace("g", ""));
        const match = regex.exec(line);

        if (match) {
          const snippet = line.trim();
          findings.push({
            ruleId: rule.id,
            ruleName: rule.name,
            filePath: file.path,
            line: lineIdx + 1, // 1-indexed
            column: match.index, // 0-indexed
            snippet,
            severity: rule.severity,
            cweId: rule.cweId,
            owaspCategory: rule.owaspCategory,
            fingerprint: computeFingerprint(rule.id, file.path, snippet),
          });
        }
      }
    }
  }

  const durationMs = Date.now() - startTime;

  return {
    metadata: {
      repository: metadata.repository,
      branch: metadata.branch,
      commitSha: metadata.commitSha,
      timestamp: new Date().toISOString(),
      durationMs,
      rulesLoaded: rules.length,
      filesScanned: files.length,
      languageBreakdown,
      tags: ["pr-scan"],
    },
    findings,
  };
}

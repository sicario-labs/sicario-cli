import type { SastRule } from "./prSastEngine";

// ── JavaScript / TypeScript Rules ───────────────────────────────────────────

const jsRules: SastRule[] = [
  {
    id: "js-sql-string-concat",
    name: "SQL Query with String Concatenation",
    description:
      "Building SQL queries via string concatenation with variables allows SQL injection. Use parameterized queries instead.",
    severity: "High",
    languages: ["JavaScript", "TypeScript"],
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s.*\+\s/i,
    cweId: "CWE-89",
    owaspCategory: "A03_Injection",
  },
  {
    id: "js-sql-template-literal",
    name: "SQL Query with Template Literal Interpolation",
    description:
      "Interpolating variables into SQL template literals allows SQL injection. Use parameterized queries instead.",
    severity: "High",
    languages: ["JavaScript", "TypeScript"],
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE)\s.*\$\{/i,
    cweId: "CWE-89",
    owaspCategory: "A03_Injection",
  },
  {
    id: "js-xss-innerhtml-assignment",
    name: "innerHTML Assignment",
    description:
      "Assigning to innerHTML with dynamic content allows XSS. Use textContent or sanitize with DOMPurify.",
    severity: "High",
    languages: ["JavaScript", "TypeScript"],
    pattern: /\.innerHTML\s*=/,
    cweId: "CWE-79",
    owaspCategory: "A03_Injection",
  },
  {
    id: "js-xss-outerhtml-assignment",
    name: "outerHTML Assignment",
    description:
      "Assigning to outerHTML with dynamic content allows XSS. Use safe DOM manipulation methods instead.",
    severity: "High",
    languages: ["JavaScript", "TypeScript"],
    pattern: /\.outerHTML\s*=/,
    cweId: "CWE-79",
    owaspCategory: "A03_Injection",
  },
  {
    id: "js-xss-document-write",
    name: "document.write Usage",
    description:
      "document.write with dynamic content allows XSS. Use safe DOM APIs like createElement and textContent.",
    severity: "High",
    languages: ["JavaScript", "TypeScript"],
    pattern: /document\.write\s*\(/,
    cweId: "CWE-79",
    owaspCategory: "A03_Injection",
  },
  {
    id: "js-xss-document-writeln",
    name: "document.writeln Usage",
    description:
      "document.writeln with dynamic content allows XSS. Use safe DOM APIs instead.",
    severity: "High",
    languages: ["JavaScript", "TypeScript"],
    pattern: /document\.writeln\s*\(/,
    cweId: "CWE-79",
    owaspCategory: "A03_Injection",
  },
  {
    id: "js-xss-dangerously-set-inner-html",
    name: "dangerouslySetInnerHTML with Dynamic Content",
    description:
      "Using dangerouslySetInnerHTML with dynamic content in React/JSX allows XSS. Sanitize HTML with DOMPurify or use safe rendering methods.",
    severity: "High",
    languages: ["JavaScript", "TypeScript"],
    pattern: /dangerouslySetInnerHTML/,
    cweId: "CWE-79",
    owaspCategory: "A03_Injection",
  },
  {
    id: "js-nosql-mongodb-where-injection",
    name: "MongoDB $where with User Input",
    description:
      "Using $where with user-controlled input allows NoSQL injection via JavaScript execution. Use standard query operators instead.",
    severity: "Critical",
    languages: ["JavaScript", "TypeScript"],
    pattern: /\$where\s*:.*\$\{/,
    cweId: "CWE-943",
    owaspCategory: "A03_Injection",
  },
  {
    id: "js-redos-new-regexp-user-input",
    name: "new RegExp with User Input",
    description:
      "Constructing RegExp from user-controlled input can cause ReDoS. Validate and sanitize input before using in regex.",
    severity: "Medium",
    languages: ["JavaScript", "TypeScript"],
    pattern: /new\s+RegExp\s*\(\s*[a-zA-Z_$]/,
    cweId: "CWE-1333",
    owaspCategory: "A03_Injection",
  },
  {
    id: "js-eval-usage",
    name: "eval() Usage",
    description:
      "eval() executes arbitrary code and is a major security risk. Use safer alternatives like JSON.parse or Function constructors with validation.",
    severity: "Critical",
    languages: ["JavaScript", "TypeScript"],
    pattern: /\beval\s*\(/,
    cweId: "CWE-95",
    owaspCategory: "A03_Injection",
  },
  {
    id: "js-xss-jquery-html",
    name: "jQuery .html() with Dynamic Content",
    description:
      "Using jQuery .html() with dynamic content allows XSS. Use .text() for plain text or sanitize HTML input.",
    severity: "High",
    languages: ["JavaScript", "TypeScript"],
    pattern: /\.html\s*\([^)]+\)/,
    cweId: "CWE-79",
    owaspCategory: "A03_Injection",
  },
  {
    id: "js-xss-insert-adjacent-html",
    name: "insertAdjacentHTML Usage",
    description:
      "insertAdjacentHTML with dynamic content allows XSS. Sanitize HTML before insertion or use safe DOM methods.",
    severity: "High",
    languages: ["JavaScript", "TypeScript"],
    pattern: /\.insertAdjacentHTML\s*\(/,
    cweId: "CWE-79",
    owaspCategory: "A03_Injection",
  },
];

// ── Python Rules ────────────────────────────────────────────────────────────

const pyRules: SastRule[] = [
  {
    id: "py-os-system",
    name: "os.system() Usage",
    description:
      "os.system() executes commands through the shell and is vulnerable to command injection. Use subprocess.run() with a list of arguments instead.",
    severity: "High",
    languages: ["Python"],
    pattern: /os\.system\s*\(/,
    cweId: "CWE-78",
    owaspCategory: "A03_Injection",
  },
  {
    id: "py-os-popen",
    name: "os.popen() Usage",
    description:
      "os.popen() executes commands through the shell and is vulnerable to command injection. Use subprocess.run() with a list of arguments instead.",
    severity: "High",
    languages: ["Python"],
    pattern: /os\.popen\s*\(/,
    cweId: "CWE-78",
    owaspCategory: "A03_Injection",
  },
  {
    id: "py-subprocess-shell-true",
    name: "subprocess with shell=True",
    description:
      "Using shell=True in subprocess calls is vulnerable to command injection. Pass arguments as a list without shell=True.",
    severity: "High",
    languages: ["Python"],
    pattern: /subprocess\.\w+\(.*shell\s*=\s*True/,
    cweId: "CWE-78",
    owaspCategory: "A03_Injection",
  },
  {
    id: "py-exec-usage",
    name: "exec() Usage",
    description:
      "exec() executes arbitrary Python code and is a major security risk. Avoid using exec with user-controlled input.",
    severity: "Critical",
    languages: ["Python"],
    pattern: /\bexec\s*\(/,
    cweId: "CWE-95",
    owaspCategory: "A03_Injection",
  },
  {
    id: "py-eval-usage",
    name: "eval() Usage",
    description:
      "eval() executes arbitrary Python expressions and is a major security risk. Use ast.literal_eval() for safe evaluation.",
    severity: "Critical",
    languages: ["Python"],
    pattern: /\beval\s*\(/,
    cweId: "CWE-95",
    owaspCategory: "A03_Injection",
  },
  {
    id: "py-pickle-loads",
    name: "pickle.load/loads Usage",
    description:
      "Deserializing untrusted data with pickle can lead to arbitrary code execution. Use safer formats like JSON.",
    severity: "High",
    languages: ["Python"],
    pattern: /pickle\.loads?\s*\(/,
    cweId: "CWE-502",
    owaspCategory: "A08_Software_and_Data_Integrity_Failures",
  },
  {
    id: "py-yaml-load-unsafe",
    name: "yaml.load without SafeLoader",
    description:
      "yaml.load() without specifying SafeLoader can execute arbitrary Python code. Use yaml.safe_load() or specify Loader=SafeLoader.",
    severity: "High",
    languages: ["Python"],
    pattern: /yaml\.load\s*\([^)]*(?!Loader)/,
    cweId: "CWE-502",
    owaspCategory: "A08_Software_and_Data_Integrity_Failures",
  },
  {
    id: "py-sql-fstring",
    name: "SQL Query with f-string",
    description:
      "Using f-strings to build SQL queries allows SQL injection. Use parameterized queries with placeholders instead.",
    severity: "High",
    languages: ["Python"],
    pattern: /(?:execute|cursor\.execute|\.query)\s*\(\s*f["']/i,
    cweId: "CWE-89",
    owaspCategory: "A03_Injection",
  },
  {
    id: "py-path-traversal",
    name: "Path Traversal via User Input",
    description:
      "Opening files with user-controlled paths can lead to path traversal attacks. Validate and sanitize file paths.",
    severity: "High",
    languages: ["Python"],
    pattern: /open\s*\(.*(?:request|input|argv)/,
    cweId: "CWE-22",
    owaspCategory: "A01_Broken_Access_Control",
  },
  {
    id: "py-flask-ssti",
    name: "Flask Server-Side Template Injection",
    description:
      "render_template_string with user input allows server-side template injection. Use render_template with separate template files.",
    severity: "Critical",
    languages: ["Python"],
    pattern: /render_template_string\s*\(/,
    cweId: "CWE-1336",
    owaspCategory: "A03_Injection",
  },
];

// ── Java Rules ──────────────────────────────────────────────────────────────

const javaRules: SastRule[] = [
  {
    id: "java-sqli-statement-concat",
    name: "Statement.execute with String Concatenation",
    description:
      "Concatenating user input into SQL strings passed to Statement.execute allows SQL injection. Use PreparedStatement with parameterized queries.",
    severity: "High",
    languages: ["Java"],
    pattern: /(?:executeQuery|executeUpdate|execute)\s*\(.*\+/,
    cweId: "CWE-89",
    owaspCategory: "A03_Injection",
  },
  {
    id: "java-sqli-createstatement",
    name: "createStatement Usage",
    description:
      "Using createStatement() instead of prepareStatement() often leads to SQL injection via string concatenation. Use PreparedStatement.",
    severity: "Medium",
    languages: ["Java"],
    pattern: /createStatement\s*\(/,
    cweId: "CWE-89",
    owaspCategory: "A03_Injection",
  },
  {
    id: "java-sqli-hibernate-createquery-concat",
    name: "Hibernate createQuery with Concatenation",
    description:
      "Concatenating user input into Hibernate createQuery allows HQL injection. Use named parameters or criteria queries.",
    severity: "High",
    languages: ["Java"],
    pattern: /createQuery\s*\(.*\+/,
    cweId: "CWE-89",
    owaspCategory: "A03_Injection",
  },
  {
    id: "java-runtime-exec",
    name: "Runtime.exec() Command Execution",
    description:
      "Runtime.getRuntime().exec() with user input allows command injection. Use ProcessBuilder with argument lists and validate input.",
    severity: "High",
    languages: ["Java"],
    pattern: /Runtime\.getRuntime\(\)\.exec\s*\(/,
    cweId: "CWE-78",
    owaspCategory: "A03_Injection",
  },
  {
    id: "java-deserialization",
    name: "Unsafe Java Deserialization",
    description:
      "Deserializing untrusted data via ObjectInputStream can lead to remote code execution. Use allowlists or safer serialization formats.",
    severity: "Critical",
    languages: ["Java"],
    pattern: /ObjectInputStream|readObject\s*\(/,
    cweId: "CWE-502",
    owaspCategory: "A08_Software_and_Data_Integrity_Failures",
  },
  {
    id: "java-xxe-parser",
    name: "XML External Entity (XXE) Processing",
    description:
      "Using XML parsers without disabling external entities allows XXE attacks. Disable DTDs and external entities in parser configuration.",
    severity: "High",
    languages: ["Java"],
    pattern: /DocumentBuilderFactory|SAXParserFactory|XMLInputFactory/,
    cweId: "CWE-611",
    owaspCategory: "A05_Security_Misconfiguration",
  },
  {
    id: "java-path-traversal",
    name: "Path Traversal via Request Parameter",
    description:
      "Constructing File paths from request parameters allows path traversal. Validate and canonicalize file paths.",
    severity: "High",
    languages: ["Java"],
    pattern: /new\s+File\s*\(.*(?:request|getParameter)/,
    cweId: "CWE-22",
    owaspCategory: "A01_Broken_Access_Control",
  },
  {
    id: "java-xss-response-write",
    name: "XSS via Response Writer",
    description:
      "Writing user input directly to the response via getWriter() allows XSS. Encode output before writing to the response.",
    severity: "High",
    languages: ["Java"],
    pattern: /getWriter\(\)\.(?:print|write|println)\s*\(/,
    cweId: "CWE-79",
    owaspCategory: "A03_Injection",
  },
  {
    id: "java-ldap-injection",
    name: "LDAP Injection via String Concatenation",
    description:
      "Concatenating user input into LDAP search filters allows LDAP injection. Use parameterized LDAP queries.",
    severity: "High",
    languages: ["Java"],
    pattern: /search\s*\(.*\+/,
    cweId: "CWE-90",
    owaspCategory: "A03_Injection",
  },
  {
    id: "java-spring-sqli",
    name: "Spring JdbcTemplate SQL Injection",
    description:
      "Concatenating user input into JdbcTemplate queries allows SQL injection. Use parameterized queries with placeholders.",
    severity: "High",
    languages: ["Java"],
    pattern: /jdbcTemplate\.\w+\(.*\+/,
    cweId: "CWE-89",
    owaspCategory: "A03_Injection",
  },
];

// ── Go Rules ────────────────────────────────────────────────────────────────

const goRules: SastRule[] = [
  {
    id: "go-sql-string-concat",
    name: "SQL Query with String Concatenation",
    description:
      "Concatenating user input into SQL queries passed to Query/Exec allows SQL injection. Use parameterized queries with placeholders.",
    severity: "High",
    languages: ["Go"],
    pattern: /(?:Query|Exec|QueryRow)\s*\(.*\+/,
    cweId: "CWE-89",
    owaspCategory: "A03_Injection",
  },
  {
    id: "go-sql-fmt-sprintf",
    name: "SQL Query with fmt.Sprintf",
    description:
      "Using fmt.Sprintf to build SQL queries allows SQL injection. Use parameterized queries with database/sql placeholders.",
    severity: "High",
    languages: ["Go"],
    pattern: /fmt\.Sprintf\s*\(.*(?:SELECT|INSERT|UPDATE|DELETE)/i,
    cweId: "CWE-89",
    owaspCategory: "A03_Injection",
  },
  {
    id: "go-cmd-exec",
    name: "exec.Command Usage",
    description:
      "exec.Command with user input allows command injection. Validate and sanitize all command arguments.",
    severity: "High",
    languages: ["Go"],
    pattern: /exec\.Command\s*\(/,
    cweId: "CWE-78",
    owaspCategory: "A03_Injection",
  },
  {
    id: "go-path-traversal",
    name: "Path Traversal via User Input",
    description:
      "Using filepath.Join with user-controlled input can lead to path traversal. Validate paths against a base directory.",
    severity: "High",
    languages: ["Go"],
    pattern: /filepath\.Join\s*\(.*(?:r\.|request|param)/,
    cweId: "CWE-22",
    owaspCategory: "A01_Broken_Access_Control",
  },
  {
    id: "go-ssrf",
    name: "Potential Server-Side Request Forgery",
    description:
      "Making HTTP requests with user-controlled URLs can lead to SSRF. Validate and allowlist target URLs.",
    severity: "Medium",
    languages: ["Go"],
    pattern: /http\.(?:Get|Post|NewRequest)\s*\(/,
    cweId: "CWE-918",
    owaspCategory: "A10_Server_Side_Request_Forgery",
  },
  {
    id: "go-weak-crypto",
    name: "Weak Cryptographic Algorithm",
    description:
      "Using MD5, SHA1, DES, or RC4 is cryptographically weak. Use SHA-256 or stronger algorithms.",
    severity: "Medium",
    languages: ["Go"],
    pattern: /crypto\/(?:md5|sha1|des|rc4)/,
    cweId: "CWE-327",
    owaspCategory: "A02_Cryptographic_Failures",
  },
  {
    id: "go-tls-insecure",
    name: "TLS Certificate Verification Disabled",
    description:
      "Setting InsecureSkipVerify to true disables TLS certificate validation, enabling man-in-the-middle attacks.",
    severity: "High",
    languages: ["Go"],
    pattern: /InsecureSkipVerify\s*:\s*true/,
    cweId: "CWE-295",
    owaspCategory: "A07_Identification_and_Authentication_Failures",
  },
  {
    id: "go-race-condition",
    name: "Goroutine Closure Variable Capture",
    description:
      "Launching goroutines with closures can cause race conditions on captured variables. Pass variables as function parameters.",
    severity: "Medium",
    languages: ["Go"],
    pattern: /go\s+func\s*\(/,
    cweId: "CWE-362",
    owaspCategory: "A04_Insecure_Design",
  },
];

// ── Rust Rules ──────────────────────────────────────────────────────────────

const rsRules: SastRule[] = [
  {
    id: "rs-sql-format",
    name: "SQL Query with format! Macro",
    description:
      "Using format! to build SQL queries allows SQL injection. Use parameterized queries provided by your database driver.",
    severity: "High",
    languages: ["Rust"],
    pattern: /format!\s*\(.*(?:SELECT|INSERT|UPDATE|DELETE)/i,
    cweId: "CWE-89",
    owaspCategory: "A03_Injection",
  },
  {
    id: "rs-command-exec",
    name: "Command::new Usage",
    description:
      "Command::new with user input allows command injection. Validate and sanitize all command arguments.",
    severity: "High",
    languages: ["Rust"],
    pattern: /Command::new\s*\(/,
    cweId: "CWE-78",
    owaspCategory: "A03_Injection",
  },
  {
    id: "rs-unsafe-block",
    name: "Unsafe Block Usage",
    description:
      "Unsafe blocks bypass Rust's safety guarantees. Review carefully for memory safety and undefined behavior.",
    severity: "Medium",
    languages: ["Rust"],
    pattern: /unsafe\s*\{/,
    cweId: "CWE-676",
    owaspCategory: "A04_Insecure_Design",
  },
  {
    id: "rs-unwrap-usage",
    name: "unwrap() Usage",
    description:
      "Using .unwrap() can cause panics on None/Err values. Use proper error handling with match, if let, or the ? operator.",
    severity: "Low",
    languages: ["Rust"],
    pattern: /\.unwrap\s*\(\)/,
    cweId: "CWE-252",
    owaspCategory: "A04_Insecure_Design",
  },
  {
    id: "rs-path-traversal",
    name: "File System Access",
    description:
      "Direct file system access with user-controlled paths can lead to path traversal. Validate and canonicalize paths.",
    severity: "Medium",
    languages: ["Rust"],
    pattern: /std::fs::(?:read|write|remove|create)/,
    cweId: "CWE-22",
    owaspCategory: "A01_Broken_Access_Control",
  },
];

// ── Export All Rules ────────────────────────────────────────────────────────

export const PR_SAST_RULES: SastRule[] = [
  ...jsRules,
  ...pyRules,
  ...javaRules,
  ...goRules,
  ...rsRules,
];

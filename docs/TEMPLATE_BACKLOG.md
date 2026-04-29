# Sicario Template Backlog — Batch 1 (50 Templates)

> **Status legend:** `[ ]` = not started · `[-]` = in progress · `[x]` = shipped
>
> **Already shipped (39):** `CryptoWeakHash`, `CryptoMathRandom`, `CryptoEcbMode`,
> `CryptoHardcodedJwt`, `AuthMissingSalt`, `DomInnerHTML`, `DomDocumentWrite`,
> `DomPostMessageWildcard`, `WebCorsWildcard`, `WebCookieInsecure`,
> `WebExpressXPoweredBy`, `PyUnsafeDeserialize`, `PyRequestsVerifyFalse`,
> `GoDeferClose`, `InjectEval`, `InjectOsExec`, `InjectNoSqlTypeCast`,
> `ReactDangerouslySetInnerHTML`, `IacDockerRootUser`,
> `CryptoPbkdf2LowIterations`, `CryptoRsaKeyTooShort`, `CryptoHardcodedAesKey`,
> `CryptoInsecureRandomSeed`, `CryptoMd5PasswordHash`, `CryptoJwtNoneAlgorithm`,
> `CryptoJwtWeakAlgorithm`, `CryptoHardcodedSalt`,
> `AuthSessionNoHttpOnly`, `AuthSessionNoSecureFlag`, `AuthSessionFixation`,
> `AuthPasswordInLog`, `AuthBasicAuthOverHttp`, `AuthJwtNoExpiry`,
> `InjectChildProcessShellTrue`, `InjectPythonSubprocessShell`, `InjectSsti`,
> `InjectLdap`, `InjectXpath`

---

## Domain 1 — Cryptography & Secrets

- [x] **`CryptoPbkdf2LowIterationsTemplate`** | **CWE-916** | **Lang:** `JS/TS, Python`
  - **Trigger:** `pbkdf2` / `pbkdf2Sync` call with iterations argument < 100,000 (e.g., `crypto.pbkdf2Sync(pwd, salt, 1000, ...)`)
  - **Fix Pattern:** Replace the iteration count literal with `310000` (OWASP 2023 minimum for PBKDF2-HMAC-SHA256)

- [x] **`CryptoRsaKeyTooShortTemplate`** | **CWE-326** | **Lang:** `JS/TS, Python`
  - **Trigger:** RSA key generation with `modulusLength` / `key_size` < 2048 (e.g., `generateKeyPair('rsa', { modulusLength: 1024 })`)
  - **Fix Pattern:** Replace the key size literal with `4096`

- [x] **`CryptoHardcodedAesKeyTemplate`** | **CWE-321** | **Lang:** `JS/TS, Python`
  - **Trigger:** `createCipheriv` / `AES.new` called with a string literal as the key argument (e.g., `createCipheriv('aes-256-gcm', 'hardcodedkey123', iv)`)
  - **Fix Pattern:** Replace the literal key with `process.env.AES_KEY` (JS) or `os.environ.get("AES_KEY")` (Python)

- [x] **`CryptoInsecureRandomSeedTemplate`** | **CWE-335** | **Lang:** `Python`
  - **Trigger:** `random.seed(0)` or `random.seed(<integer_literal>)` — deterministic seed defeats PRNG security
  - **Fix Pattern:** Remove the `random.seed(...)` call entirely (replace line with a comment: `# SICARIO FIX: removed deterministic seed`)

- [x] **`CryptoMd5PasswordHashTemplate`** | **CWE-916** | **Lang:** `JS/TS, Python, Go`
  - **Trigger:** `md5(password)` or `hashlib.md5(password)` used for password storage (rule ID contains "password" + "md5")
  - **Fix Pattern:** Replace with `bcrypt.hash(password, 12)` (JS) / `bcrypt.hashpw(password, bcrypt.gensalt(12))` (Python) / `bcrypt.GenerateFromPassword([]byte(password), 12)` (Go)

- [x] **`CryptoJwtNoneAlgorithmTemplate`** | **CWE-347** | **Lang:** `JS/TS, Python`
  - **Trigger:** `jwt.verify(token, secret, { algorithms: ['none'] })` or `algorithm='none'` in Python jwt.decode
  - **Fix Pattern:** Replace `'none'` with `'HS256'` in the algorithms array / algorithm parameter

- [x] **`CryptoJwtWeakAlgorithmTemplate`** | **CWE-327** | **Lang:** `JS/TS, Python`
  - **Trigger:** `jwt.sign(payload, secret, { algorithm: 'HS1' })` or any JWT call using `RS1`, `HS1`, `none`
  - **Fix Pattern:** Replace the algorithm value with `'HS256'`

- [x] **`CryptoHardcodedSaltTemplate`** | **CWE-760** | **Lang:** `Python`
  - **Trigger:** `bcrypt.hashpw(password, b"$2b$12$hardcodedsalt...")` — literal bytes as salt
  - **Fix Pattern:** Replace the literal salt with `bcrypt.gensalt(12)`

---

## Domain 2 — Authentication & Session Management

- [x] **`AuthSessionNoHttpOnlyTemplate`** | **CWE-1004** | **Lang:** `JS/TS` (Express)
  - **Trigger:** `express-session` or `cookie-session` initialised without `httpOnly: true` in the cookie options object
  - **Fix Pattern:** Inject `httpOnly: true` into the cookie options object literal

- [x] **`AuthSessionNoSecureFlagTemplate`** | **CWE-614** | **Lang:** `JS/TS` (Express)
  - **Trigger:** `express-session` cookie options missing `secure: true`
  - **Fix Pattern:** Inject `secure: process.env.NODE_ENV === 'production'` into the cookie options

- [x] **`AuthSessionFixationTemplate`** | **CWE-384** | **Lang:** `JS/TS` (Express)
  - **Trigger:** `req.session.userId = ...` assignment without a preceding `req.session.regenerate(...)` call on the same logical path
  - **Fix Pattern:** Prepend `req.session.regenerate(() => {` and close with `});` wrapping the assignment

- [x] **`AuthPasswordInLogTemplate`** | **CWE-532** | **Lang:** `JS/TS, Python`
  - **Trigger:** `console.log` / `logger.info` / `print` call where the argument string or variable name contains `password`, `passwd`, `secret`, or `token`
  - **Fix Pattern:** Replace the entire log call with a comment: `// SICARIO FIX: removed logging of sensitive value`

- [x] **`AuthBasicAuthOverHttpTemplate`** | **CWE-523** | **Lang:** `JS/TS`
  - **Trigger:** `Authorization: 'Basic '` header construction combined with an `http://` URL (not `https://`)
  - **Fix Pattern:** Replace `http://` with `https://` in the URL string literal

- [x] **`AuthJwtNoExpiryTemplate`** | **CWE-613** | **Lang:** `JS/TS, Python`
  - **Trigger:** `jwt.sign(payload, secret)` call with no options object, or options object missing `expiresIn`
  - **Fix Pattern:** Inject `, { expiresIn: '1h' }` as the third argument (JS) or `expiry=datetime.utcnow() + timedelta(hours=1)` in the payload (Python)

---

## Domain 3 — Injection (SQL, NoSQL, Command, Template)

- [ ] **`SqlStringConcatTemplate`** | **CWE-89** | **Lang:** `JS/TS, Python, Go`
  - **Trigger:** String concatenation (`+` or f-string) inside a `.query(` / `cursor.execute(` / `db.Exec(` call
  - **Fix Pattern:** Replace the concatenated string with a parameterized placeholder (`$1`, `%s`, `?`) and move the variable to the arguments array

- [ ] **`SqlTemplateStringTemplate`** | **CWE-89** | **Lang:** `JS/TS`
  - **Trigger:** Template literal (backtick) used as the first argument to `.query(` or `.execute(`
  - **Fix Pattern:** Convert to parameterized query: extract interpolated variables into a second array argument, replace `${var}` with `$1`, `$2`, etc.

- [x] **`InjectChildProcessShellTrueTemplate`** | **CWE-78** | **Lang:** `JS/TS`
  - **Trigger:** `spawn(cmd, args, { shell: true })` or `execFile(cmd, args, { shell: true })`
  - **Fix Pattern:** Remove the `shell: true` property from the options object

- [x] **`InjectPythonSubprocessShellTemplate`** | **CWE-78** | **Lang:** `Python`
  - **Trigger:** `subprocess.run(cmd, shell=True)` or `subprocess.call(cmd, shell=True)` where `cmd` is not a string literal
  - **Fix Pattern:** Replace `shell=True` with `shell=False` and wrap `cmd` in `shlex.split(cmd)` if it's a string

- [x] **`InjectSstiTemplate`** | **CWE-94** | **Lang:** `Python` (Jinja2/Flask)
  - **Trigger:** `render_template_string(user_input)` — direct user input passed to template renderer
  - **Fix Pattern:** Replace with `render_template_string(escape(user_input))` using `markupsafe.escape`

- [x] **`InjectLdapTemplate`** | **CWE-90** | **Lang:** `JS/TS, Python`
  - **Trigger:** LDAP filter string built with `+` concatenation containing `req.body.*` or user-controlled variable
  - **Fix Pattern:** Wrap the user variable with an LDAP escape helper: `ldap.escape(userInput)` (JS) or `ldap3.utils.conv.escape_filter_chars(user_input)` (Python)

- [x] **`InjectXpathTemplate`** | **CWE-643** | **Lang:** `JS/TS, Python`
  - **Trigger:** XPath query string built with `+` concatenation or f-string containing user input
  - **Fix Pattern:** Replace with a parameterized XPath call using `xpath.select(expr, doc, { variables: { param: userInput } })` (JS)

---

## Domain 4 — Web Security Headers & CORS

- [ ] **`WebHelmetMissingTemplate`** | **CWE-693** | **Lang:** `JS/TS` (Express)
  - **Trigger:** `const app = express()` line without a subsequent `app.use(helmet())` call in the same file
  - **Fix Pattern:** Inject `app.use(require('helmet')());` on the line after the `express()` initialisation

- [ ] **`WebCspMissingTemplate`** | **CWE-693** | **Lang:** `JS/TS` (Express)
  - **Trigger:** `helmet()` call without a `contentSecurityPolicy` configuration
  - **Fix Pattern:** Replace `helmet()` with `helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"] } } })`

- [ ] **`WebHstsDisabledTemplate`** | **CWE-319** | **Lang:** `JS/TS` (Express/Helmet)
  - **Trigger:** `helmet({ hsts: false })` or `hsts: { maxAge: 0 }`
  - **Fix Pattern:** Replace with `hsts: { maxAge: 31536000, includeSubDomains: true }`

- [ ] **`WebCorsCredentialsWildcardTemplate`** | **CWE-942** | **Lang:** `JS/TS`
  - **Trigger:** CORS config with both `origin: '*'` and `credentials: true` — browsers block this but it signals misconfiguration
  - **Fix Pattern:** Replace `origin: '*'` with `origin: process.env.ALLOWED_ORIGIN`

- [ ] **`WebReferrerPolicyMissingTemplate`** | **CWE-200** | **Lang:** `JS/TS` (Express)
  - **Trigger:** `helmet()` call without `referrerPolicy` option
  - **Fix Pattern:** Inject `referrerPolicy: { policy: 'strict-origin-when-cross-origin' }` into the helmet options object

- [ ] **`WebClickjackingTemplate`** | **CWE-1021** | **Lang:** `JS/TS` (Express)
  - **Trigger:** `helmet({ frameguard: false })` or explicit `X-Frame-Options` header set to `ALLOWALL`
  - **Fix Pattern:** Replace with `frameguard: { action: 'deny' }` or `X-Frame-Options: DENY`

- [ ] **`WebCacheControlMissingTemplate`** | **CWE-525** | **Lang:** `JS/TS` (Express)
  - **Trigger:** Route handler for sensitive paths (`/api/`, `/admin/`, `/user/`) without `res.setHeader('Cache-Control', ...)` 
  - **Fix Pattern:** Inject `res.setHeader('Cache-Control', 'no-store');` before the `res.json(` / `res.send(` call

---

## Domain 5 — Input Validation & Prototype Pollution

- [ ] **`PrototypePollutionMergeTemplate`** | **CWE-1321** | **Lang:** `JS/TS`
  - **Trigger:** `Object.assign(target, userInput)` or `_.merge(target, userInput)` where `userInput` is from `req.body`
  - **Fix Pattern:** Wrap with a prototype-safe merge: replace `Object.assign(target, userInput)` with `Object.assign(Object.create(null), target, JSON.parse(JSON.stringify(userInput)))`

- [ ] **`PrototypePollutionSetTemplate`** | **CWE-1321** | **Lang:** `JS/TS`
  - **Trigger:** `obj[req.body.key] = req.body.value` — dynamic property assignment from user input
  - **Fix Pattern:** Prepend a key validation guard: `if (['__proto__', 'constructor', 'prototype'].includes(req.body.key)) throw new Error('Invalid key');`

- [ ] **`InputReqBodyNoValidationTemplate`** | **CWE-20** | **Lang:** `JS/TS` (Express)
  - **Trigger:** Route handler that accesses `req.body.*` properties without any preceding validation call (no `express-validator`, `joi`, or `zod` usage in scope)
  - **Fix Pattern:** Inject a comment above the first `req.body` access: `// SICARIO: validate req.body with express-validator, joi, or zod before use`

- [ ] **`InputPathTraversalTemplate`** | **CWE-22** | **Lang:** `JS/TS`
  - **Trigger:** `path.join(baseDir, req.params.filename)` or `path.resolve(baseDir, userInput)` without a subsequent `startsWith` check
  - **Fix Pattern:** Wrap in a guard: `const safe = path.resolve(baseDir, userInput); if (!safe.startsWith(path.resolve(baseDir))) throw new Error('Path traversal blocked');`

- [ ] **`InputRegexDosTemplate`** | **CWE-1333** | **Lang:** `JS/TS`
  - **Trigger:** `new RegExp(userInput)` — user-controlled regex pattern (ReDoS risk)
  - **Fix Pattern:** Replace with a safe literal regex or add input length guard: prepend `if (userInput.length > 100) throw new Error('Input too long');`

- [ ] **`InputJsonParseNoTryCatchTemplate`** | **CWE-755** | **Lang:** `JS/TS`
  - **Trigger:** `JSON.parse(userInput)` without a surrounding `try/catch` block
  - **Fix Pattern:** Wrap in try/catch: `let parsed; try { parsed = JSON.parse(userInput); } catch (e) { return res.status(400).json({ error: 'Invalid JSON' }); }`

---

## Domain 6 — File & Resource Handling

- [ ] **`FileUploadNoMimeCheckTemplate`** | **CWE-434** | **Lang:** `JS/TS` (Multer/Express)
  - **Trigger:** `multer({ dest: '...' })` without a `fileFilter` function checking `mimetype`
  - **Fix Pattern:** Inject a `fileFilter` option: `fileFilter: (req, file, cb) => { const allowed = ['image/jpeg', 'image/png']; cb(null, allowed.includes(file.mimetype)); }`

- [ ] **`FileReadSyncTemplate`** | **CWE-400** | **Lang:** `JS/TS`
  - **Trigger:** `fs.readFileSync(userInput)` — synchronous file read with user-controlled path
  - **Fix Pattern:** Replace with async `await fs.promises.readFile(userInput)` and add path validation comment

- [ ] **`FileTempFileInsecureTemplate`** | **CWE-377** | **Lang:** `Python`
  - **Trigger:** `tempfile.mktemp()` — insecure temp file creation (race condition)
  - **Fix Pattern:** Replace with `tempfile.mkstemp()` (returns fd + path tuple)

- [ ] **`FilePermissionsWorldWritableTemplate`** | **CWE-732** | **Lang:** `Python`
  - **Trigger:** `os.chmod(path, 0o777)` or `os.chmod(path, 0o666)`
  - **Fix Pattern:** Replace the mode with `0o600` (owner read/write only)

- [ ] **`GoFileCloseErrorIgnoredTemplate`** | **CWE-390** | **Lang:** `Go`
  - **Trigger:** `defer f.Close()` where the error return is discarded (bare `defer` without error check)
  - **Fix Pattern:** Replace `defer f.Close()` with `defer func() { if err := f.Close(); err != nil { log.Printf("close error: %v", err) } }()`

---

## Domain 7 — Network & TLS

- [ ] **`TlsMinVersionTemplate`** | **CWE-326** | **Lang:** `JS/TS, Go`
  - **Trigger:** `tls.createServer({ secureProtocol: 'TLSv1_method' })` or `minVersion: 'TLSv1'` / `minVersion: 'TLSv1.1'`
  - **Fix Pattern:** Replace the version string with `'TLSv1.2'`

- [ ] **`TlsCertVerifyDisabledNodeTemplate`** | **CWE-295** | **Lang:** `JS/TS`
  - **Trigger:** `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'` or `rejectUnauthorized: false` in https/tls options
  - **Fix Pattern:** Remove the assignment (NODE_TLS) or replace `rejectUnauthorized: false` with `rejectUnauthorized: true`

- [ ] **`TlsCertVerifyDisabledGoTemplate`** | **CWE-295** | **Lang:** `Go`
  - **Trigger:** `tls.Config{ InsecureSkipVerify: true }`
  - **Fix Pattern:** Replace `InsecureSkipVerify: true` with `InsecureSkipVerify: false`

- [ ] **`SsrfHttpGetUserInputTemplate`** | **CWE-918** | **Lang:** `JS/TS, Python`
  - **Trigger:** `axios.get(req.body.url)` / `requests.get(user_url)` — user-controlled URL passed directly to HTTP client
  - **Fix Pattern:** Prepend URL allowlist check: `const parsed = new URL(req.body.url); if (!ALLOWED_HOSTS.has(parsed.hostname)) throw new Error('SSRF blocked');`

- [ ] **`SsrfFetchUserInputTemplate`** | **CWE-918** | **Lang:** `JS/TS`
  - **Trigger:** `fetch(req.query.url)` or `fetch(userInput)` — user-controlled URL in native fetch
  - **Fix Pattern:** Same allowlist guard as `SsrfHttpGetUserInputTemplate`

---

## Domain 8 — Django / Flask Specific

- [ ] **`DjangoDebugTrueTemplate`** | **CWE-215** | **Lang:** `Python` (Django)
  - **Trigger:** `DEBUG = True` in a Django settings file (detected by file path containing `settings.py`)
  - **Fix Pattern:** Replace with `DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'`

- [ ] **`DjangoSecretKeyHardcodedTemplate`** | **CWE-798** | **Lang:** `Python` (Django)
  - **Trigger:** `SECRET_KEY = '<literal string>'` in Django settings
  - **Fix Pattern:** Replace with `SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')`

- [ ] **`DjangoAllowedHostsWildcardTemplate`** | **CWE-183** | **Lang:** `Python` (Django)
  - **Trigger:** `ALLOWED_HOSTS = ['*']`
  - **Fix Pattern:** Replace with `ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')`

- [ ] **`DjangoCsrfExemptTemplate`** | **CWE-352** | **Lang:** `Python` (Django)
  - **Trigger:** `@csrf_exempt` decorator on a view function
  - **Fix Pattern:** Remove the `@csrf_exempt` decorator line and add a comment: `# SICARIO FIX: removed @csrf_exempt — ensure CSRF token is sent by client`

- [ ] **`FlaskDebugTrueTemplate`** | **CWE-215** | **Lang:** `Python` (Flask)
  - **Trigger:** `app.run(debug=True)` or `app.config['DEBUG'] = True`
  - **Fix Pattern:** Replace `debug=True` with `debug=os.environ.get('FLASK_DEBUG', 'False') == 'True'`

- [ ] **`FlaskSecretKeyHardcodedTemplate`** | **CWE-798** | **Lang:** `Python` (Flask)
  - **Trigger:** `app.secret_key = '<literal>'` or `app.config['SECRET_KEY'] = '<literal>'`
  - **Fix Pattern:** Replace the literal with `os.environ.get('FLASK_SECRET_KEY')`

- [ ] **`FlaskSqlAlchemyUriHardcodedTemplate`** | **CWE-798** | **Lang:** `Python` (Flask/SQLAlchemy)
  - **Trigger:** `SQLALCHEMY_DATABASE_URI = 'postgresql://user:password@host/db'` — credentials in URI literal
  - **Fix Pattern:** Replace with `SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')`

---

## Domain 9 — Cloud & Infrastructure

- [ ] **`AwsHardcodedAccessKeyTemplate`** | **CWE-798** | **Lang:** `JS/TS, Python`
  - **Trigger:** `accessKeyId: 'AKIA...'` or `aws_access_key_id = 'AKIA...'` — AWS key ID literal starting with `AKIA`
  - **Fix Pattern:** Remove the literal and replace with SDK default credential chain comment: `// SICARIO FIX: use IAM role or environment credentials (AWS_ACCESS_KEY_ID)`

- [ ] **`AwsS3PublicReadAclTemplate`** | **CWE-732** | **Lang:** `JS/TS, Python`
  - **Trigger:** `ACL: 'public-read'` or `ACL: 'public-read-write'` in S3 `putObject` / `upload` params
  - **Fix Pattern:** Remove the `ACL` property entirely (defaults to private)

- [ ] **`IacDockerLatestTagTemplate`** | **CWE-1104** | **Lang:** `Dockerfile`
  - **Trigger:** `FROM <image>:latest` — unpinned base image tag
  - **Fix Pattern:** Replace `:latest` with `:lts-alpine` (for node) or `:slim` (for python) as a safer default, with a comment to pin to a digest

- [ ] **`IacDockerAddInsteadOfCopyTemplate`** | **CWE-706** | **Lang:** `Dockerfile`
  - **Trigger:** `ADD <local_path> <dest>` — `ADD` with a local path (not a URL) unpacks archives and has broader permissions than `COPY`
  - **Fix Pattern:** Replace `ADD` with `COPY`

- [ ] **`IacEnvFileHardcodedTemplate`** | **CWE-798** | **Lang:** `Any` (`.env` files)
  - **Trigger:** Any line in a `.env` file matching `<KEY>=<value>` where value is not empty and not a reference (i.e., a real secret)
  - **Fix Pattern:** Replace the value with a placeholder: `<KEY>=<REPLACE_WITH_REAL_VALUE>` and add a comment `# SICARIO: do not commit real secrets`

---

## Domain 10 — React & Frontend

- [ ] **`ReactHrefJavascriptTemplate`** | **CWE-79** | **Lang:** `JS/TS` (React)
  - **Trigger:** `href={userInput}` or `href={\`${userInput}\`}` in JSX without URL scheme validation
  - **Fix Pattern:** Wrap with scheme check: `href={/^https?:\/\//.test(userInput) ? userInput : '#'}`

- [ ] **`ReactWindowLocationTemplate`** | **CWE-601** | **Lang:** `JS/TS`
  - **Trigger:** `window.location.href = userInput` or `window.location.replace(userInput)` — open redirect
  - **Fix Pattern:** Prepend URL validation: `if (!/^\//.test(userInput) && !/^https:\/\/yourdomain\.com/.test(userInput)) throw new Error('Redirect blocked');`

- [ ] **`ReactLocalStorageTokenTemplate`** | **CWE-922** | **Lang:** `JS/TS` (React)
  - **Trigger:** `localStorage.setItem('token', ...)` or `localStorage.setItem('jwt', ...)` — storing auth tokens in localStorage (XSS-accessible)
  - **Fix Pattern:** Replace with a comment: `// SICARIO FIX: store auth tokens in httpOnly cookies, not localStorage`

- [ ] **`ReactUseEffectMissingDepTemplate`** | **CWE-362** | **Lang:** `JS/TS` (React)
  - **Trigger:** `useEffect(() => { fetchData(userId) }, [])` — empty dependency array when the callback uses an outer variable (race condition / stale closure)
  - **Fix Pattern:** Replace `[]` with `[userId]` — inject the used variable into the dependency array

---

## Execution Notes

- Templates marked with `(Django)` / `(Flask)` / `(Express)` should check file path or import context before firing to avoid false positives.
- All templates must pass the **Deterministic Trimmer** constraint: output line count ≤ input line count + 2.
- Register each template in `TemplateRegistry::default()` with both a CWE entry and at least one rule-ID alias.
- Write a minimum of 3 unit tests per template: one positive match, one negative (no match), one wrong-language guard.

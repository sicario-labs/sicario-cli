// SAFE: password-in-log — password field excluded from log output
// Rule: AuthPasswordInLog | CWE-532 | Expected: TrueNegative

const express = require('express');
const app = express();
app.use(express.json());

function sanitizeForLog(obj) {
  const SENSITIVE_FIELDS = ['password', 'token', 'secret', 'apiKey', 'authorization'];
  const sanitized = { ...obj };
  for (const field of SENSITIVE_FIELDS) {
    if (field in sanitized) sanitized[field] = '[REDACTED]';
  }
  return sanitized;
}

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // SAFE: log only the sanitized request body; password is redacted
  console.log('Login attempt:', JSON.stringify(sanitizeForLog(req.body)));

  if (username === 'admin' && password === process.env.ADMIN_PASSWORD) {
    res.json({ token: 'jwt-token-here' });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.listen(3000);

// SAFE: regex-dos — safe regex without catastrophic backtracking
// Rule: InputRegexDos | CWE-1333 | Expected: TrueNegative

const express = require('express');
const app = express();

// SAFE: simple, linear-time regex without nested quantifiers that cause ReDoS
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

app.get('/validate-email', (req, res) => {
  const email = req.query.email || '';

  // SAFE: input length bounded before regex evaluation to prevent DoS
  if (email.length > 254) {
    return res.status(400).json({ valid: false, error: 'Email too long' });
  }

  const valid = EMAIL_REGEX.test(email);
  res.json({ valid });
});

app.listen(3000);

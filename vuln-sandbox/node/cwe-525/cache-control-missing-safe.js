// SAFE: cache-control-missing — Cache-Control header set to prevent caching sensitive responses
// Rule: WebCacheControlMissing | CWE-525 | Expected: TrueNegative

const express = require('express');

const app = express();

app.get('/api/profile', (req, res) => {
  // SAFE: Cache-Control set to no-store to prevent caching of sensitive data
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.json({ username: 'alice', email: 'alice@example.com' });
});

app.listen(3000);

// SAFE: open-redirect — redirect target validated against an allowlist
// Rule: ReactWindowLocation | CWE-601 | Expected: TrueNegative

const express = require('express');
const app = express();

const ALLOWED_REDIRECT_PATHS = ['/dashboard', '/profile', '/settings', '/home'];

app.get('/redirect', (req, res) => {
  const target = req.query.to;

  // SAFE: only allow redirects to known internal paths; reject external URLs
  if (!ALLOWED_REDIRECT_PATHS.includes(target)) {
    return res.redirect('/home');
  }

  res.redirect(target);
});

app.listen(3000);

// SAFE: hsts-disabled — HSTS header enabled with a long max-age
// Rule: WebHstsDisabled | CWE-319 | Expected: TrueNegative

const express = require('express');
const helmet = require('helmet');

const app = express();

// SAFE: HSTS enabled with a 1-year max-age and includeSubDomains
app.use(
  helmet.hsts({
    maxAge: 31536000,       // 1 year in seconds
    includeSubDomains: true,
    preload: true,
  })
);

app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000);

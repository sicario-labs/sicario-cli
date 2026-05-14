// SAFE: helmet-missing — helmet() middleware applied to set security headers
// Rule: WebHelmetMissing | CWE-693 | Expected: TrueNegative

const express = require('express');
const helmet = require('helmet');

const app = express();

// SAFE: helmet() sets X-Frame-Options, X-Content-Type-Options, and other security headers
app.use(helmet());

app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000);

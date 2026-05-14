// SAFE: clickjacking — X-Frame-Options set to DENY to prevent framing
// Rule: WebClickjacking | CWE-1021 | Expected: TrueNegative

const express = require('express');
const helmet = require('helmet');

const app = express();

// SAFE: X-Frame-Options set to DENY via helmet to prevent clickjacking
app.use(helmet.frameguard({ action: 'deny' }));

app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000);

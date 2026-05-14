// SAFE: referrer-policy-missing — Referrer-Policy header set to restrict leakage
// Rule: WebReferrerPolicyMissing | CWE-200 | Expected: TrueNegative

const express = require('express');
const helmet = require('helmet');

const app = express();

// SAFE: Referrer-Policy set to no-referrer-when-downgrade to prevent leaking URLs
app.use(helmet.referrerPolicy({ policy: 'no-referrer-when-downgrade' }));

app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000);

// SAFE: basic-auth-over-http — HTTPS enforced before accepting Basic Auth credentials
// Rule: AuthBasicAuthOverHttp | CWE-523 | Expected: TrueNegative

const express = require('express');
const basicAuth = require('express-basic-auth');

const app = express();

// SAFE: redirect HTTP to HTTPS before any authentication middleware runs
app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] !== 'https' && process.env.NODE_ENV === 'production') {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

app.use(
  basicAuth({
    users: { admin: process.env.ADMIN_PASSWORD },
    challenge: true,
  })
);

app.get('/admin', (req, res) => res.json({ status: 'authenticated' }));
app.listen(3000);

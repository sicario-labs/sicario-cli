// SAFE: csp-missing — Content-Security-Policy header explicitly configured
// Rule: WebCspMissing | CWE-693 | Expected: TrueNegative

const express = require('express');
const helmet = require('helmet');

const app = express();

// SAFE: helmet.contentSecurityPolicy() sets a restrictive CSP header
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);

app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000);

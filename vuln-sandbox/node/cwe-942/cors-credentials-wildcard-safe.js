// SAFE: cors-credentials-wildcard — specific origin used with credentials instead of wildcard
// Rule: WebCorsCredentialsWildcard | CWE-942 | Expected: TrueNegative

const express = require('express');
const cors = require('cors');

const app = express();

// SAFE: specific trusted origin used; wildcard (*) is not allowed with credentials
app.use(
  cors({
    origin: 'https://app.example.com',
    credentials: true,
    methods: ['GET', 'POST'],
  })
);

app.get('/api/data', (req, res) => {
  res.json({ data: 'sensitive' });
});

app.listen(3000);

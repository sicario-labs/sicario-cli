// SAFE: ssrf-fetch — URL validation prevents SSRF via fetch()
// Rule: SsrfFetchUserInput | CWE-918 | Expected: TrueNegative

const express = require('express');

const app = express();

const ALLOWED_ORIGINS = ['https://api.example.com', 'https://data.example.com'];

app.get('/proxy', async (req, res) => {
  const targetUrl = req.query.url;

  // SAFE: validate URL against an allowlist of trusted origins before fetching
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  const origin = `${parsed.protocol}//${parsed.host}`;
  if (!ALLOWED_ORIGINS.includes(origin)) {
    return res.status(400).json({ error: 'URL not allowed' });
  }

  const response = await fetch(parsed.toString());
  const data = await response.text();
  res.send(data);
});

app.listen(3000);

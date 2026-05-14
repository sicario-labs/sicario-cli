// SAFE: ssrf-http-get — allowlist validation prevents SSRF
// Rule: SsrfHttpGetUserInput | CWE-918 | Expected: TrueNegative

const express = require('express');
const http = require('http');

const app = express();

const ALLOWED_HOSTS = ['api.example.com', 'data.example.com'];

app.get('/fetch', (req, res) => {
  const host = req.query.host;

  // SAFE: host validated against an allowlist before making outbound request
  if (!ALLOWED_HOSTS.includes(host)) {
    return res.status(400).json({ error: 'Host not allowed' });
  }

  http.get(`http://${host}/data`, (response) => {
    let data = '';
    response.on('data', (chunk) => { data += chunk; });
    response.on('end', () => res.send(data));
  }).on('error', (err) => res.status(500).json({ error: err.message }));
});

app.listen(3000);

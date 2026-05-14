// Taint: SSRF — 1-hop (JS)
// Source: req.query.url → Sink: fetch
// Expected: TruePositive (taint/cwe918)
const express = require('express');
const app = express();

app.get('/proxy', async (req, res) => {
    const url = req.query.url;                  // SOURCE: HTTP request param
    const response = await fetch(url);          // SINK: outbound HTTP request
    const data = await response.text();
    res.send(data);
});

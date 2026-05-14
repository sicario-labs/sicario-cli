// Taint: XSS — 1-hop (JS)
// Source: req.query.name → Sink: innerHTML
// Expected: TruePositive (taint/cwe79)
const express = require('express');
const app = express();

app.get('/greet', (req, res) => {
    const name = req.query.name;               // SOURCE: HTTP request param
    // SINK: innerHTML assignment with tainted data
    res.send(`<script>document.getElementById('msg').innerHTML = '${name}';</script>`);
});

// Taint: XSS — 2-hop (JS)
// Source: req.query.msg → intermediate: renderMessage() → Sink: innerHTML
// Expected: TruePositive (taint/cwe79)
const express = require('express');
const app = express();

function renderMessage(msg) {
    document.getElementById('output').innerHTML = msg; // SINK: innerHTML
}

app.get('/message', (req, res) => {
    const msg = req.query.msg;                 // SOURCE: HTTP request param
    renderMessage(msg);                        // INTERMEDIATE
    res.send('rendered');
});

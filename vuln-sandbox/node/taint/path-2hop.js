// Taint: Path Traversal — 2-hop (JS)
// Source: req.params.name → intermediate: buildPath() → Sink: fs.readFileSync
// Expected: TruePositive (taint/cwe22)
const express = require('express');
const fs = require('fs');
const app = express();

function buildPath(name) {
    return fs.readFileSync(`/data/${name}`);    // SINK: file read
}

app.get('/file/:name', (req, res) => {
    const name = req.params.name;              // SOURCE: HTTP request param
    const content = buildPath(name);           // INTERMEDIATE
    res.send(content);
});

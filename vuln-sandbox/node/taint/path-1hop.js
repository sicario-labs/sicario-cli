// Taint: Path Traversal — 1-hop (JS)
// Source: req.query.file → Sink: fs.readFile
// Expected: TruePositive (taint/cwe22)
const express = require('express');
const fs = require('fs');
const app = express();

app.get('/download', (req, res) => {
    const file = req.query.file;                // SOURCE: HTTP request param
    fs.readFile(`/uploads/${file}`, (err, data) => { // SINK: file read
        res.send(data);
    });
});

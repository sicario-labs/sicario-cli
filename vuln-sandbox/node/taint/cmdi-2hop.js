// Taint: Command Injection — 2-hop (JS)
// Source: req.body.filename → intermediate: processFile() → Sink: exec
// Expected: TruePositive (taint/cwe78)
const express = require('express');
const { exec } = require('child_process');
const app = express();

function processFile(filename) {
    exec(`convert ${filename} output.png`);     // SINK: shell command
}

app.post('/convert', (req, res) => {
    const filename = req.body.filename;         // SOURCE: HTTP request body
    processFile(filename);                      // INTERMEDIATE
    res.send('done');
});

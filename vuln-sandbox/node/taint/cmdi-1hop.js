// Taint: Command Injection — 1-hop (JS)
// Source: req.query.cmd → Sink: child_process.exec
// Expected: TruePositive (taint/cwe78)
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/run', (req, res) => {
    const cmd = req.query.cmd;                  // SOURCE: HTTP request param
    exec(`ls ${cmd}`, (err, stdout) => {        // SINK: shell command
        res.send(stdout);
    });
});

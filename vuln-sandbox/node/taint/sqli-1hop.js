// Taint: SQL Injection — 1-hop (JS)
// Source: req.query.id → Sink: db.query (same function)
// Expected: TruePositive (taint/cwe89)
const express = require('express');
const app = express();

app.get('/user', async (req, res) => {
    const id = req.query.id;                    // SOURCE: HTTP request param
    const result = await db.query(`SELECT * FROM users WHERE id = ${id}`); // SINK
    res.json(result);
});

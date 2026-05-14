// Taint: SQL Injection — 2-hop (JS)
// Source: req.query.id → intermediate: getUser() → Sink: db.query
// Expected: TruePositive (taint/cwe89)
const express = require('express');
const app = express();

function getUser(id) {
    return db.query(`SELECT * FROM users WHERE id = ${id}`); // SINK
}

app.get('/user', async (req, res) => {
    const id = req.query.id;   // SOURCE: HTTP request param
    const result = await getUser(id); // INTERMEDIATE: passes taint to getUser
    res.json(result);
});

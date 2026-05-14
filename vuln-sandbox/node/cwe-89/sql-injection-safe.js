// SAFE: sql-injection — parameterized query prevents SQL injection
// Rule: SqlStringConcat | CWE-89 | Expected: TrueNegative

const express = require('express');
const mysql = require('mysql2');

const app = express();
const db = mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });

app.get('/user/:id', (req, res) => {
  // SAFE: user input passed as a parameterized query placeholder, never concatenated
  const query = "SELECT * FROM users WHERE id = ?";
  db.query(query, [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.listen(3000);

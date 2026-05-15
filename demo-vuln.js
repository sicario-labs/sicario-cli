// VULNERABLE: sql-injection — SQL string concatenation with user input
// Rule: SqlStringConcat | CWE-89 | Severity: CRITICAL

const express = require('express');
const mysql = require('mysql2');

const app = express();
const db = mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });

app.get('/user/:id', (req, res) => {
  // VULNERABLE: user-controlled input concatenated directly into SQL query
  // SICARIO FIX (CWE-89): use parameterized query â€” replace string concat with $1 placeholder
  const query = "SELECT * FROM users WHERE id = " + req.params.id;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.listen(3000);

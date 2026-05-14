// SAFE: sql-template-string — parameterized query prevents SQL injection
// Rule: SqlTemplateString | CWE-89 | Expected: TrueNegative

const express = require('express');
const mysql = require('mysql2/promise');

const app = express();

app.get('/search', async (req, res) => {
  const db = await mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });
  const username = req.query.username;

  // SAFE: parameterized placeholder used instead of template string interpolation
  const [rows] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
  await db.end();
  res.json(rows);
});

app.listen(3000);

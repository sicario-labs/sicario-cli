// VULNERABLE: SqlStringConcat — SQL string concatenation with user input (TypeScript)
// Rule: SqlStringConcat | CWE-89 | Severity: CRITICAL

import express, { Request, Response } from 'express';
import mysql2 from 'mysql2/promise';

const app = express();

async function getUser(req: Request, res: Response): Promise<void> {
  const db = await mysql2.createConnection({
    host: 'localhost',
    user: 'root',
    database: 'app',
  });

  const userId: string = req.params.id;

  // VULNERABLE: user-controlled input concatenated directly into SQL query
  // An attacker can pass: 1 OR 1=1 -- to dump all users
  const query: string = "SELECT * FROM users WHERE id = " + userId;
  const [rows] = await db.query(query);

  await db.end();
  res.json(rows);
}

app.get('/user/:id', getUser);
app.listen(3000);

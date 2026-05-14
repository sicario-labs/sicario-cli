// SAFE: sql-injection — parameterized query prevents SQL injection (TypeScript)
// Rule: SqlStringConcat | CWE-89 | Expected: TrueNegative

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

  // SAFE: parameterized placeholder used; user input never concatenated into the query
  const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);

  await db.end();
  res.json(rows);
}

app.get('/user/:id', getUser);
app.listen(3000);

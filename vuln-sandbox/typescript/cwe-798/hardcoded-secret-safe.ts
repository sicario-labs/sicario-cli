// SAFE: hardcoded-secret — JWT secret loaded from environment variable
// Rule: js/hardcoded-jwt-secret | CWE-798 | Expected: TrueNegative

import express, { Request, Response } from 'express';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json());

// SAFE: JWT secret loaded from environment variable; never hardcoded in source
const JWT_SECRET: string = process.env.JWT_SECRET!;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable must be set');
}

app.post('/login', (req: Request, res: Response): void => {
  const { username } = req.body as { username: string };

  const token = jwt.sign(
    { sub: username, role: 'user' },
    JWT_SECRET,
    { expiresIn: '1h', algorithm: 'HS256' }
  );

  res.json({ token });
});

app.listen(3000);

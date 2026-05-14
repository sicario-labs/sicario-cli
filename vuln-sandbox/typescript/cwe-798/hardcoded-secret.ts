// VULNERABLE: js/hardcoded-jwt-secret — JWT signed with hardcoded string secret (TypeScript)
// Rule: js/hardcoded-jwt-secret | CWE-798 | Severity: CRITICAL

import express, { Request, Response } from 'express';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json());

interface LoginBody {
  username: string;
  password: string;
}

app.post('/login', (req: Request<{}, {}, LoginBody>, res: Response): void => {
  const { username, password } = req.body;

  // Simplified auth check (not the vulnerability here)
  if (username === 'admin' && password === 'password') {
    // VULNERABLE: JWT signed with hardcoded string literal
    // Anyone with access to the source code can forge tokens
    const token = jwt.sign({ username, role: 'admin' }, "my-super-secret");
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.listen(3000);

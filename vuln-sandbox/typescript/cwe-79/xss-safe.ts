// SAFE: xss — textContent used instead of innerHTML to prevent XSS (TypeScript)
// Rule: DomInnerHTML | CWE-79 | Expected: TrueNegative

import express, { Request, Response } from 'express';

const app = express();

app.get('/greet', (req: Request, res: Response): void => {
  const name: string = (req.query.name as string) || 'World';

  // SAFE: user input returned as JSON data; client should use textContent, not innerHTML
  res.json({ message: `Hello, ${name}!` });
});

// Client-side safe pattern (for documentation):
// const el = document.getElementById('greeting')!;
// el.textContent = data.message;  // SAFE: textContent does not parse HTML
// NOT: el.innerHTML = data.message;  // UNSAFE

app.listen(3000);

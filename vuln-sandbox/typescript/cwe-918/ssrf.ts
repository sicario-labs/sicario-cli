// VULNERABLE: SsrfFetchUserInput — fetch with user-controlled URL (TypeScript)
// Rule: SsrfFetchUserInput | CWE-918 | Severity: HIGH

import express, { Request, Response } from 'express';

const app = express();

app.get('/proxy', async (req: Request, res: Response): Promise<void> => {
  const targetUrl: string = req.query.url as string;

  try {
    // VULNERABLE: user-controlled URL passed directly to fetch
    // An attacker can pass: http://169.254.169.254/latest/meta-data to access cloud metadata
    const response = await fetch(targetUrl);
    const data = await response.text();
    res.send(data);
  } catch (err) {
    res.status(502).json({ error: 'Bad gateway' });
  }
});

app.listen(3000);

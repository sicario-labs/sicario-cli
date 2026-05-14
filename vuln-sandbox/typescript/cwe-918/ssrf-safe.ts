// SAFE: ssrf — URL validated against allowlist before fetch (TypeScript)
// Rule: SsrfFetchUserInput | CWE-918 | Expected: TrueNegative

import express, { Request, Response } from 'express';

const app = express();

const ALLOWED_ORIGINS: ReadonlySet<string> = new Set([
  'https://api.example.com',
  'https://data.example.com',
]);

app.get('/proxy', async (req: Request, res: Response): Promise<void> => {
  const targetUrl = req.query.url as string;

  // SAFE: parse and validate the URL against an allowlist of trusted origins
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    res.status(400).json({ error: 'Invalid URL' });
    return;
  }

  const origin = `${parsed.protocol}//${parsed.host}`;
  if (!ALLOWED_ORIGINS.has(origin)) {
    res.status(400).json({ error: 'URL not allowed' });
    return;
  }

  const response = await fetch(parsed.toString());
  const data = await response.text();
  res.send(data);
});

app.listen(3000);

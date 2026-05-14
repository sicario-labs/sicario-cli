// VULNERABLE: DomInnerHTML — innerHTML assignment with user-controlled data (TypeScript)
// Rule: DomInnerHTML | CWE-79 | Severity: HIGH

import express, { Request, Response } from 'express';

const app = express();

app.get('/search', (req: Request, res: Response): void => {
  const query: string = req.query.q as string;

  // VULNERABLE: user input reflected into HTML response via innerHTML-equivalent
  // An attacker can pass: <script>document.cookie</script> to steal session cookies
  const html: string = `
    <html>
      <body>
        <div id="results">
          <script>
            document.getElementById('results').innerHTML = '${query}';
          </script>
        </div>
      </body>
    </html>
  `;

  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

app.listen(3000);

// VULNERABLE: InputPathTraversal — path traversal via user-controlled filename (TypeScript)
// Rule: InputPathTraversal | CWE-22 | Severity: HIGH

import express, { Request, Response } from 'express';
import fs from 'fs';
import path from 'path';

const app = express();
const UPLOAD_DIR = '/var/app/uploads';

app.get('/file', (req: Request, res: Response): void => {
  const filename: string = req.query.file as string;

  // VULNERABLE: user-controlled filename used to construct file path
  // An attacker can pass: ../../etc/passwd to read arbitrary files
  const filePath: string = path.join(UPLOAD_DIR, filename);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.status(404).json({ error: 'File not found' });
      return;
    }
    res.send(data);
  });
});

app.listen(3000);

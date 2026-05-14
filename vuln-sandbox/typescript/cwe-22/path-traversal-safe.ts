// SAFE: path-traversal — path normalization and containment check prevent traversal (TypeScript)
// Rule: InputPathTraversal | CWE-22 | Expected: TrueNegative

import express, { Request, Response } from 'express';
import path from 'path';
import fs from 'fs';

const app = express();
const UPLOAD_DIR: string = path.resolve('/uploads');

app.get('/file', (req: Request, res: Response): void => {
  const filename = req.query.file as string;

  // SAFE: resolve the full path and verify it stays within the allowed directory
  const filePath = path.resolve(UPLOAD_DIR, path.basename(filename));
  if (!filePath.startsWith(UPLOAD_DIR + path.sep)) {
    res.status(400).json({ error: 'Invalid file path' });
    return;
  }

  if (!fs.existsSync(filePath)) {
    res.status(404).json({ error: 'File not found' });
    return;
  }

  res.sendFile(filePath);
});

app.listen(3000);

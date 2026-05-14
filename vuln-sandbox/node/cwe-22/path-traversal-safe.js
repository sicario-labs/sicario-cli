// SAFE: path-traversal — path normalization and allowlist prevent directory traversal
// Rule: InputPathTraversal | CWE-22 | Expected: TrueNegative

const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const UPLOAD_DIR = path.resolve('/uploads');

app.get('/file', (req, res) => {
  const filename = req.query.file;

  // SAFE: resolve the full path and verify it stays within the allowed directory
  const filePath = path.resolve(UPLOAD_DIR, path.basename(filename));
  if (!filePath.startsWith(UPLOAD_DIR + path.sep)) {
    return res.status(400).json({ error: 'Invalid file path' });
  }

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }

  res.sendFile(filePath);
});

app.listen(3000);

// SAFE: file-read-sync — async fs.readFile used instead of blocking readFileSync
// Rule: FileReadSync | CWE-400 | Expected: TrueNegative

const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const CONFIG_DIR = path.resolve(__dirname, 'config');

app.get('/config/:name', (req, res) => {
  const safeName = path.basename(req.params.name);
  const filePath = path.join(CONFIG_DIR, safeName + '.json');

  // SAFE: async readFile does not block the event loop
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(404).json({ error: 'Config not found' });
    try {
      res.json(JSON.parse(data));
    } catch {
      res.status(500).json({ error: 'Invalid config format' });
    }
  });
});

app.listen(3000);

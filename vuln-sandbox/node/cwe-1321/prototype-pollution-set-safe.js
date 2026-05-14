// SAFE: prototype-pollution-set — key validation prevents prototype pollution via bracket notation
// Rule: PrototypePollutionSet | CWE-1321 | Expected: TrueNegative

const express = require('express');
const app = express();
app.use(express.json());

const FORBIDDEN_KEYS = ['__proto__', 'constructor', 'prototype'];

app.post('/set', (req, res) => {
  const { key, value } = req.body;

  // SAFE: reject keys that would pollute the prototype chain
  if (FORBIDDEN_KEYS.includes(key) || key.includes('.')) {
    return res.status(400).json({ error: 'Invalid key' });
  }

  const store = Object.create(null);
  store[key] = value;
  res.json({ stored: store });
});

app.listen(3000);

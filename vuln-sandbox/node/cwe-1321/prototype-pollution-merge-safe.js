// SAFE: prototype-pollution-merge — Object.create(null) and key validation prevent prototype pollution
// Rule: PrototypePollutionMerge | CWE-1321 | Expected: TrueNegative

const express = require('express');
const app = express();
app.use(express.json());

const FORBIDDEN_KEYS = ['__proto__', 'constructor', 'prototype'];

function safeMerge(target, source) {
  // SAFE: skip keys that would pollute the prototype chain
  for (const key of Object.keys(source)) {
    if (FORBIDDEN_KEYS.includes(key)) continue;
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = safeMerge(Object.create(null), source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.post('/merge', (req, res) => {
  const base = Object.create(null);
  const result = safeMerge(base, req.body);
  res.json(result);
});

app.listen(3000);

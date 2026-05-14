// SAFE: eval-injection — JSON.parse used instead of eval() to prevent code injection
// Rule: InjectEval | CWE-95 | Expected: TrueNegative

const express = require('express');
const app = express();
app.use(express.text());

app.post('/calculate', (req, res) => {
  const body = req.body;

  // SAFE: JSON.parse instead of eval(); only parses data, never executes code
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  const { a, b, op } = parsed;
  const ops = { add: (x, y) => x + y, sub: (x, y) => x - y, mul: (x, y) => x * y };
  if (!ops[op]) return res.status(400).json({ error: 'Unknown operation' });

  res.json({ result: ops[op](Number(a), Number(b)) });
});

app.listen(3000);

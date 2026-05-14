// SAFE: json-parse-no-try-catch — JSON.parse wrapped in try/catch to handle errors
// Rule: InputJsonParseNoTryCatch | CWE-755 | Expected: TrueNegative

const express = require('express');
const app = express();
app.use(express.text());

app.post('/parse', (req, res) => {
  // SAFE: JSON.parse wrapped in try/catch to handle malformed input gracefully
  let parsed;
  try {
    parsed = JSON.parse(req.body);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid JSON: ' + err.message });
  }

  res.json({ received: parsed });
});

app.listen(3000);

// SAFE: jwt-none-algorithm — algorithm explicitly set to HS256; 'none' not accepted
// Rule: CryptoJwtNoneAlgorithm | CWE-347 | Expected: TrueNegative

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

app.get('/verify', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  // SAFE: algorithms array explicitly excludes 'none'; only HS256 is accepted
  jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] }, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    res.json({ user: decoded });
  });
});

app.listen(3000);

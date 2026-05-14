// SAFE: jwt-weak-algorithm — strong RS256 algorithm used instead of weak HS256 with shared secret
// Rule: CryptoJwtWeakAlgorithm | CWE-327 | Expected: TrueNegative

const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();

// SAFE: RS256 asymmetric algorithm used; private key signs, public key verifies
const privateKey = fs.readFileSync(process.env.JWT_PRIVATE_KEY_PATH);
const publicKey = fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH);

app.post('/token', (req, res) => {
  const token = jwt.sign({ sub: req.body.userId }, privateKey, {
    algorithm: 'RS256',
    expiresIn: '1h',
  });
  res.json({ token });
});

app.get('/verify', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  jwt.verify(token, publicKey, { algorithms: ['RS256'] }, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    res.json({ user: decoded });
  });
});

app.listen(3000);

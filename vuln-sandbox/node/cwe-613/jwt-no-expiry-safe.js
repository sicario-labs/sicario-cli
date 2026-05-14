// SAFE: jwt-no-expiry — JWT issued with an expiration time
// Rule: AuthJwtNoExpiry | CWE-613 | Expected: TrueNegative

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

app.post('/login', (req, res) => {
  const { username } = req.body;

  // SAFE: expiresIn set to 1 hour; token will expire and cannot be used indefinitely
  const token = jwt.sign(
    { sub: username, role: 'user' },
    process.env.JWT_SECRET,
    { expiresIn: '1h', algorithm: 'HS256' }
  );

  res.json({ token });
});

app.listen(3000);

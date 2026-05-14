// SAFE: req-body-no-validation — input validated with a schema before use
// Rule: InputReqBodyNoValidation | CWE-20 | Expected: TrueNegative

const express = require('express');
const app = express();
app.use(express.json());

function validateUser(body) {
  const errors = [];
  if (typeof body.username !== 'string' || body.username.length < 3 || body.username.length > 32) {
    errors.push('username must be a string between 3 and 32 characters');
  }
  if (typeof body.email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) {
    errors.push('email must be a valid email address');
  }
  return errors;
}

app.post('/users', (req, res) => {
  // SAFE: validate all fields before processing
  const errors = validateUser(req.body);
  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }

  const { username, email } = req.body;
  res.status(201).json({ username, email });
});

app.listen(3000);

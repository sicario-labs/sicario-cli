// SAFE: session-fixation — session regenerated after login to prevent fixation
// Rule: AuthSessionFixation | CWE-384 | Expected: TrueNegative

const express = require('express');
const session = require('express-session');

const app = express();
app.use(express.json());
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (username === 'admin' && password === process.env.ADMIN_PASSWORD) {
    // SAFE: regenerate session ID after successful authentication to prevent session fixation
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error' });
      req.session.userId = username;
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ error: 'Session save error' });
        res.json({ message: 'Logged in' });
      });
    });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.listen(3000);

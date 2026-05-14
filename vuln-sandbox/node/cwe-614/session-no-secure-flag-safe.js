// SAFE: session-no-secure-flag — session cookie has secure flag set to true
// Rule: AuthSessionNoSecureFlag | CWE-614 | Expected: TrueNegative

const express = require('express');
const session = require('express-session');

const app = express();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      // SAFE: secure flag ensures cookie is only sent over HTTPS
      secure: true,
      httpOnly: true,
      sameSite: 'strict',
      maxAge: 3600000,
    },
  })
);

app.get('/', (req, res) => res.json({ status: 'ok' }));
app.listen(3000);

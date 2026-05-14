// SAFE: session-no-httponly — session cookie has httpOnly flag set to true
// Rule: AuthSessionNoHttpOnly | CWE-1004 | Expected: TrueNegative

const express = require('express');
const session = require('express-session');

const app = express();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      // SAFE: httpOnly prevents JavaScript from accessing the session cookie
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 3600000,
    },
  })
);

app.get('/', (req, res) => res.json({ status: 'ok' }));
app.listen(3000);

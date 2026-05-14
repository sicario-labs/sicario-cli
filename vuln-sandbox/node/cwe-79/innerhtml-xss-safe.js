// SAFE: innerhtml-xss — textContent used instead of innerHTML to prevent XSS
// Rule: DomInnerHTML | CWE-79 | Expected: TrueNegative

const express = require('express');
const app = express();

app.get('/greet', (req, res) => {
  const name = req.query.name || 'World';

  // SAFE: user input is sent as JSON data; the client should use textContent, not innerHTML
  res.json({ message: `Hello, ${name}!` });
});

// Client-side safe pattern (for documentation):
// const el = document.getElementById('greeting');
// el.textContent = data.message;  // SAFE: textContent does not parse HTML
// NOT: el.innerHTML = data.message;  // UNSAFE

app.listen(3000);

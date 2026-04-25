// Test file to trigger PR scan and verify the atob fix
const express = require("express");
const app = express();

// Intentional SQL injection vulnerability for scan testing
app.get("/users", (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// Intentional XSS vulnerability for scan testing
app.get("/search", (req, res) => {
  const term = req.query.q;
  res.send("<h1>Results for: " + term + "</h1>");
});

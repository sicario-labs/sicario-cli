// Intentionally vulnerable code for testing PR scan workflow
// This file contains security issues that the SAST engine should detect

const express = require('express');
const app = express();

// SQL Injection via string concatenation (js-sql-string-concat)
function getUser(userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  return db.query(query);
}

// XSS via innerHTML assignment (js-xss-innerhtml-assignment)
function renderContent(userInput) {
  document.getElementById('output').innerHTML = userInput;
}

// eval usage (js-eval-usage)
function processInput(data) {
  eval(data);
}

// document.write XSS (js-xss-document-write)
function writeOutput(content) {
  document.write(content);
}

// SQL template literal injection (js-sql-template-literal)
function deleteUser(id) {
  const query = `DELETE FROM users WHERE id = ${id}`;
  return db.query(query);
}

// dangerouslySetInnerHTML (js-xss-dangerously-set-inner-html)
function RenderHTML({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

module.exports = { getUser, renderContent, processInput, writeOutput, deleteUser };

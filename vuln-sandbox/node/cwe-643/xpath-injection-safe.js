// SAFE: xpath-injection — parameterized XPath query prevents injection
// Rule: InjectXpath | CWE-643 | Expected: TrueNegative

const express = require('express');
const xpath = require('xpath');
const { DOMParser } = require('@xmldom/xmldom');

const app = express();

const xmlDoc = new DOMParser().parseFromString(
  '<users><user id="1"><name>Alice</name></user><user id="2"><name>Bob</name></user></users>'
);

app.get('/user', (req, res) => {
  const userId = req.query.id;

  // SAFE: validate that id is a positive integer before using in XPath
  if (!/^\d+$/.test(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  // SAFE: numeric ID validated; no string interpolation of arbitrary user input
  const nodes = xpath.select(`/users/user[@id="${userId}"]/name`, xmlDoc);
  const names = nodes.map((n) => n.firstChild.nodeValue);
  res.json({ names });
});

app.listen(3000);

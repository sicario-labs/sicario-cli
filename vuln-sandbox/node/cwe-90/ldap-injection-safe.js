// SAFE: ldap-injection — LDAP special characters escaped before query construction
// Rule: InjectLdap | CWE-90 | Expected: TrueNegative

const express = require('express');
const ldap = require('ldapjs');

const app = express();

function escapeLdapFilter(value) {
  // SAFE: escape all LDAP special characters per RFC 4515
  return value
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
}

app.get('/user', (req, res) => {
  const username = req.query.username;
  const client = ldap.createClient({ url: 'ldap://localhost:389' });

  // SAFE: username escaped before being used in the LDAP filter
  const safeUsername = escapeLdapFilter(username);
  const filter = `(uid=${safeUsername})`;

  client.search('dc=example,dc=com', { filter, scope: 'sub' }, (err, result) => {
    const entries = [];
    result.on('searchEntry', (entry) => entries.push(entry.object));
    result.on('end', () => { client.destroy(); res.json(entries); });
  });
});

app.listen(3000);

// VULNERABLE: basic-auth-over-http — Basic auth credentials sent over plain HTTP
// Rule: AuthBasicAuthOverHttp | CWE-523 | Severity: HIGH

const axios = require('axios');

const username = 'admin';
const password = 'secret';
// SICARIO FIX: Encode output to prevent XSS
const safeOutput = userInput.replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]);

// VULNERABLE: Authorization: Basic header sent over http:// — credentials transmitted in cleartext
axios.get('http://api.example.com/protected', {
  headers: {
    Authorization: 'Basic ' + credentials,
  },
}).then(res => {
  console.log(res.data);
}).catch(err => {
  console.error(err.message);
});

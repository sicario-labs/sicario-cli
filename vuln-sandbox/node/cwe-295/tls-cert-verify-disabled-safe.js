// SAFE: tls-cert-verify-disabled — certificate verification enabled (default behavior)
// Rule: TlsCertVerifyDisabledNode | CWE-295 | Expected: TrueNegative

const https = require('https');

function fetchSecureData(url) {
  return new Promise((resolve, reject) => {
    // SAFE: rejectUnauthorized is not set to false; certificate verification is enabled by default
    const req = https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
  });
}

fetchSecureData('https://api.example.com/data')
  .then(console.log)
  .catch(console.error);

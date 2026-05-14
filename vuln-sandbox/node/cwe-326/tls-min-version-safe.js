// SAFE: tls-min-version — TLS minimum version set to TLSv1.2 or higher
// Rule: TlsMinVersion | CWE-326 | Expected: TrueNegative

const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('/etc/ssl/private/server.key'),
  cert: fs.readFileSync('/etc/ssl/certs/server.crt'),
  // SAFE: minimum TLS version set to TLSv1.2; TLSv1.0 and TLSv1.1 are disabled
  minVersion: 'TLSv1.2',
  ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES256-GCM-SHA384',
};

const server = https.createServer(options, (req, res) => {
  res.writeHead(200);
  res.end('Secure connection established\n');
});

server.listen(443);

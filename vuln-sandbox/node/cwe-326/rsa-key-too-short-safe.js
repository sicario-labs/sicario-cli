// SAFE: rsa-key-too-short — RSA key generated with 4096-bit modulus
// Rule: CryptoRsaKeyTooShort | CWE-326 | Expected: TrueNegative

const crypto = require('crypto');

// SAFE: 4096-bit RSA key exceeds the minimum recommended 2048-bit key size
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 4096,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const message = Buffer.from('Hello, secure world!');
const encrypted = crypto.publicEncrypt(publicKey, message);
const decrypted = crypto.privateDecrypt(privateKey, encrypted);

console.log('Decrypted:', decrypted.toString());

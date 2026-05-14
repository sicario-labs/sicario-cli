// SAFE: pbkdf2-low-iterations — PBKDF2 used with sufficient iterations (600,000+)
// Rule: CryptoPbkdf2LowIterations | CWE-916 | Expected: TrueNegative

const crypto = require('crypto');

function hashPassword(password) {
  const salt = crypto.randomBytes(32);
  // SAFE: 600,000 iterations meets NIST SP 800-132 recommendation for PBKDF2-HMAC-SHA256
  const hash = crypto.pbkdf2Sync(password, salt, 600000, 64, 'sha256');
  return { salt: salt.toString('hex'), hash: hash.toString('hex') };
}

function verifyPassword(password, saltHex, hashHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const hash = crypto.pbkdf2Sync(password, salt, 600000, 64, 'sha256');
  return crypto.timingSafeEqual(hash, Buffer.from(hashHex, 'hex'));
}

const { salt, hash } = hashPassword('my-secure-password');
console.log('Password hashed securely');
console.log('Verification:', verifyPassword('my-secure-password', salt, hash));

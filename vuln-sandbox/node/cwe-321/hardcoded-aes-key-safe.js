// SAFE: hardcoded-aes-key — AES key loaded from environment variable, not hardcoded
// Rule: CryptoHardcodedAesKey | CWE-321 | Expected: TrueNegative

const crypto = require('crypto');

function encrypt(plaintext) {
  // SAFE: key loaded from environment variable; never hardcoded in source
  const key = Buffer.from(process.env.AES_KEY, 'hex');
  if (key.length !== 32) throw new Error('AES_KEY must be 32 bytes (64 hex chars)');

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return { iv: iv.toString('hex'), encrypted: encrypted.toString('hex'), authTag: authTag.toString('hex') };
}

const result = encrypt('sensitive data');
console.log('Encrypted:', result);

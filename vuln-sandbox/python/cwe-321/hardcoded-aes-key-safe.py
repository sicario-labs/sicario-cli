# SAFE: hardcoded-aes-key — AES key loaded from environment variable
# Rule: CryptoHardcodedAesKey | CWE-321 | Expected: TrueNegative

import os
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(plaintext: bytes) -> dict:
    """Encrypt data using AES-256-GCM with a key from the environment."""
    # SAFE: key loaded from environment variable; never hardcoded in source
    key_hex = os.environ['AES_KEY']
    key = binascii.unhexlify(key_hex)
    if len(key) != 32:
        raise ValueError('AES_KEY must be 32 bytes (64 hex chars)')

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {'nonce': nonce.hex(), 'ciphertext': ciphertext.hex()}


if __name__ == '__main__':
    result = encrypt(b'sensitive data')
    print('Encrypted:', result)

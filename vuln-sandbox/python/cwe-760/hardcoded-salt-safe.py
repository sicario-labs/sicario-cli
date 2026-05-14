# SAFE: hardcoded-salt — random salt generated per password using os.urandom
# Rule: CryptoHardcodedSalt | CWE-760 | Expected: TrueNegative

import hashlib
import os
import binascii


def hash_password(password: str) -> str:
    """Hash a password with a unique random salt."""
    # SAFE: salt generated randomly per password using os.urandom; never hardcoded
    salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
    return binascii.hexlify(salt).decode() + ':' + binascii.hexlify(dk).decode()


def verify_password(password: str, stored: str) -> bool:
    """Verify a password against a stored hash."""
    salt_hex, hash_hex = stored.split(':')
    salt = binascii.unhexlify(salt_hex)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
    return binascii.hexlify(dk).decode() == hash_hex


if __name__ == '__main__':
    stored = hash_password('my-secure-password')
    print('Verified:', verify_password('my-secure-password', stored))

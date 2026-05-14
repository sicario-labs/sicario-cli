# SAFE: pbkdf2-low-iterations — PBKDF2 used with sufficient iterations (600,000+)
# Rule: CryptoPbkdf2LowIterations | CWE-916 | Expected: TrueNegative

import hashlib
import os
import binascii


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with 600,000 iterations."""
    salt = os.urandom(32)
    # SAFE: 600,000 iterations meets NIST SP 800-132 recommendation for PBKDF2-HMAC-SHA256
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
    return binascii.hexlify(salt).decode() + ':' + binascii.hexlify(dk).decode()


def verify_password(password: str, stored: str) -> bool:
    """Verify a password against a stored PBKDF2 hash."""
    salt_hex, hash_hex = stored.split(':')
    salt = binascii.unhexlify(salt_hex)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
    return binascii.hexlify(dk).decode() == hash_hex


if __name__ == '__main__':
    stored = hash_password('my-secure-password')
    print('Verified:', verify_password('my-secure-password', stored))

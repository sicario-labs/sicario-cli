# SAFE: md5-password-hash — bcrypt used instead of MD5 for password hashing
# Rule: CryptoMd5PasswordHash | CWE-916 | Expected: TrueNegative

import bcrypt


def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt with a work factor of 12."""
    # SAFE: bcrypt is a purpose-built password hashing function with adaptive cost;
    # MD5 is not used for password storage
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt)


def verify_password(password: str, hashed: bytes) -> bool:
    """Verify a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode(), hashed)


if __name__ == '__main__':
    hashed = hash_password('my-secure-password')
    print('Verified:', verify_password('my-secure-password', hashed))

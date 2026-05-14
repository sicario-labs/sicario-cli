# SAFE: insecure-random-seed — secrets module used for cryptographic randomness
# Rule: CryptoInsecureRandomSeed | CWE-335 | Expected: TrueNegative

import secrets


def generate_token() -> str:
    """Generate a cryptographically secure random token."""
    # SAFE: secrets.token_hex uses os.urandom internally; suitable for security-sensitive use
    return secrets.token_hex(32)


def generate_session_id() -> str:
    """Generate a cryptographically secure session ID."""
    # SAFE: secrets.token_urlsafe generates a URL-safe random string
    return secrets.token_urlsafe(32)


if __name__ == '__main__':
    print('Token:', generate_token())
    print('Session ID:', generate_session_id())

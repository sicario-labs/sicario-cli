# SAFE: rsa-key-too-short — RSA key generated with 4096-bit modulus
# Rule: CryptoRsaKeyTooShort | CWE-326 | Expected: TrueNegative

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def generate_rsa_keypair():
    """Generate a 4096-bit RSA key pair."""
    # SAFE: 4096-bit key exceeds the minimum recommended 2048-bit key size
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    return private_key, private_key.public_key()


if __name__ == '__main__':
    private_key, public_key = generate_rsa_keypair()
    message = b'Hello, secure world!'
    ciphertext = public_key.encrypt(message, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ))
    plaintext = private_key.decrypt(ciphertext, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ))
    print('Decrypted:', plaintext.decode())

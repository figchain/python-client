from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import binascii


def load_ed25519_private_key(hex_key: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(binascii.unhexlify(hex_key))


def load_x25519_private_key(hex_key: str) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(binascii.unhexlify(hex_key))


def decrypt_x25519(packed_blob: bytes, private_key: X25519PrivateKey) -> bytes:
    """
    Decrypts X25519 envelope.
    Format: EphemeralPubKey (32) || IV (12) || Ciphertext
    """
    if len(packed_blob) < 32 + 12:
        raise ValueError("Blob too short")

    ephemeral_pub_bytes = packed_blob[:32]
    iv = packed_blob[32:44]
    ciphertext = packed_blob[44:]

    ephemeral_pub_key = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
    shared_secret = private_key.exchange(ephemeral_pub_key)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=b"",
    )
    kek = hkdf.derive(shared_secret)

    # Decrypt AES-GCM
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(iv, ciphertext, None)


def sign_ed25519(message: bytes, private_key: Ed25519PrivateKey) -> bytes:
    return private_key.sign(message)


def decrypt_aes_gcm(encrypted_bytes: bytes, key: bytes) -> bytes:
    """
    Decrypts data using AES-GCM.
    Expected format: IV (12 bytes) + Ciphertext + Tag (16 bytes)
    """
    if len(encrypted_bytes) < 28:
        raise ValueError("Encrypted data too short")

    iv = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)

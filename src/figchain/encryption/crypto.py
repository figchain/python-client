from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

from ..util import load_rsa_private_key

def load_private_key(path: str) -> rsa.RSAPrivateKey:
    return load_rsa_private_key(path)

def unwrap_aes_key(wrapped_key: bytes, kek: bytes) -> bytes:
    """
    Unwraps an AES key using RFC 3394 AES Key Wrap.
    """
    return aes_key_unwrap(kek, wrapped_key)

def decrypt_rsa_oaep(encrypted_bytes: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Decrypts data using RSA-OAEP with SHA-256 and MGF1(SHA-256).
    """
    return private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_aes_gcm(encrypted_bytes: bytes, key: bytes) -> bytes:
    """
    Decrypts data using AES-GCM.
    Expected format: IV (12 bytes) + Ciphertext + Tag (16 bytes, appended by GCM)
    python cryptography GCM expects tag to be appended to ciphertext, which matches Java GCM default.
    """
    if len(encrypted_bytes) < 28: # 12 IV + 16 Tag
        raise ValueError("Encrypted data too short")

    iv = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]

    tag = ciphertext[-16:]
    actual_ciphertext = ciphertext[:-16]

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()

    return decryptor.update(actual_ciphertext) + decryptor.finalize()


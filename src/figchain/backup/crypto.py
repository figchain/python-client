import binascii
import base64
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from ..encryption import crypto

logger = logging.getLogger(__name__)


def load_private_key(hex_key: str):
    try:
        data = binascii.unhexlify(hex_key)
        if len(data) == 32:
            try:
                return Ed25519PrivateKey.from_private_bytes(data)
            except Exception:
                return X25519PrivateKey.from_private_bytes(data)
        return data  # raw bytes if fallback
    except Exception as e:
        logger.error(f"Failed to load hex key: {e}")
        raise


def calculate_fingerprint(private_key) -> str:
    if hasattr(private_key, "public_key"):
        pub = private_key.public_key()
        pub_bytes = pub.public_bytes(
            encoding=crypto.serialization.Encoding.Raw,
            format=crypto.serialization.PublicFormat.Raw,
        )
    else:
        # Fallback for raw bytes if any
        pub_bytes = private_key

    digest = hashes.Hash(hashes.SHA256())
    digest.update(pub_bytes)
    return digest.finalize().hex()


def decrypt_aes_key(encrypted_key_b64: str, private_key) -> bytes:
    blob = base64.b64decode(encrypted_key_b64)
    # Use the unified decryption logic
    if isinstance(private_key, X25519PrivateKey):
        return crypto.decrypt_x25519(blob, private_key)
    else:
        # Fallback or error
        raise ValueError("Backup decryption currently requires X25519 key")


def decrypt_data(encrypted_data_b64: str, aes_key: bytes) -> str:
    blob = base64.b64decode(encrypted_data_b64)
    return crypto.decrypt_aes_gcm(blob, aes_key).decode("utf-8")

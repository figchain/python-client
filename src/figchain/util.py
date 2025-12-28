import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)

def load_rsa_private_key(path: str) -> rsa.RSAPrivateKey:
    """
    Loads an RSA private key from a PEM-encoded file.
    """
    try:
        with open(path, "rb") as f:
            return parse_rsa_private_key(f.read())
    except FileNotFoundError:
        logger.error(f"Private key file not found: {path}")
        raise
    except (IOError, OSError) as e:
        logger.error(f"Failed to read private key file {path}: {e}")
        raise

def parse_rsa_private_key(key_bytes: bytes) -> rsa.RSAPrivateKey:
    """
    Parses an RSA private key from PEM-encoded bytes.
    """
    try:
        return serialization.load_pem_private_key(
            key_bytes,
            password=None
        )
    except (ValueError, TypeError) as e:
        logger.error(f"Failed to parse private key: {e}")
        raise

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

def load_private_key(path: str):
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None, # Encrypted keys not supported in this simplistic snippet
            backend=default_backend()
        )

def calculate_fingerprint(private_key) -> str:
    original_public_key = private_key.public_key()
    der = original_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(der)
    return digest.finalize().hex()

def decrypt_aes_key(encrypted_key_b64: str, private_key) -> bytes:
    encrypted_key = base64.b64decode(encrypted_key_b64)

    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_data(encrypted_data_b64: str, aes_key: bytes) -> str:
    encrypted_bytes = base64.b64decode(encrypted_data_b64)

    if len(encrypted_bytes) < 28: # 12 IV + 16 Tag
        raise ValueError("Encrypted data too short")

    iv = encrypted_bytes[:12]
    # In standard Java GCM output, the tag is appended to the ciphertext.
    # Python cryptography expects tag separately.
    tag = encrypted_bytes[-16:]
    ciphertext = encrypted_bytes[12:-16]

    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')

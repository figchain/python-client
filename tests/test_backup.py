import base64
import json
import os
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from figchain.backup.service import decrypt_backup

FIXTURES = Path(__file__).parent / "fixtures"
# Throwaway local-dev key matching fixtures/backup_v3.json.
V3_KEY_HEX = "807c5fb05b1ea661625cade3c12c5db6059b95d40e91381233d26d5b1574e440"


def _v3_key():
    return X25519PrivateKey.from_private_bytes(bytes.fromhex(V3_KEY_HEX))


def _v3_backup() -> dict:
    return json.loads((FIXTURES / "backup_v3.json").read_text())


def _build_backup(private_key, payload: dict, version="v2", public_data=None):
    """Encrypt a backup the way the server does (X25519-ECIES + AES-GCM)."""
    aes_key = AESGCM.generate_key(bit_length=256)

    eph = X25519PrivateKey.generate()
    kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"").derive(
        eph.exchange(private_key.public_key())
    )
    iv = os.urandom(12)
    eph_pub = eph.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    wrapped = eph_pub + iv + AESGCM(kek).encrypt(iv, aes_key, None)

    aad = public_data.encode("utf-8") if public_data is not None else None
    data_iv = os.urandom(12)
    ct = AESGCM(aes_key).encrypt(data_iv, json.dumps(payload).encode(), aad)

    doc = {
        "version": version,
        "algorithm": "X25519-ECIES",
        "keyFingerprint": "unused",
        "encryptedKey": base64.b64encode(wrapped).decode(),
        "encryptedData": base64.b64encode(data_iv + ct).decode(),
    }
    if public_data is not None:
        doc["publicData"] = public_data
    return doc


def test_decrypts_v3_test_vector():
    payload = decrypt_backup(_v3_backup(), _v3_key())
    assert payload.tenant_id == "plugin_e2e"
    assert len(payload.items_data) == 2
    assert payload.public_data is not None
    assert "schemas" in payload.public_data
    assert "generatedAt" in payload.public_data


def test_v2_still_decrypts():
    key = X25519PrivateKey.generate()
    doc = _build_backup(key, {"tenantId": "t2", "syncToken": "s", "items": []})
    payload = decrypt_backup(doc, key)
    assert payload.tenant_id == "t2"
    assert payload.sync_token == "s"
    assert payload.public_data is None


def test_v3_built_in_test_roundtrips():
    key = X25519PrivateKey.generate()
    pub = json.dumps({"generatedAt": "x", "schemas": {}})
    doc = _build_backup(key, {"tenantId": "t3"}, version="v3", public_data=pub)
    assert decrypt_backup(doc, key).tenant_id == "t3"


def test_tampered_public_data_fails():
    doc = _v3_backup()
    doc["publicData"] = doc["publicData"].replace("{", "{ ", 1)
    with pytest.raises(InvalidTag):
        decrypt_backup(doc, _v3_key())


def test_v3_marked_as_v2_fails():
    doc = _v3_backup()
    doc["version"] = "v2"
    with pytest.raises(InvalidTag):
        decrypt_backup(doc, _v3_key())


def test_v3_missing_public_data_errors():
    doc = _v3_backup()
    del doc["publicData"]
    with pytest.raises(ValueError, match="publicData"):
        decrypt_backup(doc, _v3_key())


def test_unknown_version_errors():
    doc = _v3_backup()
    doc["version"] = "v9"
    with pytest.raises(ValueError, match="Unsupported backup version 'v9'"):
        decrypt_backup(doc, _v3_key())


def test_fingerprint_from_hex_key():
    from figchain.backup.crypto import calculate_fingerprint, load_private_key

    key = load_private_key(V3_KEY_HEX)
    assert isinstance(key, X25519PrivateKey)
    assert (
        calculate_fingerprint(key)
        == "1560c7168e948cebfb07a001592a7cc8be5032230abfd9e056b4e7422299ad5f"
    )


def test_decrypts_v3_via_hex_key_loader():
    from figchain.backup.crypto import load_private_key

    payload = decrypt_backup(_v3_backup(), load_private_key(V3_KEY_HEX))
    assert payload.tenant_id == "plugin_e2e"

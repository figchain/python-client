import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import ed25519

from figchain.auth import SharedSecretTokenProvider, PrivateKeyTokenProvider


def test_shared_secret_token_provider():
    secret = "my-secret"
    provider = SharedSecretTokenProvider(secret)
    assert provider.get_token() == secret


def test_private_key_token_provider():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    service_id = "sa-123"
    key_id = "key-456"
    provider = PrivateKeyTokenProvider(private_key, service_id, key_id=key_id)

    token = provider.get_token()

    # Verify token
    decoded = jwt.decode(
        token, public_key, algorithms=["EdDSA"], options={"verify_exp": True}
    )

    assert decoded["iss"] == service_id
    assert decoded["sub"] == service_id
    assert "exp" in decoded

    # Verify header kid
    headers = jwt.get_unverified_header(token)
    assert headers["kid"] == key_id


def test_private_key_token_provider_expiry():
    private_key = ed25519.Ed25519PrivateKey.generate()

    # Very short TTL
    provider = PrivateKeyTokenProvider(
        private_key, "sa", token_ttl_minutes=-1
    )  # Expired
    token = provider.get_token()

    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, private_key.public_key(), algorithms=["EdDSA"])

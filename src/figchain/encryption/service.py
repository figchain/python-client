import base64
import logging
from typing import Dict, Optional
from ..transport import Transport
from ..models import Fig
from . import crypto

logger = logging.getLogger(__name__)


class EncryptionService:
    def __init__(
        self,
        transport: Transport,
        private_key: any,
        s3_backup_enabled: bool = False,
        s3_backup_config: Optional[dict] = None,
        client_id: Optional[str] = None,
    ):
        self.transport = transport
        self.s3_backup_enabled = s3_backup_enabled
        self.s3_backup_config = s3_backup_config or {}
        self.client_id = client_id
        self.private_key = private_key
        self.nsk_cache: Dict[str, bytes] = {}

    def decrypt(self, fig: Fig, namespace: str) -> bytes:
        if not fig.isEncrypted:
            return fig.payload

        nsk_id = fig.keyId
        wrapped_dek = fig.wrappedDek

        if not wrapped_dek:
            raise ValueError("Encrypted fig has no wrapped DEK")

        # Get NSK
        nsk = self._get_nsk(namespace, nsk_id)

        # Unwrap DEK (AES-GCM wrap only now)
        try:
            dek = crypto.decrypt_aes_gcm(wrapped_dek, nsk)
        except Exception as e:
            raise ValueError("Failed to unwrap DEK via AES-GCM") from e

        # Decrypt Payload
        return crypto.decrypt_aes_gcm(fig.payload, dek)

    def _get_nsk(self, namespace: str, key_id: Optional[str]) -> bytes:
        if key_id and key_id in self.nsk_cache:
            return self.nsk_cache[key_id]

        matching_key = None

        # Try API
        try:
            ns_keys = self.transport.get_namespace_key(namespace)
            matching_key = next((key for key in ns_keys if key.key_id == key_id), None)
            if not matching_key and not key_id and ns_keys:
                matching_key = ns_keys[0]
        except Exception as e:
            if not self.s3_backup_enabled:
                logger.warning(
                    f"Failed to fetch NSK from API and s3 backup disabled: {e}"
                )
                pass  # Proceed to fallback check

        # Try S3 Fallback
        if not matching_key and self.s3_backup_enabled and self.client_id:
            try:
                matching_key = self._fetch_from_s3(namespace)
                # Ensure ID match if requested
                if key_id and matching_key.key_id != key_id:
                    matching_key = None
            except Exception as e:
                logger.warning(f"Failed to fetch NSK from S3: {e}")

        if not matching_key:
            raise ValueError(
                f"No matching key found for namespace {namespace} and keyId {key_id} (API and S3 failed)"
            )

        try:
            wrapped_key_bytes = base64.b64decode(matching_key.wrapped_key)
            # Decrypt X25519
            unwrapped_nsk = crypto.decrypt_x25519(wrapped_key_bytes, self.private_key)

            if matching_key.key_id:
                self.nsk_cache[matching_key.key_id] = unwrapped_nsk

            return unwrapped_nsk
        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Failed to fetch/decrypt NSK for namespace {namespace}: {e}")
            raise

    def _fetch_from_s3(self, namespace: str):
        try:
            import boto3
            import json
            from types import SimpleNamespace
        except ImportError:
            logger.error("boto3 required for s3 backup operations")
            raise

        bucket = self.s3_backup_config.get("bucket")
        prefix = self.s3_backup_config.get("prefix", "")
        region = self.s3_backup_config.get("region", "us-east-1")
        endpoint = self.s3_backup_config.get("endpoint")

        s3 = boto3.client("s3", region_name=region, endpoint_url=endpoint)

        if prefix and not prefix.endswith("/"):
            prefix += "/"

        # Path: devices/{client_id}/namespaces/{namespace}.json
        key = f"{prefix}devices/{self.client_id}/namespaces/{namespace}.json"

        resp = s3.get_object(Bucket=bucket, Key=key)
        content = resp["Body"].read().decode("utf-8")
        data = json.loads(content)

        return SimpleNamespace(
            key_id=str(data.get("keyId")), wrapped_key=data.get("wrappedKey")
        )

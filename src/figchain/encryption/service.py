import base64
import logging
from typing import Dict, Optional, Any
from ..transport import Transport
from ..models import Fig
from . import crypto

logger = logging.getLogger(__name__)

class EncryptionService:
    def __init__(self, transport: Transport, private_key_path: str):
        self.transport = transport
        try:
            self.private_key = crypto.load_private_key(private_key_path)
            self.nsk_cache: Dict[str, bytes] = {}
        except (ImportError, FileNotFoundError) as e:
            logger.error(f"Failed to initialize EncryptionService: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error loading encryption private key: {e}")
            raise

    def decrypt(self, fig: Fig, namespace: str) -> bytes:
        if not fig.isEncrypted:
            return fig.payload

        nsk_id = fig.keyId
        wrapped_dek = fig.wrappedDek

        if not wrapped_dek:
            raise ValueError("Encrypted fig has no wrapped DEK")

        # Get NSK
        nsk = self._get_nsk(namespace, nsk_id)

        # Unwrap DEK
        dek = crypto.unwrap_aes_key(wrapped_dek, nsk)

        # Decrypt Payload
        return crypto.decrypt_aes_gcm(fig.payload, dek)

    def _get_nsk(self, namespace: str, key_id: Optional[str]) -> bytes:
        if key_id and key_id in self.nsk_cache:
            return self.nsk_cache[key_id]

        try:
            ns_keys = self.transport.get_namespace_key(namespace)

            matching_key = next((key for key in ns_keys if key.key_id == key_id), None)

            if not matching_key:
                if not key_id and ns_keys:
                    # Fallback to first if no ID requested
                    matching_key = ns_keys[0]
                else:
                    raise ValueError(f"No matching key found for namespace {namespace} and keyId {key_id}")

            wrapped_key_bytes = base64.b64decode(matching_key.wrapped_key)
            unwrapped_nsk = crypto.decrypt_rsa_oaep(wrapped_key_bytes, self.private_key)

            if matching_key.key_id:
                self.nsk_cache[matching_key.key_id] = unwrapped_nsk

            return unwrapped_nsk
        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Failed to fetch/decrypt NSK for namespace {namespace}: {e}")
            raise

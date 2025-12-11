import json
import logging
import uuid
import base64
from datetime import datetime
from typing import List, Optional
from ..config import Config
from ..models import FigFamily, FigDefinition, Fig, Rule, Condition, Operator
from .crypto import load_private_key, calculate_fingerprint, decrypt_aes_key, decrypt_data
from .fetcher import S3VaultFetcher

logger = logging.getLogger(__name__)

class VaultPayload:
    def __init__(self, tenant_id: str, generated_at: str, sync_token: str, items_data: List[dict]):
        self.tenant_id = tenant_id
        self.generated_at = generated_at
        self.sync_token = sync_token
        self.items_data = items_data

    @property
    def items(self) -> List[FigFamily]:
        families = []
        for d in self.items_data:
            try:
                families.append(self._dict_to_fig_family(d))
            except Exception as e:
                logger.error(f"Failed to parse FigFamily from vault backup: {e}")
        return families

    def _dict_to_fig_family(self, d: dict) -> FigFamily:
        # Definition
        def_data = d['definition']
        definition = FigDefinition(
            namespace=def_data['namespace'],
            key=def_data['key'],
            figId=uuid.UUID(def_data['figId']),
            schemaUri=def_data['schemaUri'],
            schemaVersion=def_data['schemaVersion'],
            createdAt=self._parse_dt(def_data['createdAt']),
            updatedAt=self._parse_dt(def_data['updatedAt'])
        )

        # Figs
        figs = []
        for f in d.get('figs', []):
            # Assume base64 string for bytes in JSON
            payload = base64.b64decode(f['payload']) if isinstance(f['payload'], str) else f['payload']

            figs.append(Fig(
                figId=uuid.UUID(f['figId']),
                version=uuid.UUID(f['version']),
                payload=payload
            ))

        # Rules
        rules = []
        for r in d.get('rules', []):
            conditions = []
            for c in r.get('conditions', []):
                conditions.append(Condition(
                    variable=c['variable'],
                    operator=Operator(c['operator']),
                    values=c['values']
                ))

            rules.append(Rule(
                description=r.get('description'),
                conditions=conditions,
                targetVersion=uuid.UUID(r['targetVersion'])
            ))

        # Default Version
        dv = uuid.UUID(d['defaultVersion']) if d.get('defaultVersion') else None

        return FigFamily(
            definition=definition,
            figs=figs,
            rules=rules,
            defaultVersion=dv
        )

    def _parse_dt(self, dt_str: str) -> datetime:
        # Handle various formats if needed, but ISO is standard
        # Replace Z with +00:00 for fromisoformat compatibility in older python versions if needed
        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))

class VaultService:
    def __init__(self, config: Config):
        self.config = config

    def load_backup(self) -> Optional[VaultPayload]:
        if not self.config.vault_enabled:
            return None

        if not self.config.vault_private_key_path:
            raise ValueError("Vault private key path not configured")

        # 1. Load Private Key
        logger.debug(f"Loading private key from {self.config.vault_private_key_path}")
        private_key = load_private_key(self.config.vault_private_key_path)

        # 2. Calculate Fingerprint
        fingerprint = calculate_fingerprint(private_key)
        logger.debug(f"Calculated key fingerprint: {fingerprint}")

        # 3. Fetch Encrypted Backup
        logger.debug("Fetching backup from S3...")
        fetcher = S3VaultFetcher(self.config)
        try:
            backup_io = fetcher.fetch_backup(fingerprint)
            backup_data = json.load(backup_io)
        finally:
            fetcher.close()

        # 4. Decrypt AES Key
        logger.debug("Decrypting AES key...")
        encrypted_key = backup_data.get("encryptedKey")
        if not encrypted_key:
            raise ValueError("Invalid backup format: missing encryptedKey")

        aes_key = decrypt_aes_key(encrypted_key, private_key)

        # 5. Decrypt Payload
        logger.debug("Decrypting payload...")
        encrypted_data = backup_data.get("encryptedData")
        if not encrypted_data:
            raise ValueError("Invalid backup format: missing encryptedData")

        json_payload = decrypt_data(encrypted_data, aes_key)

        # 6. Parse
        payload_dict = json.loads(json_payload)

        logger.info(f"Successfully loaded backup from vault. Tenant: {payload_dict.get('tenantId')}")

        return VaultPayload(
            tenant_id=payload_dict.get("tenantId"),
            generated_at=payload_dict.get("generatedAt"),
            sync_token=payload_dict.get("syncToken"),
            items_data=payload_dict.get("items", [])
        )

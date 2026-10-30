import base64
import json
import logging
import uuid
from datetime import datetime

from ..config import Config
from ..models import Condition, Fig, FigDefinition, FigFamily, Operator, Rule
from .crypto import (
    calculate_fingerprint,
    decrypt_aes_key,
    decrypt_data,
    load_private_key,
)
from .fetcher import S3BackupFetcher

logger = logging.getLogger(__name__)


SUPPORTED_BACKUP_VERSIONS = ("v2", "v3")


class BackupPayload:
    def __init__(
        self,
        tenant_id: str,
        generated_at: str,
        sync_token: str,
        items_data: list[dict],
        public_data: dict | None = None,
    ):
        self.tenant_id = tenant_id
        # Parsed v3 public section (e.g. generatedAt, schemas); None for v2.
        self.public_data = public_data
        self.generated_at = generated_at
        self.sync_token = sync_token
        self.items_data = items_data

    @property
    def items(self) -> list[FigFamily]:
        families = []
        for d in self.items_data:
            try:
                families.append(self._dict_to_fig_family(d))
            except Exception as e:
                logger.error(f"Failed to parse FigFamily from backup: {e}")
        return families

    def _dict_to_fig_family(self, d: dict) -> FigFamily:
        # Definition
        def_data = d["definition"]
        definition = FigDefinition(
            namespace=def_data["namespace"],
            key=def_data["key"],
            figId=uuid.UUID(def_data["figId"]),
            schemaUri=def_data["schemaUri"],
            schemaVersion=def_data["schemaVersion"],
            createdAt=self._parse_dt(def_data["createdAt"]),
            updatedAt=self._parse_dt(def_data["updatedAt"]),
        )

        # Figs. The server writes each item as {definition, latestFig}; a
        # FigFamily-shaped "figs" list is also accepted.
        figs = []
        latest = d.get("latestFig")
        if latest:
            figs.append(self._latest_fig_to_fig(latest))
        for f in d.get("figs", []):
            # Assume base64 string for bytes in JSON
            payload = (
                base64.b64decode(f["payload"])
                if isinstance(f["payload"], str)
                else f["payload"]
            )

            figs.append(
                Fig(
                    figId=uuid.UUID(f["figId"]),
                    version=uuid.UUID(f["version"]),
                    payload=payload,
                )
            )

        # Rules
        rules = []
        for r in d.get("rules", []):
            conditions = []
            for c in r.get("conditions", []):
                conditions.append(
                    Condition(
                        variable=c["variable"],
                        operator=Operator(c["operator"]),
                        values=c["values"],
                    )
                )

            rules.append(
                Rule(
                    description=r.get("description"),
                    conditions=conditions,
                    targetVersion=uuid.UUID(r["targetVersion"]),
                )
            )

        # Default Version
        dv = uuid.UUID(d["defaultVersion"]) if d.get("defaultVersion") else None

        return FigFamily(
            definition=definition, figs=figs, rules=rules, defaultVersion=dv
        )

    @staticmethod
    def _latest_fig_to_fig(f: dict) -> Fig:
        """Map the server's Fig JSON (payload.data.binaryData) to a client Fig."""
        data = (f.get("payload") or {}).get("data") or {}
        binary = data.get("binaryData")
        if binary is None:
            raise ValueError(
                f"latestFig {f.get('figId')} has no payload.data.binaryData"
            )
        wrapped_dek = f.get("wrappedDek")
        return Fig(
            figId=uuid.UUID(f["figId"]),
            version=uuid.UUID(f["version"]),
            payload=base64.b64decode(binary),
            isEncrypted=bool(f.get("encrypted")),
            wrappedDek=base64.b64decode(wrapped_dek) if wrapped_dek else None,
            encryptionAlgorithm=f.get("encryptionAlgorithm"),
            keyId=f.get("keyId"),
        )

    def _parse_dt(self, dt_str: str) -> datetime:
        # Handle various formats if needed, but ISO is standard
        # Replace Z with +00:00 for fromisoformat compatibility in older python versions if needed
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))


def decrypt_backup(backup_data: dict, private_key) -> BackupPayload:
    """Decrypt a parsed backup document (format v2 or v3)."""
    version = backup_data.get("version", "v2")
    if version not in SUPPORTED_BACKUP_VERSIONS:
        raise ValueError(
            f"Unsupported backup version {version!r}; "
            f"supported: {', '.join(SUPPORTED_BACKUP_VERSIONS)}"
        )

    aad = None
    public_data = None
    if version == "v3":
        public_str = backup_data.get("publicData")
        if not isinstance(public_str, str):
            raise ValueError("Invalid v3 backup format: missing publicData string")
        # The exact UTF-8 bytes of publicData are authenticated as AES-GCM AAD.
        aad = public_str.encode("utf-8")

    # Decrypt AES Key
    logger.debug("Decrypting AES key...")
    encrypted_key = backup_data.get("encryptedKey")
    if not encrypted_key:
        raise ValueError("Invalid backup format: missing encryptedKey")

    aes_key = decrypt_aes_key(encrypted_key, private_key)

    # Decrypt Payload
    logger.debug("Decrypting payload...")
    encrypted_data = backup_data.get("encryptedData")
    if not encrypted_data:
        raise ValueError("Invalid backup format: missing encryptedData")

    json_payload = decrypt_data(encrypted_data, aes_key, aad)

    if aad is not None:
        # Only parse after the tag has authenticated it.
        public_data = json.loads(aad)

    # Parse
    payload_dict = json.loads(json_payload)

    logger.info(
        f"Successfully loaded backup from s3 backup. Tenant: {payload_dict.get('tenantId')}"
    )

    return BackupPayload(
        tenant_id=payload_dict.get("tenantId"),
        generated_at=payload_dict.get("generatedAt"),
        sync_token=payload_dict.get("syncToken"),
        items_data=payload_dict.get("items", []),
        public_data=public_data,
    )


class S3BackupService:
    def __init__(self, config: Config):
        self.config = config

    def load_backup(self) -> BackupPayload | None:
        if not self.config.s3_backup_enabled:
            return None

        # Backups are encrypted to the X25519 encryption key; the auth key is only a fallback
        # for configs that set a single key, since it would otherwise always win.
        s3_backup_key_hex = (
            self.config.encryption_private_key or self.config.auth_private_key
        )
        if not s3_backup_key_hex:
            raise ValueError("Backup private key (hex) not configured")

        # 1. Load Private Key
        logger.debug("Loading private key from config (hex)")
        private_key = load_private_key(s3_backup_key_hex)

        # 2. Calculate Fingerprint
        fingerprint = calculate_fingerprint(private_key)
        logger.debug(f"Calculated key fingerprint: {fingerprint}")

        # 3. Fetch Encrypted Backup
        logger.debug("Fetching backup from S3...")
        fetcher = S3BackupFetcher(self.config)
        try:
            backup_io = fetcher.fetch_backup(fingerprint)
            backup_data = json.load(backup_io)
        finally:
            fetcher.close()

        return decrypt_backup(backup_data, private_key)

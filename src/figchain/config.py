import json
import os
import sys
from dataclasses import dataclass, field
from enum import Enum

import yaml


class BootstrapStrategy(Enum):
    SERVER = "server"
    SERVER_FIRST = "server-first"
    S3_BACKUP_ONLY = "s3-backup-only"
    HYBRID = "hybrid"


@dataclass
class Config:
    base_url: str = "https://app.figchain.io/api/"
    long_polling_base_url: str | None = None
    client_secret: str | None = None
    environment_id: str | None = None
    namespaces: set[str] = field(default_factory=set)
    as_of: str | None = None
    poll_interval: float = 60  # seconds
    max_retries: int = 3
    retry_delay_ms: int = 1000
    bootstrap_strategy: BootstrapStrategy = BootstrapStrategy.SERVER_FIRST
    tenant_id: str = "default"
    use_long_polling: bool = True

    # S3 Backup Configuration
    s3_backup_enabled: bool = False
    s3_backup_bucket: str | None = None
    s3_backup_prefix: str = ""
    s3_backup_region: str = "us-east-1"
    s3_backup_endpoint: str | None = None
    s3_backup_path_style_access: bool = False

    # Encryption
    encryption_private_key: str | None = None
    auth_private_key: str | None = None
    auth_client_id: str | None = None
    auth_credential_id: str | None = None

    @staticmethod
    def _map_legacy_keys(yaml_data: dict) -> None:
        """Maps legacy keys to internal fields."""
        key_map = {
            "privateKey": "auth_private_key",
            "encryptionPrivateKey": "encryption_private_key",
            "authPrivateKey": "auth_private_key",
            "tenantId": "tenant_id",
            "environmentId": "environment_id",
        }
        for camel, snake in key_map.items():
            if camel in yaml_data:
                yaml_data[snake] = yaml_data.pop(camel)

        if "namespace" in yaml_data:
            ns = yaml_data.pop("namespace")
            if "namespaces" not in yaml_data:
                yaml_data["namespaces"] = [ns]

        if "backup" in yaml_data:
            yaml_data.pop("backup")

    @classmethod
    def load(cls, path: str | None = None, **kwargs) -> "Config":
        """Loads configuration from file, environment, and kwargs."""

        config_data = {}

        # Config file
        def _load_from_file(p: str):
            try:
                with open(p) as f:
                    content = f.read()
            except FileNotFoundError:
                raise

            _, ext = os.path.splitext(p)
            ext = ext.lower()

            # If extension is explicit, parse strictly according to it.
            if ext == ".json":
                data = json.loads(content) or {}
            elif ext in (".yml", ".yaml"):
                data = yaml.safe_load(content) or {}
            else:
                # No extension: try YAML first, then JSON as a fallback.
                try:
                    data = yaml.safe_load(content) or {}
                except yaml.YAMLError as e_yaml:
                    try:
                        data = json.loads(content) or {}
                    except json.JSONDecodeError:
                        # Raise the original YAML error for clarity.
                        raise e_yaml from None

            if isinstance(data, dict):
                cls._map_legacy_keys(data)
            return data

        if path:
            # Load the provided path. _load_from_file handles strict extension
            # parsing and fallbacks for extension-less files.
            config_data.update(_load_from_file(path))
        else:
            # look for common filenames
            if os.path.exists("figchain.yaml"):
                config_data.update(_load_from_file("figchain.yaml"))
            elif os.path.exists("figchain.yml"):
                config_data.update(_load_from_file("figchain.yml"))
            elif os.path.exists("figchain.json"):
                config_data.update(_load_from_file("figchain.json"))

        # Environment Variables
        env_map = {
            "FIGCHAIN_URL": "base_url",
            "FIGCHAIN_LONG_POLLING_URL": "long_polling_base_url",
            "FIGCHAIN_CLIENT_SECRET": "client_secret",
            "FIGCHAIN_ENVIRONMENT_ID": "environment_id",
            "FIGCHAIN_NAMESPACE": "namespaces",  # Special handling in loop below
            "FIGCHAIN_NAMESPACES": "namespaces",
            "FIGCHAIN_POLLING_INTERVAL_MS": "poll_interval",
            "FIGCHAIN_MAX_RETRIES": "max_retries",
            "FIGCHAIN_RETRY_DELAY_MS": "retry_delay_ms",
            "FIGCHAIN_AS_OF_TIMESTAMP": "as_of",
            "FIGCHAIN_BOOTSTRAP_STRATEGY": "bootstrap_strategy",
            "FIGCHAIN_USE_LONG_POLLING": "use_long_polling",
            "FIGCHAIN_S3_BACKUP_ENABLED": "s3_backup_enabled",
            "FIGCHAIN_S3_BACKUP_BUCKET": "s3_backup_bucket",
            "FIGCHAIN_S3_BACKUP_PREFIX": "s3_backup_prefix",
            "FIGCHAIN_S3_BACKUP_REGION": "s3_backup_region",
            "FIGCHAIN_S3_BACKUP_ENDPOINT": "s3_backup_endpoint",
            "FIGCHAIN_S3_BACKUP_PATH_STYLE_ACCESS": "s3_backup_path_style_access",
            "FIGCHAIN_ENCRYPTION_PRIVATE_KEY": "encryption_private_key",
            "FIGCHAIN_IDENTITY_PRIVATE_KEY": "auth_private_key",
        }

        def normalize_strategy(val: str) -> str:
            # Normalize to kebab-case (e.g., S3_BACKUP_ONLY -> s3-backup-only)
            return val.lower().replace("_", "-")

        for env_key, config_key in env_map.items():
            val = os.getenv(env_key)
            if val is not None:
                if env_key == "FIGCHAIN_NAMESPACE":
                    config_data["namespaces"] = {val.strip()}
                elif config_key == "namespaces":
                    config_data[config_key] = {
                        s.strip() for s in val.split(",") if s.strip()
                    }
                elif env_key == "FIGCHAIN_POLLING_INTERVAL_MS":
                    config_data[config_key] = int(val) / 1000
                elif config_key in ("max_retries", "retry_delay_ms"):
                    config_data[config_key] = int(val)
                elif config_key in (
                    "s3_backup_enabled",
                    "s3_backup_path_style_access",
                    "use_long_polling",
                ):
                    config_data[config_key] = val.lower() in ("true", "1", "yes")
                elif config_key == "bootstrap_strategy":
                    try:
                        config_data[config_key] = BootstrapStrategy(
                            normalize_strategy(val)
                        )
                    except ValueError:
                        print(f"Invalid bootstrap strategy: {val}", file=sys.stderr)
                else:
                    config_data[config_key] = val

        # kwargs (Overrides)
        for k, v in kwargs.items():
            if v is not None:
                config_data[k] = v

        # Convert types if necessary (dataclass doesn't auto-convert)
        if "namespaces" in config_data and isinstance(config_data["namespaces"], list):
            config_data["namespaces"] = set(config_data["namespaces"])

        if "bootstrap_strategy" in config_data and isinstance(
            config_data["bootstrap_strategy"], str
        ):
            try:
                config_data["bootstrap_strategy"] = BootstrapStrategy(
                    normalize_strategy(config_data["bootstrap_strategy"])
                )
            except ValueError:
                print(
                    "Invalid bootstrap strategy: {}".format(
                        config_data["bootstrap_strategy"]
                    ),
                    file=sys.stderr,
                )

        return cls(**config_data)

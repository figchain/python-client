import os
import sys
import json
import yaml
from dataclasses import dataclass, field
from typing import Set, Optional
from enum import Enum


class BootstrapStrategy(Enum):
    SERVER = "server"
    SERVER_FIRST = "server-first"
    VAULT = "vault"
    HYBRID = "hybrid"


@dataclass
class Config:
    base_url: str = "https://app.figchain.io/api/"
    long_polling_base_url: Optional[str] = None
    client_secret: Optional[str] = None
    environment_id: Optional[str] = None
    namespaces: Set[str] = field(default_factory=set)
    as_of: Optional[str] = None
    poll_interval: int = 60
    max_retries: int = 3
    retry_delay_ms: int = 1000
    bootstrap_strategy: BootstrapStrategy = BootstrapStrategy.SERVER
    tenant_id: str = "default"

    # Vault Configuration
    vault_enabled: bool = False
    vault_bucket: Optional[str] = None
    vault_prefix: str = ""
    vault_region: str = "us-east-1"
    vault_endpoint: Optional[str] = None
    vault_path_style_access: bool = False
    vault_private_key_path: Optional[str] = None

    # Encryption
    encryption_private_key_path: Optional[str] = None
    auth_private_key_path: Optional[str] = None
    auth_private_key_pem: Optional[str] = None
    auth_client_id: Optional[str] = None
    auth_credential_id: Optional[str] = None

    @staticmethod
    def _map_legacy_keys(yaml_data: dict) -> None:
        """
        Maps camelCase keys from JSON/YAML to snake_case for the internal Config object.
        Also handles legacy field mapping like 'namespace' to 'namespaces'.
        """
        key_map = {
            "credentialId": "auth_credential_id",
            "privateKey": "auth_private_key_pem",
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
            # Ignore or map backup if needed
            yaml_data.pop("backup")

    @classmethod
    def load(cls, path: Optional[str] = None, **kwargs) -> "Config":
        """
        Loads configuration from YAML (optional), Environment Variables, and kwargs.
        Precedence: kwargs > Env Vars > YAML > Defaults
        """

        # 1. Defaults (handled by dataclass)
        config_data = {}

        # 2. Config file (YAML or JSON) - autodetect by extension or try both
        def _load_from_file(p: str):
            try:
                with open(p, "r") as f:
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

        # 3. Environment Variables
        env_map = {
            "FIGCHAIN_URL": "base_url",
            "FIGCHAIN_LONG_POLLING_URL": "long_polling_base_url",
            "FIGCHAIN_CLIENT_SECRET": "client_secret",
            "FIGCHAIN_ENVIRONMENT_ID": "environment_id",
            "FIGCHAIN_NAMESPACES": "namespaces",
            "FIGCHAIN_POLLING_INTERVAL_MS": "poll_interval",
            "FIGCHAIN_MAX_RETRIES": "max_retries",
            "FIGCHAIN_RETRY_DELAY_MS": "retry_delay_ms",
            "FIGCHAIN_AS_OF_TIMESTAMP": "as_of",
            "FIGCHAIN_BOOTSTRAP_STRATEGY": "bootstrap_strategy",
            "FIGCHAIN_VAULT_ENABLED": "vault_enabled",
            "FIGCHAIN_VAULT_BUCKET": "vault_bucket",
            "FIGCHAIN_VAULT_PREFIX": "vault_prefix",
            "FIGCHAIN_VAULT_REGION": "vault_region",
            "FIGCHAIN_VAULT_ENDPOINT": "vault_endpoint",
            "FIGCHAIN_VAULT_PATH_STYLE_ACCESS": "vault_path_style_access",
            "FIGCHAIN_VAULT_PRIVATE_KEY_PATH": "vault_private_key_path",
            "FIGCHAIN_ENCRYPTION_PRIVATE_KEY_PATH": "encryption_private_key_path",
            "FIGCHAIN_AUTH_PRIVATE_KEY_PATH": "auth_private_key_path",
        }

        for env_key, config_key in env_map.items():
            val = os.getenv(env_key)
            if val is not None:
                if config_key == "namespaces":
                    config_data[config_key] = set(
                        s.strip() for s in val.split(",") if s.strip()
                    )
                elif config_key in ("poll_interval", "max_retries", "retry_delay_ms"):
                    config_data[config_key] = int(val)
                elif config_key in ("vault_enabled", "vault_path_style_access"):
                    config_data[config_key] = val.lower() in ("true", "1", "yes")
                elif config_key == "bootstrap_strategy":
                    try:
                        config_data[config_key] = BootstrapStrategy(val.lower())
                    except ValueError:
                        print("Invalid bootstrap strategy: %s" % val, file=sys.stderr)
                        pass
                else:
                    config_data[config_key] = val

        # 4. kwargs (Overrides)
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
                    config_data["bootstrap_strategy"]
                )
            except ValueError:
                print(
                    "Invalid bootstrap strategy: %s"
                    % config_data["bootstrap_strategy"],
                    file=sys.stderr,
                )
                pass

        return cls(**config_data)

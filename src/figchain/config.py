import os
import sys
import yaml
from dataclasses import dataclass, field
from typing import Set, Optional, List
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
    auth_client_id: Optional[str] = None

    @classmethod
    def load(cls, path: Optional[str] = None, **kwargs) -> 'Config':
        """
        Loads configuration from YAML (optional), Environment Variables, and kwargs.
        Precedence: kwargs > Env Vars > YAML > Defaults
        """

        # 1. Defaults (handled by dataclass)
        config_data = {}

        # 2. YAML
        if path:
            with open(path, 'r') as f:
                yaml_data = yaml.safe_load(f) or {}
                # Map snake_case keys from yaml to config_data
                config_data.update(yaml_data)
        elif os.path.exists("figchain.yaml"):
            with open("figchain.yaml", 'r') as f:
                yaml_data = yaml.safe_load(f) or {}
                config_data.update(yaml_data)

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
                    config_data[config_key] = set(s.strip() for s in val.split(",") if s.strip())
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

        if "bootstrap_strategy" in config_data and isinstance(config_data["bootstrap_strategy"], str):
            try:
                config_data["bootstrap_strategy"] = BootstrapStrategy(config_data["bootstrap_strategy"])
            except ValueError:
                print("Invalid bootstrap strategy: %s" % config_data["bootstrap_strategy"], file=sys.stderr)
                pass

        return cls(**config_data)

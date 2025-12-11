import boto3
from botocore.client import Config as BotoConfig
import io
from ..config import Config

class S3VaultFetcher:
    def __init__(self, config: Config):
        self.bucket = config.vault_bucket
        self.prefix = config.vault_prefix

        s3_config = BotoConfig(
            region_name=config.vault_region,
            s3={'addressing_style': 'path'} if config.vault_path_style_access else None
        )

        self.s3_client = boto3.client(
            's3',
            region_name=config.vault_region,
            endpoint_url=config.vault_endpoint,
            config=s3_config
        )

    def fetch_backup(self, key_fingerprint: str) -> io.BytesIO:
        key = "backup.json"

        if key_fingerprint:
            key = f"{key_fingerprint}/{key}"

        if self.prefix:
            key = f"{self.prefix.rstrip('/')}/{key}"

        # S3 keys should not have a leading slash
        key = key.lstrip('/')

        try:
            response = self.s3_client.get_object(Bucket=self.bucket, Key=key)
            return io.BytesIO(response['Body'].read())
        except Exception as e:
            raise Exception(f"Failed to fetch backup from S3: {e}") from e

    def close(self):
        # Boto3 client doesn't strictly need close, but good practice if available
        pass

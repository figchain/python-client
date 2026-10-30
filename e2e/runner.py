"""Cross-client e2e runner for the Python client.

Driven by figchain-clients/e2e/run.py; see its README for the contract. Prints one
``E2E-RESULT {json}`` line.
"""

import json
import logging
import os
import sys
import threading
from dataclasses import asdict, dataclass

from figchain import FigChainClient
from figchain.config import BootstrapStrategy, Config

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

STRATEGIES = {
    "server-first": BootstrapStrategy.SERVER_FIRST,
    "hybrid": BootstrapStrategy.HYBRID,
    "backup-only": BootstrapStrategy.S3_BACKUP_ONLY,
    "listen": BootstrapStrategy.SERVER_FIRST,
}


@dataclass
class CheckoutSettings:
    currency: str
    maxItems: int


def emit(**result):
    print("E2E-RESULT " + json.dumps(result), flush=True)


def describe(value):
    if not isinstance(value, CheckoutSettings):
        return {"ok": False, "error": f"expected CheckoutSettings, got {value!r}"}
    return {"ok": True, "value": asdict(value), "type": type(value).__name__}


def main():
    mode = sys.argv[1]
    env = os.environ
    cfg = Config(
        base_url=env["FC_BASE_URL"], client_secret=env["FC_CLIENT_SECRET"],
        environment_id=env["FC_ENVIRONMENT_ID"], tenant_id=env["FC_TENANT_ID"],
        namespaces={env["FC_NAMESPACE"]}, bootstrap_strategy=STRATEGIES[mode],
        s3_backup_enabled=True, s3_backup_bucket=env["FC_S3_BUCKET"], s3_backup_prefix=env["FC_S3_PREFIX"],
        s3_backup_endpoint=env["FC_S3_ENDPOINT"], s3_backup_path_style_access=True,
        s3_backup_region=env["AWS_REGION"], encryption_private_key=env["FC_ENCRYPTION_PRIVATE_KEY"],
        poll_interval=1, max_retries=1, retry_delay_ms=100)
    key = env["FC_FIG_KEY"]
    client = FigChainClient(config=cfg)
    try:
        if mode != "listen":
            emit(mode=mode, **describe(client.get_fig(key, CheckoutSettings)))
            return
        initial = client.get_fig(key, CheckoutSettings)
        received = []
        changed = threading.Event()

        def on_change(value):
            if value != initial:
                received.append(value)
                changed.set()
        client.register_listener(key, on_change, CheckoutSettings)
        print("E2E-READY", flush=True)
        if changed.wait(timeout=float(env.get("FC_LISTEN_TIMEOUT", "60"))):
            emit(mode=mode, **describe(received[0]))
        else:
            emit(mode=mode, ok=False, error="listener saw no change")
    finally:
        client.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # report, don't just crash, so the orchestrator shows the reason
        emit(ok=False, error=f"{type(e).__name__}: {e}")
        sys.exit(1)

import threading
import json
import uuid
import time
from datetime import datetime
import pytest
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

from figchain import FigChainClient
from figchain.models import InitialFetchResponse, FigFamily, FigDefinition, Fig
from figchain.serialization import serialize, serialize_ocf, register_schema_from_file

@dataclass
class UserConfig:
    backgroundColor: str
    enabled: bool

def test_client_e2e():
    # Register schema
    register_schema_from_file("tests/user_config.avsc")

    # Create payload
    config = UserConfig(backgroundColor="red", enabled=True)
    payload = serialize(config, "UserConfig")

    # Mock data
    env_id = uuid.uuid4()
    namespace = "test-ns"
    key = "my-key"

    fig_def = FigDefinition(
        namespace=namespace,
        key=key,
        figId=uuid.uuid4(),
        schemaUri="http://example.com/schema",
        schemaVersion="1.0",
        createdAt=datetime.now(),
        updatedAt=datetime.now()
    )

    fig = Fig(
        figId=fig_def.figId,
        version=uuid.uuid4(),
        payload=payload
    )

    family = FigFamily(
        definition=fig_def,
        figs=[fig],
        rules=[],
        defaultVersion=fig.version
    )

    init_response = InitialFetchResponse(
        figFamilies=[family],
        cursor="cursor-1",
        environmentId=env_id
    )

    # Mock Transport
    with patch("figchain.transport.requests.Session") as mock_session_cls:
        mock_session = mock_session_cls.return_value

        # Mock fetch_initial and fetch_updates responses
        mock_init_resp = MagicMock()
        mock_init_resp.status_code = 200
        mock_init_resp.content = serialize_ocf(init_response, "InitialFetchResponse")

        # Prepare an update response
        config_v2 = UserConfig(backgroundColor="blue", enabled=False)
        payload_v2 = serialize(config_v2, "UserConfig")
        fig_v2 = Fig(
            figId=fig_def.figId,
            version=uuid.uuid4(),
            payload=payload_v2
        )
        family_v2 = FigFamily(
            definition=fig_def,
            figs=[fig_v2],
            rules=[],
            defaultVersion=fig_v2.version
        )
        from figchain.models import UpdateFetchResponse
        update_resp_obj = UpdateFetchResponse(
            figFamilies=[family_v2],
            cursor="cursor-2"
        )
        mock_update_resp = MagicMock()
        mock_update_resp.status_code = 200
        mock_update_resp.content = serialize_ocf(update_resp_obj, "UpdateFetchResponse")

        # side_effect logic
        allow_update = threading.Event()

        def mock_post_side_effect(*args, **kwargs):
            # We can check the mock_session.post call count, but side_effect is stateful.
            pass

        # We need to distinguish initial fetch from update fetch.
        # Initial fetch happens in __init__ (main thread). Update fetch in thread.

        update_iter = iter([mock_update_resp, Exception("Stop Polling")])

        def side_effect(*args, **kwargs):
            # Initial fetch is usually checking url ending in /data/initial
            url = args[0] if len(args) > 0 else kwargs.get("url")
            if "initial" in url:
                return mock_init_resp
            else:
                # Update fetch
                # Block until we allow it
                allow_update.wait(timeout=5.0)
                item = next(update_iter)
                if isinstance(item, Exception):
                    raise item
                return item

        mock_session.post.side_effect = side_effect

        client = FigChainClient(
            base_url="http://localhost",
            client_secret="secret",
            environment_id=str(env_id),
            namespaces={namespace},
            poll_interval=0.1 # fast poll
        )

        # Test get_fig - should be initial state (red)
        result = client.get_fig(key, UserConfig)

        assert result is not None
        assert result.backgroundColor == "red"

        # Test listener
        listener_event = threading.Event()
        received_config = None

        def on_update(cfg):
            nonlocal received_config
            received_config = cfg
            listener_event.set()

        client.register_listener(key, on_update, UserConfig)

        # Trigger update
        allow_update.set()

        # Wait for update
        if listener_event.wait(timeout=2.0):
            assert received_config is not None
            assert received_config.backgroundColor == "blue"
            assert received_config.enabled is False
        else:
            pytest.fail("Listener was not triggered")

        client.close()

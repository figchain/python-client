import uuid
from unittest.mock import MagicMock, patch

import pytest

from figchain.auth import SharedSecretTokenProvider
from figchain.models import InitialFetchResponse, UpdateFetchResponse
from figchain.transport import Transport


@pytest.fixture
def mock_session():
    with patch("requests.Session") as mock:
        yield mock.return_value


@pytest.fixture
def transport(mock_session):
    token_provider = SharedSecretTokenProvider("secret")
    return Transport("http://api", token_provider, uuid.uuid4())


def test_fetch_initial_success(transport, mock_session):
    # Setup response
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    # We rely on serialization working.
    # The serialization module already registers schemas on import.
    from figchain.serialization import serialize_ocf

    resp_obj = InitialFetchResponse(
        figFamilies=[], cursor="cursor", environmentId=uuid.uuid4(), schemas={}
    )
    mock_resp.content = serialize_ocf(resp_obj, "InitialFetchResponse")
    mock_session.post.return_value = mock_resp

    res = transport.fetch_initial("ns")
    assert res.cursor == "cursor"
    assert res.environmentId == resp_obj.environmentId


def test_fetch_initial_401(transport, mock_session):
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_session.post.return_value = mock_resp

    with pytest.raises(PermissionError, match="Authentication failed"):
        transport.fetch_initial("ns")


def test_fetch_initial_403(transport, mock_session):
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_session.post.return_value = mock_resp

    with pytest.raises(PermissionError, match="Authorization failed"):
        transport.fetch_initial("ns")


def test_fetch_updates_success(transport, mock_session):
    # Setup response
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    from figchain.serialization import serialize_ocf

    resp_obj = UpdateFetchResponse(figFamilies=[], cursor="new-cursor", schemas={})
    mock_resp.content = serialize_ocf(resp_obj, "UpdateFetchResponse")
    mock_session.post.return_value = mock_resp

    res = transport.fetch_updates("ns", "old-cursor")
    assert res.cursor == "new-cursor"


def test_fetch_updates_httperror(transport, mock_session):
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.raise_for_status.side_effect = Exception("Server Error")
    mock_session.post.return_value = mock_resp

    with pytest.raises(Exception, match="Server Error"):
        transport.fetch_updates("ns", "c")


def _ok_update(mock_session):
    from figchain.serialization import serialize_ocf

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = serialize_ocf(
        UpdateFetchResponse(figFamilies=[], cursor="c2"), "UpdateFetchResponse"
    )
    mock_session.post.return_value = mock_resp


def test_fetch_updates_long_poll_sends_wait_header(transport, mock_session):
    _ok_update(mock_session)

    transport.fetch_updates("ns", "c1", wait_seconds=30)
    _, kwargs = mock_session.post.call_args
    assert kwargs["headers"]["X-Long-Poll-Timeout"] == "30"
    assert kwargs["timeout"] == 35

    transport.fetch_updates("ns", "c1")
    _, kwargs = mock_session.post.call_args
    assert "X-Long-Poll-Timeout" not in kwargs["headers"]
    assert kwargs["timeout"] == 5

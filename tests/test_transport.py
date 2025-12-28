
import pytest
import uuid
from unittest.mock import MagicMock, patch
from figchain.transport import Transport
from figchain.models import InitialFetchRequest, InitialFetchResponse, UpdateFetchRequest, UpdateFetchResponse
from figchain.auth import SharedSecretTokenProvider

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

    resp_obj = InitialFetchResponse(figFamilies=[], cursor="cursor", environmentId=uuid.uuid4())
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

    resp_obj = UpdateFetchResponse(figFamilies=[], cursor="new-cursor")
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

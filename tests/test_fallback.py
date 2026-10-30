import pytest

from figchain.bootstrap.fallback import FallbackStrategy
from figchain.bootstrap.strategy import BootstrapResult

BACKUP = BootstrapResult(fig_families=[], cursors={"ns": "backup"})


class Static:
    def bootstrap(self, namespaces):
        return BACKUP


class Failing:
    def __init__(self, error):
        self.error = error

    def bootstrap(self, namespaces):
        raise self.error


def test_uses_backup_when_server_unreachable():
    strategy = FallbackStrategy(Failing(ConnectionError("refused")), Static())
    assert strategy.bootstrap(["ns"]) is BACKUP


def test_fails_on_rejected_credentials():
    strategy = FallbackStrategy(Failing(PermissionError("Authentication failed")), Static())
    with pytest.raises(PermissionError):
        strategy.bootstrap(["ns"])

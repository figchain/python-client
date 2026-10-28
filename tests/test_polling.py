"""The single poll loop: long polling vs polling, and fallback."""

import threading
from types import SimpleNamespace

import requests

from figchain.client import LONG_POLL_WAIT_SECONDS, FigChainClient
from figchain.config import Config


class FakeTransport:
    """Records each request's wait and answers from a script of outcomes
    (None = empty success, an exception instance = raise it)."""

    def __init__(self, script, shutdown: threading.Event):
        self.script = list(script)
        self.waits = []
        self.shutdown = shutdown

    def fetch_updates(self, ns, cursor, wait_seconds=0):
        self.waits.append(wait_seconds)
        outcome = self.script.pop(0) if self.script else None
        if not self.script:
            self.shutdown.set()
        if isinstance(outcome, Exception):
            raise outcome
        return SimpleNamespace(figFamilies=[], cursor=None, schemas=None)


def run_poller(use_long_polling, script):
    c = FigChainClient.__new__(FigChainClient)
    c.config = Config(use_long_polling=use_long_polling, poll_interval=0.001)
    c.namespace_cursors = {}
    c._lock = threading.Lock()
    c._shutdown_event = threading.Event()
    c.transport = FakeTransport(script, c._shutdown_event)
    t = threading.Thread(target=c._poll_namespace, args=("ns",))
    t.start()
    t.join(timeout=5)
    assert not t.is_alive(), "poller did not stop"
    return c.transport.waits


def test_long_polling_asks_server_to_wait():
    assert run_poller(True, [None, None, None]) == [LONG_POLL_WAIT_SECONDS] * 3


def test_polling_does_not_wait():
    assert run_poller(False, [None, None, None]) == [0, 0, 0]


def test_falls_back_after_repeated_transit_failures():
    timeout = requests.Timeout("read timed out")
    waits = run_poller(True, [timeout, timeout, timeout, None, None])
    assert waits == [LONG_POLL_WAIT_SECONDS] * 3 + [0, 0]


def test_server_errors_do_not_trigger_fallback():
    err = requests.HTTPError("500 Server Error")
    waits = run_poller(True, [err, err, err, err, None])
    assert waits == [LONG_POLL_WAIT_SECONDS] * 5


def test_polling_interval_env_is_milliseconds(monkeypatch):
    monkeypatch.setenv("FIGCHAIN_POLLING_INTERVAL_MS", "15000")
    monkeypatch.setenv("FIGCHAIN_USE_LONG_POLLING", "false")
    cfg = Config.load()
    assert cfg.poll_interval == 15
    assert cfg.use_long_polling is False


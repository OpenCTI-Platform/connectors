import os
import sys

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture(name="timers")
def fixture_timers(monkeypatch):
    """Record the deferred syncs of the connector instead of starting timer threads;
    a test runs one with `timer.function()`."""
    started = []

    class FakeTimer:
        def __init__(self, interval, function):
            self.interval = interval
            self.function = function
            self.daemon = False

        def start(self):
            started.append(self)

    monkeypatch.setattr("cloudflare_rules_list.connector.threading.Timer", FakeTimer)
    return started

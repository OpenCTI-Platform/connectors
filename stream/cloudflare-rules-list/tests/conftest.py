import os
import sys
import threading

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture(name="timers", autouse=True)
def fixture_timers(monkeypatch):
    """Record the deferred syncs of the connector instead of starting timer threads,
    in every test (a failed upload schedules one); a test runs one with
    `timer.function()`. The other timers (deployment reporter) stay real."""
    started = []
    real_timer = threading.Timer

    class FakeTimer:
        def __init__(self, interval, function):
            self.interval = interval
            self.function = function
            self.daemon = False

        def start(self):
            started.append(self)

    def timer(interval, function, *args, **kwargs):
        if getattr(function, "__name__", None) != "_run_deferred_sync":
            return real_timer(interval, function, *args, **kwargs)
        return FakeTimer(interval, function)

    monkeypatch.setattr("cloudflare_rules_list.connector.threading.Timer", timer)
    return started

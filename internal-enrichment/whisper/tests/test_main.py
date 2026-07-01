"""Tests for the connector entrypoint's OpenCTI startup retry (main.py).

The connector boots before OpenCTI's GraphQL API is ready on a fresh stack;
``_build_helper`` must retry the (health-checking) helper construction quietly
instead of crash-looping with a traceback.
"""

import logging
from unittest.mock import MagicMock

import main as main_mod
import pytest


def test_build_helper_retries_until_opencti_reachable(monkeypatch):
    sentinel = object()
    calls = {"n": 0}

    def fake_helper(_config, playbook_compatible):
        calls["n"] += 1
        if calls["n"] < 3:
            raise ValueError("OpenCTI API is not reachable. Waiting for OpenCTI...")
        return sentinel

    sleeps: list[int] = []
    monkeypatch.setattr(main_mod, "OpenCTIConnectorHelper", fake_helper)
    monkeypatch.setattr(main_mod.time, "sleep", lambda d: sleeps.append(d))

    # pycti's "api" logger is muted during the wait and must be restored.
    logging.getLogger("api").setLevel(logging.INFO)

    result = main_mod._build_helper({}, max_retries=5, retry_delay=2)

    assert result is sentinel
    assert calls["n"] == 3
    assert sleeps == [2, 2]  # slept between the two failed attempts
    assert logging.getLogger("api").level == logging.INFO  # restored


def test_build_helper_reraises_config_errors_immediately(monkeypatch):
    # A missing token/url is not a transient "not reachable" condition —
    # retrying for minutes would only hide the misconfiguration.
    calls = {"n": 0}

    def fake_helper(_config, playbook_compatible):
        calls["n"] += 1
        raise ValueError("A TOKEN must be set")

    monkeypatch.setattr(main_mod, "OpenCTIConnectorHelper", fake_helper)
    monkeypatch.setattr(main_mod.time, "sleep", lambda d: None)

    with pytest.raises(ValueError, match="TOKEN"):
        main_mod._build_helper({}, max_retries=5, retry_delay=1)
    assert calls["n"] == 1  # no retries


def test_build_helper_gives_up_after_budget_exhausted(monkeypatch):
    helper = MagicMock(
        side_effect=ValueError("OpenCTI API is not reachable. Waiting...")
    )
    monkeypatch.setattr(main_mod, "OpenCTIConnectorHelper", helper)
    monkeypatch.setattr(main_mod.time, "sleep", lambda d: None)

    with pytest.raises(ValueError, match="not reachable"):
        main_mod._build_helper({}, max_retries=3, retry_delay=1)
    assert helper.call_count == 3

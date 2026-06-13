"""Tests for the abuse-ssl connector run() work lifecycle."""

import importlib.util
import os
from unittest.mock import MagicMock

import pytest

MODULE_NAME = "abuse_ssl"
MODULE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "src", "abuse_ssl.py")
)


def _load_module():
    """Load src/abuse_ssl.py by absolute path with a null spec/loader guard."""
    spec = importlib.util.spec_from_file_location(MODULE_NAME, MODULE_PATH)
    if spec is None or spec.loader is None:
        raise ImportError("Unable to load module from {0}".format(MODULE_PATH))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


abuse_ssl = _load_module()


class _StopLoop(Exception):
    """Sentinel raised from time.sleep to break the infinite run() loop."""


def _build_connector():
    """Build a connector instance without invoking the real __init__."""
    connector = abuse_ssl.AbuseSSLConnector.__new__(abuse_ssl.AbuseSSLConnector)
    connector.helper = MagicMock()
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.helper.connect_id = "connector-id"
    connector.helper.get_state.return_value = None
    connector.interval = 1
    connector.author = MagicMock()
    connector.api_url = "https://example.invalid/list.txt"
    return connector


def _raise_stop_loop(*_args, **_kwargs):
    raise _StopLoop()


def test_run_success(monkeypatch):
    """A successful iteration completes the work with in_error=False."""
    connector = _build_connector()
    # Exercise the "connector has run before" state branch.
    connector.helper.get_state.return_value = {"last_run": 1700000000.0}

    connector.get_ips = MagicMock(return_value=["1.2.3.4"])
    connector.create_observables = MagicMock(return_value=["observable"])
    connector.create_indicators = MagicMock(return_value=["indicator"])
    connector.create_relationships = MagicMock(return_value=["relationship"])
    connector.create_bundle = MagicMock(return_value="bundle")
    connector.send_bundle = MagicMock()

    monkeypatch.setattr(abuse_ssl.time, "sleep", _raise_stop_loop)

    with pytest.raises(_StopLoop):
        connector.run()

    _args, kwargs = connector.helper.api.work.initiate_work.call_args
    assert kwargs["is_multipart"] is True

    connector.send_bundle.assert_called_once_with("bundle", "work-1")
    connector.helper.set_state.assert_called_once()

    connector.helper.api.work.to_processed.assert_called_once()
    to_processed_args, to_processed_kwargs = (
        connector.helper.api.work.to_processed.call_args
    )
    assert to_processed_args[0] == "work-1"
    assert to_processed_kwargs["in_error"] is False


def test_run_error(monkeypatch):
    """A failing iteration completes the work with in_error=True."""
    connector = _build_connector()

    connector.get_ips = MagicMock(side_effect=Exception("boom"))

    monkeypatch.setattr(abuse_ssl.time, "sleep", _raise_stop_loop)

    with pytest.raises(_StopLoop):
        connector.run()

    connector.helper.api.work.to_processed.assert_called_once()
    to_processed_args, to_processed_kwargs = (
        connector.helper.api.work.to_processed.call_args
    )
    assert to_processed_args[0] == "work-1"
    assert to_processed_kwargs["in_error"] is True


def test_run_interrupt(monkeypatch):
    """A KeyboardInterrupt/SystemExit still completes the work then exits."""
    connector = _build_connector()

    connector.get_ips = MagicMock(side_effect=KeyboardInterrupt())

    # exit(0) raises SystemExit before time.sleep, but guard the loop anyway.
    monkeypatch.setattr(abuse_ssl.time, "sleep", _raise_stop_loop)

    with pytest.raises(SystemExit):
        connector.run()

    connector.helper.api.work.to_processed.assert_called_once()
    to_processed_args, to_processed_kwargs = (
        connector.helper.api.work.to_processed.call_args
    )
    assert to_processed_args[0] == "work-1"
    assert to_processed_kwargs["in_error"] is True

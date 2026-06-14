import importlib.util
import os
from unittest.mock import MagicMock

import pytest

# The connector module lives at src/lastinfosec.py and is not packaged, so it is
# loaded directly from its absolute path with a guard against a null spec/loader.
_SRC = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "src", "lastinfosec.py")
)
_spec = importlib.util.spec_from_file_location("lastinfosec", _SRC)
if _spec is None or _spec.loader is None:
    raise ImportError("Unable to load lastinfosec module from {0}".format(_SRC))
module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(module)
LastInfoSec = module.LastInfoSec


def _make_connector():
    """Build the connector without running __init__ (which needs a real API)."""
    connector = LastInfoSec.__new__(LastInfoSec)
    connector.helper = MagicMock()
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.proxy_http = None
    connector.proxy_https = None
    return connector


def _make_response(status_code, payload):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    return response


def _patch_requests(monkeypatch, response):
    fake_requests = MagicMock()
    fake_requests.get.return_value = response
    monkeypatch.setattr(module, "requests", fake_requests)
    return fake_requests


def test_fetch_data_success_initiates_and_closes_work(monkeypatch):
    connector = _make_connector()
    connector.push_data = MagicMock()
    fake_requests = _patch_requests(
        monkeypatch, _make_response(200, [{"type": "bundle"}])
    )

    result = connector.fetch_data("https://example.test/feed", 600)

    fake_requests.get.assert_called_once()
    connector.helper.api.work.initiate_work.assert_called_once()
    _, init_kwargs = connector.helper.api.work.initiate_work.call_args
    assert init_kwargs.get("is_multipart") is True

    connector.push_data.assert_called_once()

    connector.helper.api.work.to_processed.assert_called_once()
    _, processed_kwargs = connector.helper.api.work.to_processed.call_args
    assert processed_kwargs.get("in_error") is False

    assert isinstance(result, (int, float))


def test_fetch_data_reraises_and_closes_work_on_error(monkeypatch):
    connector = _make_connector()
    connector.push_data = MagicMock(side_effect=Exception("boom"))
    _patch_requests(monkeypatch, _make_response(200, [{"type": "bundle"}]))

    with pytest.raises(Exception, match="boom"):
        connector.fetch_data("https://example.test/feed", 600)

    connector.helper.api.work.initiate_work.assert_called_once()

    connector.helper.api.work.to_processed.assert_called_once()
    processed_args, processed_kwargs = connector.helper.api.work.to_processed.call_args
    assert processed_kwargs.get("in_error") is True
    # The failure message must carry the exception instead of a misleading
    # "Done in ... seconds" success message.
    assert "boom" in processed_args[1]


def test_fetch_data_slow_run_clamps_sleep_to_zero(monkeypatch):
    connector = _make_connector()
    connector.push_data = MagicMock()
    _patch_requests(monkeypatch, _make_response(200, [{"type": "bundle"}]))

    # run_interval=0 forces run_interval - process_time_seconds negative; the
    # clamp must keep the returned sleep duration at 0 (never negative).
    result = connector.fetch_data("https://example.test/feed", 0)

    assert result == 0


def test_fetch_data_interrupt_closes_work_in_error(monkeypatch):
    connector = _make_connector()
    connector.push_data = MagicMock(side_effect=KeyboardInterrupt())
    _patch_requests(monkeypatch, _make_response(200, [{"type": "bundle"}]))

    with pytest.raises(KeyboardInterrupt):
        connector.fetch_data("https://example.test/feed", 600)

    connector.helper.api.work.to_processed.assert_called_once()
    _, processed_kwargs = connector.helper.api.work.to_processed.call_args
    # An interrupt must close the work as in_error rather than as a success.
    assert processed_kwargs.get("in_error") is True


def test_fetch_data_empty_payload_skips_work(monkeypatch):
    connector = _make_connector()
    connector.push_data = MagicMock()
    _patch_requests(monkeypatch, _make_response(200, []))

    result = connector.fetch_data("https://example.test/feed", 600)

    connector.helper.api.work.initiate_work.assert_not_called()
    connector.helper.api.work.to_processed.assert_not_called()
    connector.push_data.assert_not_called()

    assert isinstance(result, (int, float))


def test_fetch_data_uses_configured_proxies(monkeypatch):
    connector = _make_connector()
    connector.proxy_http = "http://proxy.test:3128"
    connector.proxy_https = "https://proxy.test:3128"
    connector.push_data = MagicMock()
    fake_requests = _patch_requests(
        monkeypatch, _make_response(200, [{"type": "bundle"}])
    )

    connector.fetch_data("https://example.test/feed", 600)

    _, get_kwargs = fake_requests.get.call_args
    assert get_kwargs.get("proxies") == {
        "http": "http://proxy.test:3128",
        "https": "https://proxy.test:3128",
    }


def test_fetch_data_non_200_skips_work(monkeypatch):
    connector = _make_connector()
    connector.push_data = MagicMock()
    _patch_requests(monkeypatch, _make_response(500, None))
    monkeypatch.setattr(module.time, "sleep", MagicMock())

    result = connector.fetch_data("https://example.test/feed", 600)

    connector.helper.api.work.initiate_work.assert_not_called()
    connector.helper.api.work.to_processed.assert_not_called()
    connector.helper.set_state.assert_called_once()
    assert result == 0

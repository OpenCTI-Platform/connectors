from unittest.mock import MagicMock

import connector.connector as connector_module
import pytest
from connector import AnyrunFeed


def _feed(monkeypatch, check_side_effect=None):
    feeds_connector = MagicMock()
    feeds_connector.check_authorization.side_effect = check_side_effect
    factory = MagicMock()
    factory.return_value.__enter__.return_value = feeds_connector
    monkeypatch.setattr(connector_module, "FeedsConnector", factory)

    config = MagicMock()
    config.anyrun.api_key.get_secret_value.return_value = "api-key"
    helper = MagicMock()
    helper.get_state.return_value = {}
    feed = AnyrunFeed(config=config, helper=helper)
    feed._run_once = MagicMock()
    return feed


@pytest.mark.parametrize(
    "error",
    [
        # What anyrun-sdk raises when the endpoint answers a non-JSON body (#7306)
        TypeError(
            "'>=' not supported between instances of 'JSONDecodeError' and 'int'"
        ),
        RuntimeError("Connection error"),
    ],
)
def test_failed_authorization_is_logged_and_skips_the_run(monkeypatch, error):
    feed = _feed(monkeypatch, check_side_effect=error)

    feed.process_message()  # must not raise to the scheduler

    feed._run_once.assert_not_called()
    feed.helper.connector_logger.error.assert_called_once()
    message, context = feed.helper.connector_logger.error.call_args.args
    assert "authorization check failed" in message
    assert type(error).__name__ in context["error"]


def test_successful_authorization_runs_once(monkeypatch):
    feed = _feed(monkeypatch)

    feed.process_message()

    feed._run_once.assert_called_once()
    assert feed._run_once.call_args.kwargs == {"is_delta": False}
    feed.helper.connector_logger.error.assert_not_called()

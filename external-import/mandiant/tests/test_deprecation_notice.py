from unittest.mock import MagicMock, patch

import pytest
from connector.base import Mandiant
from deprecation_notice import (
    DEPRECATION_MESSAGE,
    REPLACEMENT,
    SUPPORT_END_DATE,
    log_deprecation,
    warn_deprecated,
)


def test_warn_deprecated_should_emit_future_warning_when_called():
    """`FutureWarning` is shown by default, unlike `DeprecationWarning`."""
    # Given the connector is deprecated
    # When the startup warning is emitted
    # Then a FutureWarning carries the deprecation message
    with pytest.warns(FutureWarning, match="DEPRECATED"):
        warn_deprecated()


def test_log_deprecation_should_log_a_single_warning_when_called():
    # Given a connector logger
    logger = MagicMock()

    # When the deprecation is logged
    log_deprecation(logger)

    # Then exactly one WARNING is emitted, tagged as deprecated
    logger.warning.assert_called_once()
    message = logger.warning.call_args.args[0]
    assert "[DEPRECATED]" in message


def test_log_deprecation_should_log_support_end_and_replacement_when_called():
    # Given a connector logger
    logger = MagicMock()

    # When the deprecation is logged
    log_deprecation(logger)

    # Then the context dict carries the end-of-support date and where to migrate
    context = logger.warning.call_args.args[1]
    assert context["support_end"] == SUPPORT_END_DATE
    assert context["replacement"] == REPLACEMENT


def test_deprecation_message_should_mention_date_and_replacement():
    # Given the shared deprecation message
    # When it is read
    # Then it tells users when and where to migrate
    assert SUPPORT_END_DATE in DEPRECATION_MESSAGE
    assert REPLACEMENT in DEPRECATION_MESSAGE


def test_run_should_log_deprecation_when_connector_starts():
    # Given a connector with a mocked helper
    connector = object.__new__(Mandiant)
    connector.helper = MagicMock()
    connector.duration_period = MagicMock()

    # When the connector starts
    connector.run()

    # Then the deprecation is logged before the scheduling starts
    connector.helper.connector_logger.warning.assert_called_once()
    assert "[DEPRECATED]" in connector.helper.connector_logger.warning.call_args.args[0]
    connector.helper.schedule_process.assert_called_once()


def test_process_message_should_log_deprecation_when_a_run_starts():
    # Given a connector with a mocked helper and nothing to collect
    connector = object.__new__(Mandiant)
    connector.helper = MagicMock()
    connector.mandiant_collections = []

    # When a run starts
    with patch.object(Mandiant, "_init_state"):
        connector.process_message()

    # Then the deprecation is logged at WARNING level
    connector.helper.connector_logger.warning.assert_called_once()
    assert "[DEPRECATED]" in connector.helper.connector_logger.warning.call_args.args[0]

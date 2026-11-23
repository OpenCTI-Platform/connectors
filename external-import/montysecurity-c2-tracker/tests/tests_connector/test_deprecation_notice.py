import re
from datetime import date
from unittest.mock import MagicMock

import pytest
from connector import MontysecurityC2TrackerConnector
from deprecation_notice import (
    DEPRECATION_DATE,
    DEPRECATION_MESSAGE,
    REASON,
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


def test_log_deprecation_should_log_the_reason_when_called():
    # Given a connector logger
    logger = MagicMock()

    # When the deprecation is logged
    log_deprecation(logger)

    # Then the context dict tells users why the connector no longer works
    context = logger.warning.call_args.args[1]
    assert context["reason"] == REASON


def test_deprecation_message_should_state_that_there_is_no_replacement():
    # Given the shared deprecation message
    # When it is read
    # Then users are told explicitly that nothing replaces the connector
    assert "No replacement" in DEPRECATION_MESSAGE


def test_connector_should_log_deprecation_when_instantiated(
    mock_connector_settings, mock_connector_helper
):
    # Given a connector helper
    # When the connector starts
    MontysecurityC2TrackerConnector(
        config=mock_connector_settings, helper=mock_connector_helper
    )

    # Then the deprecation is logged at WARNING level
    warning = mock_connector_helper.connector_logger.warning
    assert any("[DEPRECATED]" in call.args[0] for call in warning.call_args_list)


def test_runtime_notice_should_not_contain_a_placeholder_when_logged():
    # Given a connector logger
    logger = MagicMock()

    # When the deprecation is warned and logged
    log_deprecation(logger)

    # Then no `[PLACEHOLDER]` token reaches users through the runtime output
    placeholder = re.compile(r"\[[A-Z_0-9]+\]")
    meta = logger.warning.call_args.args[1]
    assert not placeholder.search(DEPRECATION_MESSAGE.replace("[DEPRECATED]", ""))
    assert not placeholder.search(DEPRECATION_DATE)
    assert not any(placeholder.search(str(value)) for value in meta.values())


def test_deprecation_date_should_be_an_iso_8601_date():
    # Given the shared deprecation date
    # When it is parsed as ISO 8601
    # Then it is valid, and cannot be read as a US or European format
    assert date.fromisoformat(DEPRECATION_DATE).isoformat() == DEPRECATION_DATE

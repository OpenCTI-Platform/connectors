from unittest.mock import MagicMock

import pytest
from deprecation_notice import (
    DEPRECATION_MESSAGE,
    REPLACEMENT,
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


def test_log_deprecation_should_log_replacement_when_called():
    # Given a connector logger
    logger = MagicMock()

    # When the deprecation is logged
    log_deprecation(logger)

    # Then the context dict tells users where to migrate
    context = logger.warning.call_args.args[1]
    assert context["replacement"] == REPLACEMENT


def test_deprecation_message_should_mention_the_replacement():
    # Given the shared deprecation message
    # When it is read
    # Then it tells users where to migrate
    assert REPLACEMENT in DEPRECATION_MESSAGE

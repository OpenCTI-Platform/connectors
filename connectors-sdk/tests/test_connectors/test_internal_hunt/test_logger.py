"""Tests of the logger of the hunt connectors."""

from unittest.mock import MagicMock

import pytest
from connectors_sdk.connectors.internal_hunt._logger import ConnectorLogger


@pytest.mark.parametrize("level", ["info", "debug", "warning", "error"])
def test_connector_logger_should_delegate_to_the_helper_logger(level):
    # Given a logger built on a connector helper
    helper = MagicMock()
    logger = ConnectorLogger(helper)

    # When a message is logged with its meta
    getattr(logger, level)("Hello", {"key": "value"})

    # Then the helper's logger receives the message and the meta
    getattr(helper.connector_logger, level).assert_called_once_with(
        "Hello", {"key": "value"}
    )


def test_connector_logger_should_pass_none_without_meta():
    # Given a logger built on a connector helper
    helper = MagicMock()
    logger = ConnectorLogger(helper)

    # When a message is logged without meta
    logger.info("Hello")

    # Then the meta is None
    helper.connector_logger.info.assert_called_once_with("Hello", None)

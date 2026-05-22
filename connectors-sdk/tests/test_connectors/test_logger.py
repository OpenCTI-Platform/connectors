# pragma: no cover
# type: ignore
from unittest.mock import MagicMock

from connectors_sdk.connectors.external_import.logger import ConnectorLogger


class TestConnectorLogger:
    def test_init_stores_connector_logger(self, mock_helper: MagicMock):
        logger = ConnectorLogger(mock_helper)
        assert logger._logger is mock_helper.connector_logger

    def test_info(self, mock_logger: ConnectorLogger, mock_helper: MagicMock):
        mock_logger.info("hello", {"key": "val"})
        mock_helper.connector_logger.info.assert_called_once_with(
            "hello", {"key": "val"}
        )

    def test_info_no_meta(self, mock_logger: ConnectorLogger, mock_helper: MagicMock):
        mock_logger.info("hello")
        mock_helper.connector_logger.info.assert_called_once_with("hello", None)

    def test_debug(self, mock_logger: ConnectorLogger, mock_helper: MagicMock):
        mock_logger.debug("dbg", {"k": "v"})
        mock_helper.connector_logger.debug.assert_called_once_with("dbg", {"k": "v"})

    def test_warning(self, mock_logger: ConnectorLogger, mock_helper: MagicMock):
        mock_logger.warning("warn")
        mock_helper.connector_logger.warning.assert_called_once_with("warn", None)

    def test_error(self, mock_logger: ConnectorLogger, mock_helper: MagicMock):
        mock_logger.error("err", {"detail": "x"})
        mock_helper.connector_logger.error.assert_called_once_with(
            "err", {"detail": "x"}
        )

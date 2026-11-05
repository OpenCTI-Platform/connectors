from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from types import SimpleNamespace
from unittest.mock import MagicMock

from connector.logging_config import (
    FileLoggingConfig,
    get_stdlib_logger,
    setup_file_logging,
)

# --- FileLoggingConfig -------------------------------------------------------


class TestFileLoggingConfig:
    def test_defaults(self):
        cfg = FileLoggingConfig()
        assert cfg.enabled is False
        assert cfg.directory == "/opt/connector/logs"
        assert cfg.filename == "connector.log"
        assert cfg.max_bytes == 10 * 1024 * 1024
        assert cfg.backup_count == 5

    def test_file_path_property(self):
        cfg = FileLoggingConfig(directory="/var/log", filename="x.log")
        assert cfg.file_path == "/var/log/x.log"

    def test_frozen(self):
        # ``@dataclass(frozen=True)`` — assignment after construction
        # must raise.
        cfg = FileLoggingConfig()
        try:
            cfg.enabled = True
        except Exception as e:
            assert (
                "frozen" in str(e).lower() or "FrozenInstanceError" in type(e).__name__
            )
        else:  # pragma: no cover
            raise AssertionError("FileLoggingConfig should be frozen")

    def test_format_strings_present(self):
        cfg = FileLoggingConfig()
        assert "%(asctime)s" in cfg.format
        assert "%(levelname)s" in cfg.format
        assert "%(message)s" in cfg.format


# --- get_stdlib_logger -------------------------------------------------------


class TestGetStdlibLogger:
    def test_extracts_underlying_logger_from_helper(self):
        underlying = logging.getLogger("test-extracts-underlying")
        helper = SimpleNamespace(connector_logger=SimpleNamespace(logger=underlying))
        out = get_stdlib_logger(helper)
        assert out is underlying

    def test_fallback_when_helper_is_none(self):
        out = get_stdlib_logger(None)
        assert isinstance(out, logging.Logger)
        assert out.name == "Group-IB Connector"

    def test_fallback_when_helper_has_no_connector_logger(self):
        helper = SimpleNamespace()  # no connector_logger attribute
        out = get_stdlib_logger(helper)
        assert isinstance(out, logging.Logger)
        assert out.name == "Group-IB Connector"

    def test_fallback_when_wrapper_lacks_logger_attr(self):
        helper = SimpleNamespace(connector_logger=SimpleNamespace())
        out = get_stdlib_logger(helper)
        assert isinstance(out, logging.Logger)

    def test_fallback_when_logger_attr_is_not_a_logger(self):
        helper = SimpleNamespace(
            connector_logger=SimpleNamespace(logger="not-a-logger")
        )
        out = get_stdlib_logger(helper)
        assert isinstance(out, logging.Logger)
        assert out.name == "Group-IB Connector"

    def test_custom_fallback_name(self):
        out = get_stdlib_logger(None, fallback_name="custom-name")
        assert out.name == "custom-name"


# --- setup_file_logging ------------------------------------------------------


def _fresh_helper(logger_name: str) -> SimpleNamespace:
    """Build a helper stand-in whose ``connector_logger`` wraps a clean
    stdlib logger (no inherited handlers from previous tests)."""
    lg = logging.getLogger(logger_name)
    # Clear handlers from any prior test reuse, since stdlib loggers are
    # module-level singletons.
    lg.handlers.clear()
    return SimpleNamespace(
        connector_logger=SimpleNamespace(logger=lg, info=MagicMock())
    )


class TestSetupFileLogging:
    def test_disabled_is_noop(self, tmp_path):
        helper = _fresh_helper("setup-disabled-noop")
        cfg = FileLoggingConfig(enabled=False, directory=str(tmp_path))
        setup_file_logging(helper, cfg)
        # No handler attached, no file created, no info log emitted.
        assert helper.connector_logger.info.call_count == 0
        assert not any(
            isinstance(h, RotatingFileHandler)
            for h in helper.connector_logger.logger.handlers
        )

    def test_enabled_attaches_rotating_file_handler(self, tmp_path):
        helper = _fresh_helper("setup-enabled-attaches")
        cfg = FileLoggingConfig(
            enabled=True,
            directory=str(tmp_path),
            filename="my.log",
            max_bytes=1024,
            backup_count=2,
        )
        setup_file_logging(helper, cfg)
        handlers = [
            h
            for h in helper.connector_logger.logger.handlers
            if isinstance(h, RotatingFileHandler)
        ]
        assert len(handlers) == 1
        h = handlers[0]
        assert h.baseFilename == os.path.join(str(tmp_path), "my.log")
        assert h.maxBytes == 1024
        assert h.backupCount == 2

    def test_enabled_creates_directory_if_missing(self, tmp_path):
        helper = _fresh_helper("setup-creates-dir")
        target = tmp_path / "nested" / "logs"
        cfg = FileLoggingConfig(enabled=True, directory=str(target))
        assert not target.exists()
        setup_file_logging(helper, cfg)
        assert target.is_dir()

    def test_enabled_logs_info_message(self, tmp_path):
        helper = _fresh_helper("setup-logs-info")
        cfg = FileLoggingConfig(enabled=True, directory=str(tmp_path))
        setup_file_logging(helper, cfg)
        helper.connector_logger.info.assert_called_once()
        call_args = str(helper.connector_logger.info.call_args)
        assert "File logging enabled" in call_args
        assert str(tmp_path) in call_args

    def test_idempotent_does_not_double_attach(self, tmp_path):
        helper = _fresh_helper("setup-idempotent")
        cfg = FileLoggingConfig(enabled=True, directory=str(tmp_path))
        setup_file_logging(helper, cfg)
        setup_file_logging(helper, cfg)  # second call must be a no-op.
        file_handlers = [
            h
            for h in helper.connector_logger.logger.handlers
            if isinstance(h, RotatingFileHandler)
        ]
        assert len(file_handlers) == 1
        # Second call returns early — no second info-line emitted.
        assert helper.connector_logger.info.call_count == 1

    def test_handler_writes_records_to_file(self, tmp_path):
        helper = _fresh_helper("setup-writes-records")
        cfg = FileLoggingConfig(
            enabled=True, directory=str(tmp_path), filename="emit.log"
        )
        setup_file_logging(helper, cfg)
        lg = helper.connector_logger.logger
        lg.setLevel(logging.DEBUG)
        for h in lg.handlers:
            h.setLevel(logging.DEBUG)
        lg.error("OBSERVED-ERROR-LINE")
        # Flush + close to make file contents readable.
        for h in lg.handlers:
            h.flush()
        path = tmp_path / "emit.log"
        assert path.exists()
        body = path.read_text(encoding="utf-8")
        assert "OBSERVED-ERROR-LINE" in body
        assert "ERROR" in body

    def test_handler_uses_configured_formatter(self, tmp_path):
        helper = _fresh_helper("setup-uses-fmt")
        cfg = FileLoggingConfig(
            enabled=True,
            directory=str(tmp_path),
            format="[%(levelname)s] %(message)s",
            date_format="%Y",
        )
        setup_file_logging(helper, cfg)
        handlers = [
            h
            for h in helper.connector_logger.logger.handlers
            if isinstance(h, RotatingFileHandler)
        ]
        assert handlers
        formatter = handlers[0].formatter
        assert formatter is not None
        assert formatter._fmt == "[%(levelname)s] %(message)s"

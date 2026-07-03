"""Tests for BaseLogger."""

import inspect
import logging
import logging.handlers
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from connectors_sdk.logging._base_logger import BaseLogger, _prepare_meta


class DummyLogger(BaseLogger):
    """Dummy concrete subclass of `BaseLogger` for testing purposes."""

    def __init__(self, name: str) -> None:
        super().__init__(name=name)


@pytest.fixture
def dummy_logger() -> BaseLogger:
    """Provides a `DummyLogger` instance for testing."""

    return DummyLogger(name="dummy_logger")


@pytest.fixture
def logger_factory(monkeypatch):
    """Return a factory that creates `BaseLogger` subclasses with a given log level."""

    def _make(level: str) -> BaseLogger:
        monkeypatch.setenv("CONNECTOR_LOG_LEVEL", level)

        class DynamicLogger(BaseLogger):
            # Define new subclass to trigger log level loading at class initialization
            def __init__(self, name: str) -> None:
                super().__init__(name=name)

        return DynamicLogger(name=f"{level}_logger")

    return _make


@pytest.fixture(autouse=True)
def cleanup_loggers():
    """Remove any test loggers created during a test."""
    yield
    for name in list(logging.Logger.manager.loggerDict):
        if name in (
            "dummy_logger",
            "debug_logger",
            "info_logger",
            "warning_logger",
            "error_logger",
        ):
            logger = logging.getLogger(name)
            logger.handlers.clear()
            del logging.Logger.manager.loggerDict[name]


class TestPrepareMeta:
    def test_none_returns_none(self) -> None:
        """Should return None when meta is None."""
        # Given/When: meta is None
        result = _prepare_meta(None)

        # Then: returns None
        assert result is None

    def test_dict_wrapped_in_attributes(self) -> None:
        """Should wrap dict in 'attributes' key."""
        # Given: meta is a dict
        meta = {"key": "value"}

        # When: _prepare_meta is called
        result = _prepare_meta(meta)

        # Then: returns dict wrapped in 'attributes'
        assert result == {"attributes": {"key": "value"}}

    def test_empty_dict_wrapped(self) -> None:
        """Should wrap empty dict in 'attributes' key."""
        # Given: meta is an empty dict
        meta = {}

        # When: _prepare_meta is called
        result = _prepare_meta(meta)

        # Then: returns empty dict wrapped in 'attributes'
        assert result == {"attributes": {}}


class TestBaseLoggerAbstract:
    def test_base_logger_is_abstract(self) -> None:
        """Should be an abstract class."""
        # Then: BaseLogger is abstract
        assert inspect.isabstract(BaseLogger)

    def test_base_logger_cannot_be_instantited_directly(self) -> None:
        """Should not allow direct instantiation."""
        # When/Then: Instantiating raises TypeError
        with pytest.raises(TypeError):
            BaseLogger(name="base")  # type: ignore[abstract]

    def test_base_logger_has_default_log_level_class_var(self) -> None:
        """Should have default log level class var 'ERROR'."""
        # Then: _log_level is 'ERROR'
        assert BaseLogger._log_level == "ERROR"

    def test_base_logger_has__empty_handlers_class_var(self) -> None:
        """Should have empty handlers class var by default."""
        # Then: _handlers is []
        assert BaseLogger._handlers == []


class TestBaseLoggerConcreteClass:
    def test_subclass_has_log_level(self) -> None:
        """Should inherit log level from BaseLogger."""
        # Then: DummyLogger._log_level is 'ERROR'
        assert DummyLogger._log_level == "ERROR"

    def test_subclass_sets_log_level_from_env_var(self, logger_factory) -> None:
        """Should set log level from env var."""
        # Given: CONNECTOR_LOG_LEVEL=info
        logger = logger_factory("info")

        # Then: logger._log_level is 'INFO'
        assert logger._log_level == "INFO"

    def test_subclass_has_default_handlers(self) -> None:
        """Should have one default StreamHandler."""
        # Then: DummyLogger._handlers contains one StreamHandler
        assert len(DummyLogger._handlers) == 1
        assert isinstance(DummyLogger._handlers[0], logging.StreamHandler)


class TestBaseLoggerConcreteClassInit:
    def test_subclass_creates_stdlib_logger_with_given_name(
        self, dummy_logger: DummyLogger
    ) -> None:
        """Should create stdlib logger with the given name."""
        # Then: logger name matches
        assert dummy_logger._logger.name == "dummy_logger"

    def test_subclass_sets_stdlib_logger_level_correctly(
        self, dummy_logger: DummyLogger, logger_factory
    ) -> None:
        """Should set stdlib logger level according to log level."""
        # Given: dummy_logger and info_logger
        info_logger = logger_factory("info")

        # Then: levels match
        assert dummy_logger._log_level == "ERROR"
        assert dummy_logger._logger.level == logging.ERROR
        assert info_logger._log_level == "INFO"
        assert info_logger._logger.level == logging.INFO

    def test_subclass_disables_stdlib_logger_propagate(
        self, dummy_logger: DummyLogger
    ) -> None:
        """Should disable stdlib logger propagation."""
        # Then: propagate is False
        assert dummy_logger._logger.propagate is False

    def test_subclass_adds_default_stream_handler_to_stdlib_logger(
        self, dummy_logger: DummyLogger
    ) -> None:
        """Should add a default StreamHandler to stdlib logger."""
        # Then: at least one handler is a StreamHandler
        assert any(
            isinstance(h, logging.StreamHandler) for h in dummy_logger._logger.handlers
        )

    def test_subclass_adds_default_stream_handler_to_stdlib_logger_only_once(
        self,
    ) -> None:
        """Should not duplicate handlers for same logger name."""
        # Given: two DummyLogger instances with same name
        name = "dummy_logger_dedup"
        DummyLogger(name=name)
        DummyLogger(name=name)

        # When: get logger's handlers
        logger = logging.getLogger(name)
        default_handlers = [
            h for h in logger.handlers if h.get_name() == "default_stderr_handler"
        ]

        # Then: only one default_stderr_handler
        assert len(default_handlers) == 1

    def test_subclass_default_stream_handler_has_json_formatter(
        self, dummy_logger: DummyLogger
    ) -> None:
        """Should use CustomJsonFormatter for default handler."""
        from pycti.utils.opencti_logger import CustomJsonFormatter

        # When: get StreamHandler
        handler = next(
            h
            for h in dummy_logger._logger.handlers
            if isinstance(h, logging.StreamHandler)
        )

        # Then: formatter is CustomJsonFormatter
        assert isinstance(handler.formatter, CustomJsonFormatter)


class TestBaseLoggerClassMethods:
    def test_base_logger_get_connector_main_path_returns_main_file_path(
        self, mock_main_path
    ):
        """Should locate connector's main.py via _get_connector_main_path."""
        # When: _get_connector_main_path is called
        main_path = BaseLogger._get_connector_main_path()

        # Then: returns expected path
        assert main_path == Path("/app/src/main.py").resolve()

    def test_base_logger_should_raise_when_main_module_misses_file_attribute(
        self, mock_main_path
    ):
        """Should raise RuntimeError if __main__.__file__ is missing."""
        # Given: __main__.__file__ is missing
        sys.modules["__main__"].__file__ = None

        # When/Then: calling _get_connector_main_path raises
        with pytest.raises(RuntimeError):
            BaseLogger._get_connector_main_path()

    def test_base_logger_get_log_level_from_legacy_config_yml(
        self, mock_connector_log_level_in_legacy_config_yml
    ):
        """Should read log level from legacy config.yml."""
        # When: _get_log_level_from_config_yml is called
        log_level = BaseLogger._get_log_level_from_config_yml()

        # Then: returns DEBUG
        assert log_level == "DEBUG"

    def test_base_logger_get_log_level_from_config_yml(
        self, mock_connector_log_level_in_config_yml
    ):
        """Should read log level from new config.yml path."""
        # When: _get_log_level_from_config_yml is called
        log_level = BaseLogger._get_log_level_from_config_yml()

        # Then: returns DEBUG
        assert log_level == "DEBUG"

    def test_base_logger_get_log_level_from_dot_env(
        self, mock_connector_log_level_in_dot_env
    ):
        """Should read log level from .env file."""
        # When: _get_log_level_from_dot_env is called
        log_level = BaseLogger._get_log_level_from_dot_env()

        # Then: returns DEBUG
        assert log_level == "DEBUG"

    def test_base_logger_get_log_level_from_env_var(self, monkeypatch):
        """Should use CONNECTOR_LOG_LEVEL env var if set."""
        # Given: env var set
        monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "debug")

        # When: _get_connector_log_level is called
        log_level = BaseLogger._get_connector_log_level()

        # Then: returns DEBUG
        assert log_level == "DEBUG"

    def test_get_connector_log_level_falls_back_to_config_yml(self, monkeypatch):
        """Should fall back to config.yml if env var is not set."""
        # Given: config_yml returns DEBUG
        monkeypatch.setattr(
            BaseLogger, "_get_log_level_from_config_yml", staticmethod(lambda: "DEBUG")
        )

        # When: _get_connector_log_level is called
        log_level = BaseLogger._get_connector_log_level()

        # Then: returns DEBUG
        assert log_level == "DEBUG"

    def test_get_connector_log_level_falls_back_to_dot_env(self, monkeypatch):
        """Should fall back to .env if env var and config.yml are not set."""
        # Given: config_yml returns empty, dot_env returns DEBUG
        monkeypatch.setattr(
            BaseLogger, "_get_log_level_from_config_yml", staticmethod(lambda: "")
        )
        monkeypatch.setattr(
            BaseLogger, "_get_log_level_from_dot_env", staticmethod(lambda: "DEBUG")
        )

        # When: _get_connector_log_level is called
        log_level = BaseLogger._get_connector_log_level()

        # Then: returns DEBUG
        assert log_level == "DEBUG"


class TestGetChild:
    def test_subclass_get_child_returns_subclass_instance(
        self, dummy_logger: DummyLogger
    ) -> None:
        """Should return a child logger instance of the same class."""
        # Given: a dummy_logger
        # When: get_child is called
        child = dummy_logger.get_child("child")

        # Then: child is DummyLogger
        assert isinstance(child, DummyLogger)

    def test_subclass_logger_child_name_is_dotted(
        self, dummy_logger: DummyLogger
    ) -> None:
        """Should append child name to logger name with dot."""
        # Given: a dummy_logger
        # When: get_child is called
        child = dummy_logger.get_child("child")

        # Then: child logger name is dotted
        assert child._logger.name == "dummy_logger.child"


class TestBaseLoggerLogMethods:
    def _capture_records_for(
        self, logger: BaseLogger
    ) -> logging.handlers.MemoryHandler:
        """Attach a MemoryHandler to the logger for capturing log records."""
        mem = logging.handlers.MemoryHandler(
            capacity=100, flushLevel=logging.CRITICAL + 1
        )
        logger._logger.addHandler(mem)
        return mem

    @pytest.mark.parametrize("level", ["debug", "info", "warning", "error"])
    def test_log_methods_emit_records(self, logger_factory, level: str) -> None:
        """Should emit a log record for each log method."""
        # Given: a logger at the right level
        logger = logger_factory(level)
        capture = self._capture_records_for(logger)

        # When: log method is called
        log_method = getattr(logger, level)
        log_method(f"{level} message")

        # Then: record is captured
        assert any(r.getMessage() == f"{level} message" for r in capture.buffer)

    def test_error_emits_record_for_exception(self, logger_factory) -> None:
        """Should emit a log record when error is called with an exception."""
        # Given: error-level logger
        logger = logger_factory("error")
        capture = self._capture_records_for(logger)

        # When: error is called with exception
        logger.error(ValueError("An error occurred"))

        # Then: record contains exception message
        assert any("An error occurred" in r.getMessage() for r in capture.buffer)

    def test_error_sets_exc_info(self, logger_factory) -> None:
        """Should set exc_info on error log records."""
        # Given: error-level logger
        logger = logger_factory("error")
        capture = self._capture_records_for(logger)

        # When: error is called
        logger.error("Message with exc_info")

        # Then: exc_info is set on the record
        record = next(
            r for r in capture.buffer if r.getMessage() == "Message with exc_info"
        )
        assert record.exc_info is not None

    @pytest.mark.parametrize(
        "meta,has_attributes", [({"key": "val"}, True), (None, False)]
    )
    def test_meta_is_mapped_to_attributes(
        self, logger_factory, meta: dict[str, str] | None, has_attributes: bool
    ) -> None:
        """Should map meta argument to log record attributes."""
        # Given: error-level logger
        logger = logger_factory("error")
        capture = self._capture_records_for(logger)

        # When: error is called with meta
        logger.error("Message with meta", meta)

        # Then: attributes are present or not as expected
        record = next(
            r for r in capture.buffer if r.getMessage() == "Message with meta"
        )
        if has_attributes:
            assert record.attributes == {"key": "val"}  # type: ignore[attr-defined]
        else:
            assert not hasattr(record, "attributes")

    @pytest.mark.parametrize("level", ["debug", "info", "warning", "error"])
    def test_methods_forward_expected_stdlib_arguments(
        self, logger_factory, level: str
    ) -> None:
        """Should forward correct arguments to stdlib logger methods."""
        # Given: a logger
        logger = logger_factory(level)

        # When: log method is called with meta
        with patch.object(logger._logger, level) as spy:
            log_method = getattr(logger, level)
            log_method(f"{level} message", meta={"key": "value"})

        # Then: correct arguments are forwarded
        if level == "error":
            spy.assert_called_once_with(
                f"{level} message",
                extra={"attributes": {"key": "value"}},
                exc_info=True,
            )
        else:
            spy.assert_called_once_with(
                f"{level} message", extra={"attributes": {"key": "value"}}
            )

"""Tests for BaseLogger."""

import logging
import logging.handlers
from typing import Generator

import pytest
from connectors_sdk.logging._base_logger import BaseLogger, prepare_meta


@pytest.fixture(autouse=True)
def cleanup_loggers():
    """Remove any test loggers created during a test."""
    yield
    for name in list(logging.Logger.manager.loggerDict):
        if name.startswith("test_base_logger"):
            lgr = logging.getLogger(name)
            lgr.handlers.clear()
            del logging.Logger.manager.loggerDict[name]


@pytest.fixture
def base_logger() -> BaseLogger:
    return BaseLogger(name="test_base_logger", level="debug")


class TestPrepareMeta:
    def test_none_returns_none(self) -> None:
        assert prepare_meta(None) is None

    def test_dict_wrapped_in_attributes(self) -> None:
        assert prepare_meta({"key": "value"}) == {"attributes": {"key": "value"}}

    def test_empty_dict_wrapped(self) -> None:
        assert prepare_meta({}) == {"attributes": {}}


class TestBaseLoggerInit:
    def test_creates_stdlib_logger_with_given_name(
        self, base_logger: BaseLogger
    ) -> None:
        assert base_logger._logger.name == "test_base_logger"

    def test_level_set_correctly(self) -> None:
        lgr = BaseLogger(name="test_base_logger_level", level="warning")
        assert lgr._logger.level == logging.WARNING

    def test_propagate_disabled(self, base_logger: BaseLogger) -> None:
        assert base_logger._logger.propagate is False

    def test_default_stream_handler_added(self, base_logger: BaseLogger) -> None:
        assert any(
            isinstance(h, logging.StreamHandler) for h in base_logger._logger.handlers
        )

    def test_default_handler_added_only_once(self) -> None:
        """Creating two BaseLoggers with the same name must not duplicate handlers."""
        name = "test_base_logger_dedup"
        BaseLogger(name=name, level="info")
        BaseLogger(name=name, level="info")
        lgr = logging.getLogger(name)
        named_handlers = [
            h for h in lgr.handlers if h.get_name() == f"{name}_default_handler"
        ]
        assert len(named_handlers) == 1

    def test_handler_has_json_formatter(self, base_logger: BaseLogger) -> None:
        from pycti.utils.opencti_logger import CustomJsonFormatter

        handler = next(
            h
            for h in base_logger._logger.handlers
            if isinstance(h, logging.StreamHandler)
        )
        assert isinstance(handler.formatter, CustomJsonFormatter)


class TestWrapExistingLogger:
    def test_wraps_given_logger(self) -> None:
        existing = logging.getLogger("test_base_logger_wrap")
        wrapper = BaseLogger.wrap_existing_logger(existing)
        assert wrapper._logger is existing

    def test_no_handlers_added_on_wrap(self) -> None:
        existing = logging.getLogger("test_base_logger_wrap_clean")
        existing.handlers.clear()
        BaseLogger.wrap_existing_logger(existing)
        assert existing.handlers == []


class TestGetChild:
    def test_returns_base_logger_instance(self, base_logger: BaseLogger) -> None:
        child = base_logger.get_child("child")
        assert isinstance(child, BaseLogger)

    def test_child_name_is_dotted(self, base_logger: BaseLogger) -> None:
        child = base_logger.get_child("child")
        assert child._logger.name == "test_base_logger.child"

    def test_child_propagate_enabled(self, base_logger: BaseLogger) -> None:
        child = base_logger.get_child("child")
        assert child._logger.propagate is True


class TestBaseLoggerMethods:
    @pytest.fixture(autouse=True)
    def capture(
        self, base_logger: BaseLogger
    ) -> Generator[logging.handlers.MemoryHandler, None, None]:

        mem = logging.handlers.MemoryHandler(
            capacity=100, flushLevel=logging.CRITICAL + 1
        )
        base_logger._logger.addHandler(mem)
        self.mem = mem
        yield mem
        base_logger._logger.removeHandler(mem)

    def _records(self) -> list[logging.LogRecord]:
        return self.mem.buffer

    def test_debug(self, base_logger: BaseLogger) -> None:
        base_logger.debug("debug msg")
        assert any(r.getMessage() == "debug msg" for r in self._records())

    def test_info(self, base_logger: BaseLogger) -> None:
        base_logger.info("info msg")
        assert any(r.getMessage() == "info msg" for r in self._records())

    def test_warning(self, base_logger: BaseLogger) -> None:
        base_logger.warning("warn msg")
        assert any(r.getMessage() == "warn msg" for r in self._records())

    def test_error_with_string(self, base_logger: BaseLogger) -> None:
        base_logger.error("error msg")
        assert any(r.getMessage() == "error msg" for r in self._records())

    def test_error_with_exception(self, base_logger: BaseLogger) -> None:
        base_logger.error(ValueError("boom"))
        assert any("boom" in r.getMessage() for r in self._records())

    def test_error_sets_exc_info(self, base_logger: BaseLogger) -> None:
        base_logger.error("with exc")
        record = next(r for r in self._records() if r.getMessage() == "with exc")
        # exc_info is set to True on the call — stdlib stores it as a tuple or (None,None,None)
        assert record.exc_info is not None

    def test_meta_wrapped_in_attributes(self, base_logger: BaseLogger) -> None:
        base_logger.info("with meta", {"key": "val"})
        record = next(r for r in self._records() if r.getMessage() == "with meta")
        assert record.attributes == {"key": "val"}  # type: ignore[attr-defined]

    def test_no_meta_produces_no_extra(self, base_logger: BaseLogger) -> None:
        base_logger.info("no meta")
        record = next(r for r in self._records() if r.getMessage() == "no meta")
        assert not hasattr(record, "attributes")

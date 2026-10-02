"""Fixtures to isolate the process-wide logging state in `connectors_sdk.logger` tests."""

import logging
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# The namespaces `connectors_sdk.logger` hands loggers out under. They are written here
# instead of being imported, so that the tests check the namespaces the public API
# promises, and not the ones the implementation happens to use.
SDK_NAMESPACES = ("connector", "connectors_sdk")


@pytest.fixture(autouse=True)
def isolated_logging():
    """Put the process-wide logging state back after each test.

    `connectors_sdk.logger` changes that state on purpose: the class of the loggers it
    hands out, and the handlers and levels of the namespace loggers.
    `logging.getLoggerClass()` is saved too. The SDK never changes it, but one test
    does, to reproduce a host application that sets its own logger class.
    """
    root_logger = logging.getLogger()
    manager = logging.Logger.manager

    saved_logger_class = logging.getLoggerClass()
    saved_handlers = list(root_logger.handlers)
    saved_level = root_logger.level
    saved_logger_dict = dict(manager.loggerDict)
    saved_logger_classes = {
        name: type(logger)
        for name, logger in manager.loggerDict.items()
        if isinstance(logger, logging.Logger)
    }
    saved_namespaces = {
        namespace: (logger.level, list(logger.handlers))
        for namespace in SDK_NAMESPACES
        if isinstance(logger := manager.loggerDict.get(namespace), logging.Logger)
    }

    # Other test modules instantiate `BaseConnectorSettings`, which sets a level for the
    # whole process. Reset the namespaces to `NOTSET` so each test starts as it would in
    # a fresh interpreter; the teardown below puts the original levels back.
    for namespace in SDK_NAMESPACES:
        logging.getLogger(namespace).setLevel(logging.NOTSET)

    yield

    logging.setLoggerClass(saved_logger_class)
    for name, logger_class in saved_logger_classes.items():
        logger = manager.loggerDict.get(name)
        if isinstance(logger, logging.Logger):
            logger.__class__ = logger_class

    for namespace, (level, handlers) in saved_namespaces.items():
        namespace_logger = manager.loggerDict[namespace]
        namespace_logger.setLevel(level)
        namespace_logger.handlers[:] = handlers

    manager.loggerDict.clear()
    manager.loggerDict.update(saved_logger_dict)
    root_logger.handlers[:] = saved_handlers
    root_logger.setLevel(saved_level)


def clear_root_handlers() -> logging.Logger:
    """Remove every handler from the root logger, making it look unconfigured.

    This has to be called from a test's body rather than from a fixture: pytest's logging
    plugin attaches its capture handler around the *call* phase, after fixtures have run,
    so anything a fixture removes is back by the time the test executes.

    Returns:
        logging.Logger: The root logger.
    """
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    return root_logger


@pytest.fixture
def mock_main_path(monkeypatch, tmp_path):
    """Pretend the connector was launched from `<tmp_path>/connector/src/main.py`.

    Returns:
        Path: The connector root, i.e. the parent of the `src` directory.
    """
    connector_root = tmp_path / "connector"
    (connector_root / "src").mkdir(parents=True)
    monkeypatch.setitem(
        sys.modules,
        "__main__",
        SimpleNamespace(__file__=str(connector_root / "src" / "main.py")),
    )
    return connector_root


@pytest.fixture
def mock_missing_main_path(monkeypatch):
    """Pretend the process has no file-backed entrypoint."""
    monkeypatch.setitem(sys.modules, "__main__", SimpleNamespace(__file__=None))


def make_record(**overrides) -> logging.LogRecord:
    """Build a log record, overriding any of its constructor arguments.

    Args:
        **overrides: Values passed to `logging.LogRecord`, plus an optional `extra`
            mapping merged into the record's `__dict__`.

    Returns:
        logging.LogRecord: The record.
    """
    arguments = {
        "name": "connector.demo",
        "level": logging.INFO,
        "pathname": str(Path("/app/src/main.py")),
        "lineno": 12,
        "msg": "hello",
        "args": None,
        "exc_info": None,
    }
    extra = overrides.pop("extra", {})
    arguments.update(overrides)
    record = logging.LogRecord(**arguments)
    record.__dict__.update(extra)
    return record

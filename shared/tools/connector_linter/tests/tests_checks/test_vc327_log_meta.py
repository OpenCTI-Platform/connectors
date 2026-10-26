"""Unit tests for VC327 — SDK log messages must be static, data passed in meta."""

import pytest
from connector_linter.models import Severity
from connector_linter.runner import run_checks

_PROCESSOR_HEADER = """\
from connectors_sdk import BaseDataProcessor

class Processor(BaseDataProcessor):
    def run(self, reports, err, count, value, msg):
"""

_GOOD_PROCESSOR = _PROCESSOR_HEADER + """\
        self.logger.info("Reports fetched", meta={"count": len(reports)})
        self.logger.error("Import failed", meta={"error": str(err)})
        self.logger.debug("Static message " "split on two literals")
        self.logger.debug("Static " + "concatenation")
        self.logger.info(f"No placeholder")
        self.logger.warning(message="Keyword message", meta={"id": 1})
        self.logger.info(msg)
"""

_GET_LOGGER_MODULE = """\
from connectors_sdk.logger import get_logger as make_logger

_LOGGER = make_logger(__name__)

def fetch(count):
    _LOGGER.info(f"Fetched {count} items")
"""

_ANNOTATED_CLIENT = """\
from connectors_sdk import ConnectorLoggerAdapter

class Client:
    def __init__(self, logger: ConnectorLoggerAdapter | None = None):
        self._logger = logger

    def fetch(self, count):
        self._logger.info(f"Fetched {count} items")
"""

_SUBCLASS_OF_LOCAL_SDK_CLASS = """\
from connectors_sdk import BaseClientApi

class BaseClient(BaseClientApi):
    pass

class Client(BaseClient):
    def fetch(self, count):
        log = self.logger
        log.info(f"Fetched {count} items")
"""

_PYCTI_CONNECTOR_LOGGER = """\
from connectors_sdk import BaseClientApi

class Connector:
    def run(self, count):
        self.helper.connector_logger.info(f"Fetched {count} items")
"""

_STDLIB_LOGGER_NAMED_LIKE_SDK = """\
import logging

from connectors_sdk import BaseDataProcessor

class Client:
    def __init__(self, logger=None):
        self._logger = logger or logging.getLogger(__name__)

    def fetch(self, count):
        self._logger.info(f"Fetched {count} items")
        self.logger.info(f"Not an SDK class: {count}")
"""

_UNTYPED_LOGGER_PARAM = """\
from connectors_sdk import BaseClientApi

class Client(BaseClientApi):
    def __init__(self, logger):
        self._logger = logger

    def fetch(self, count):
        self._logger.info(f"Fetched {count} items")
"""

_NO_SDK = """\
class Connector:
    def run(self, count):
        self.logger.info(f"Fetched {count} items")
"""


class TestVC327LogMeta:
    """VC327 applies to every connector type, on connectors-sdk loggers only."""

    def test_passes_with_static_messages(self, connector_src):
        path = connector_src(("src/main.py", _GOOD_PROCESSOR))
        results = run_checks(path, select=["VC327"])
        assert all(r.severity == Severity.INFO for r in results)

    @pytest.mark.parametrize(
        ("call", "kind"),
        [
            ('self.logger.info(f"Fetched {count} reports")', "an f-string"),
            ('self.logger.error("Failed: %s" % err)', "% formatting"),
            ('self.logger.warning("Failed: " + str(err))', "string concatenation"),
            ('self.logger.debug("Got {}".format(value))', "str.format()"),
            ("self.logger.error(str(err))", "a function call"),
            ('self.logger.critical(msg=f"Boom {err}")', "an f-string"),
        ],
    )
    def test_warns_on_dynamic_message(self, connector_src, call, kind):
        path = connector_src(("src/main.py", f"{_PROCESSOR_HEADER}        {call}\n"))
        results = run_checks(path, select=["VC327"])
        warnings = [r for r in results if r.severity == Severity.WARNING]
        assert len(warnings) == 1
        assert kind in warnings[0].message
        assert warnings[0].line == 5
        assert "meta" in warnings[0].suggestion

    @pytest.mark.parametrize(
        ("source", "line"),
        [
            (_GET_LOGGER_MODULE, 6),
            (_ANNOTATED_CLIENT, 8),
            (_SUBCLASS_OF_LOCAL_SDK_CLASS, 9),
        ],
        ids=["get_logger", "annotated-param", "local-subclass"],
    )
    def test_resolves_sdk_loggers(self, connector_src, source, line):
        path = connector_src(("src/main.py", source))
        results = run_checks(path, select=["VC327"])
        assert [r.line for r in results if r.severity == Severity.WARNING] == [line]

    @pytest.mark.parametrize(
        "source",
        [_PYCTI_CONNECTOR_LOGGER, _STDLIB_LOGGER_NAMED_LIKE_SDK, _UNTYPED_LOGGER_PARAM],
        ids=["pycti-connector-logger", "stdlib-logger", "untyped-param"],
    )
    def test_ignores_non_sdk_loggers(self, connector_src, source):
        path = connector_src(("src/main.py", source))
        results = run_checks(path, select=["VC327"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_skipped_without_sdk_logger(self, connector_src):
        path = connector_src(("src/main.py", _NO_SDK))
        results = run_checks(path, select=["VC327"])
        assert len(results) == 1
        assert results[0].severity == Severity.INFO
        assert "skipped" in results[0].message

    def test_one_finding_per_call_in_source_order(self, connector_src):
        source = (
            _PROCESSOR_HEADER
            + '        self.logger.error(f"b {err}")\n'
            + '        self.logger.info("ok")\n'
            + '        self.logger.info(f"a {count}")\n'
        )
        path = connector_src(("src/main.py", source))
        results = run_checks(path, select=["VC327"])
        assert [r.line for r in results if r.severity == Severity.WARNING] == [5, 7]

    def test_applies_to_stream_connector(self, connector_src):
        path = connector_src(
            ("src/main.py", _GET_LOGGER_MODULE),
            connector_type="STREAM",
        )
        results = run_checks(path, select=["VC327"])
        assert any(r.severity == Severity.WARNING for r in results)

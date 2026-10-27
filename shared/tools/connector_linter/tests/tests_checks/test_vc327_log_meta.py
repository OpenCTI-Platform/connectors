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

_ALIAS_IN_OTHER_MODULE = (
    (
        "src/sdk_logging.py",
        "from connectors_sdk import get_logger\n\nLOGGER = get_logger(__name__)\n",
    ),
    (
        "src/stdlib_logging.py",
        "from logging import getLogger as get_logger\n\n"
        "logger = get_logger(__name__)\n"
        'logger.info(f"Stdlib {value}")\n',
    ),
)

_NESTED_SCOPE = """\
from connectors_sdk import get_logger

def outer(logger, count):
    def inner():
        logger = get_logger(__name__)
        logger.info(f"Inner {count}")
    logger.info(f"Outer {count}")
"""

_PARAM_SHADOWS_MODULE_LOGGER = """\
from connectors_sdk import get_logger

logger = get_logger(__name__)

def consume(logger, count):
    logger.info(f"Count {count}")

def produce(count):
    logger.info(f"Produce {count}")
"""

_LOCAL_SHADOWS_MODULE_LOGGER = """\
import logging

from connectors_sdk import get_logger

logger = get_logger(__name__)

def run(count):
    logger = logging.getLogger(__name__)
    logger.info(f"Count {count}")
"""

_MIXED_ASSIGNMENTS = """\
import logging

from connectors_sdk import get_logger

class Client:
    def __init__(self, debug):
        if debug:
            self._logger = get_logger(__name__)
        else:
            self._logger = logging.getLogger(__name__)

    def fetch(self, count):
        self._logger.info(f"Fetched {count}")
"""

_CROSS_MODULE_CLASSES = (
    (
        "src/client/base.py",
        "from connectors_sdk import BaseClientApi\n\n"
        "class BaseClient(BaseClientApi):\n"
        "    pass\n",
    ),
    ("src/client/__init__.py", "from client.base import BaseClient\n"),
    (
        "src/client/api.py",
        "from client import BaseClient\n\n"
        "class Api(BaseClient):\n"
        "    def fetch(self, count):\n"
        '        self.logger.info(f"Fetched {count}")\n',
    ),
    # Same class name, not an SDK class
    ("src/other.py", "class BaseClient:\n    pass\n"),
    (
        "src/legacy.py",
        "from other import BaseClient\n\n"
        "class Legacy(BaseClient):\n"
        "    def fetch(self, count):\n"
        '        self.logger.info(f"Fetched {count}")\n',
    ),
)

_IMPORTED_MODULE_LOGGER = (
    (
        "src/utils.py",
        "from connectors_sdk import get_logger\n\nLOGGER = get_logger(__name__)\n",
    ),
    (
        "src/main.py",
        "import utils\n"
        "from utils import LOGGER\n\n"
        "def run(count):\n"
        '    LOGGER.info(f"Direct {count}")\n'
        '    utils.LOGGER.info(f"Qualified {count}")\n',
    ),
)


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

    @pytest.mark.parametrize(
        ("source", "lines"),
        [
            (_NESTED_SCOPE, [6]),
            (_PARAM_SHADOWS_MODULE_LOGGER, [9]),
            (_LOCAL_SHADOWS_MODULE_LOGGER, []),
            (_MIXED_ASSIGNMENTS, []),
        ],
        ids=[
            "nested-scope",
            "param-shadows-module-logger",
            "local-shadows-module-logger",
            "mixed-assignments",
        ],
    )
    def test_follows_python_scoping(self, connector_src, source, lines):
        path = connector_src(("src/main.py", source))
        results = run_checks(path, select=["VC327"])
        assert [r.line for r in results if r.severity == Severity.WARNING] == lines

    def test_resolves_imports_per_module(self, connector_src):
        """An SDK import alias in one module does not leak into another."""
        path = connector_src(*_ALIAS_IN_OTHER_MODULE)
        results = run_checks(path, select=["VC327"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_resolves_base_classes_through_imports(self, connector_src):
        path = connector_src(*_CROSS_MODULE_CLASSES)
        results = run_checks(path, select=["VC327"])
        warnings = [r for r in results if r.severity == Severity.WARNING]
        assert [(r.file_path.name, r.line) for r in warnings] == [("api.py", 5)]

    def test_resolves_logger_imported_from_another_module(self, connector_src):
        path = connector_src(*_IMPORTED_MODULE_LOGGER)
        results = run_checks(path, select=["VC327"])
        warnings = [r for r in results if r.severity == Severity.WARNING]
        assert [(r.file_path.name, r.line) for r in warnings] == [
            ("main.py", 5),
            ("main.py", 6),
        ]

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

"""Unit tests for VC307 — except blocks should use error/warning logging."""

from connector_linter.models import Severity
from connector_linter.runner import run_checks

_GOOD_EXCEPT = """\
import logging
logger = logging.getLogger(__name__)

try:
    risky()
except Exception as e:
    logger.error("Something failed: %s", e)
"""

_BAD_EXCEPT_DEBUG_ONLY = """\
import logging
logger = logging.getLogger(__name__)

try:
    risky()
except Exception as e:
    logger.debug("Caught: %s", e)
"""

_SUPPLEMENTARY_OK = """\
import logging
logger = logging.getLogger(__name__)

try:
    risky()
except Exception as e:
    logger.debug("Details: %s", e)
    logger.error("Operation failed")
"""

_KEYBOARD_INTERRUPT_EXEMPT = """\
import logging
logger = logging.getLogger(__name__)

try:
    run()
except KeyboardInterrupt:
    logger.info("Shutting down")
"""

_NO_LOGGING_IN_EXCEPT = """\
try:
    risky()
except Exception as e:
    pass
"""


class TestVC307ExceptLogging:
    """VC307 warns when except blocks only use debug/info logging."""

    def test_passes_with_error_logging(self, connector_src):
        path = connector_src(("src/main.py", _GOOD_EXCEPT))
        results = run_checks(path, select=["VC307"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_warns_debug_only(self, connector_src):
        path = connector_src(("src/main.py", _BAD_EXCEPT_DEBUG_ONLY))
        results = run_checks(path, select=["VC307"])
        # WARNINGs stay passed=True (advisory); detect by file_path presence
        flagged = [
            r
            for r in results
            if r.severity == Severity.WARNING and r.file_path is not None
        ]
        assert len(flagged) >= 1

    def test_passes_when_debug_plus_error(self, connector_src):
        """debug() alongside error() is fine — error takes care of alerting."""
        path = connector_src(("src/main.py", _SUPPLEMENTARY_OK))
        results = run_checks(path, select=["VC307"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_keyboard_interrupt_exempt(self, connector_src):
        """KeyboardInterrupt is expected control flow — info/debug is fine."""
        path = connector_src(("src/main.py", _KEYBOARD_INTERRUPT_EXEMPT))
        results = run_checks(path, select=["VC307"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_no_logging_in_except_not_flagged(self, connector_src):
        """VC307 only checks blocks that DO log — silent except is a different issue."""
        path = connector_src(("src/main.py", _NO_LOGGING_IN_EXCEPT))
        results = run_checks(path, select=["VC307"])
        assert all(r.severity == Severity.INFO for r in results)

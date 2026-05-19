"""Unit tests for VC306 — connector log level should default to 'error'."""

from connector_linter.models import Severity
from connector_linter.runner import run_checks

_CORRECT_DEFAULT = """\
from pydantic_settings import BaseSettings

class ConnectorSettings(BaseSettings):
    log_level: str = "error"
"""

_WRONG_DEFAULT_DEBUG = """\
from pydantic_settings import BaseSettings

class ConnectorSettings(BaseSettings):
    log_level: str = "debug"
"""

_WRONG_DEFAULT_INFO = """\
from pydantic_settings import BaseSettings

class ConnectorSettings(BaseSettings):
    log_level: str = "info"
"""

_SDK_INHERITS_DEFAULT = """\
from connectors_sdk.models.connector import BaseExternalImportConnectorConfig

class ConnectorSettings(BaseExternalImportConnectorConfig):
    my_api_key: str
"""

_NO_LOG_LEVEL = """\
class ConnectorSettings:
    pass
"""


class TestVC306LogLevelDefault:
    """VC306 flags log levels that are not 'error'."""

    def test_passes_error_default(self, connector_src):
        path = connector_src(("src/main.py", _CORRECT_DEFAULT))
        results = run_checks(path, select=["VC306"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_fails_debug_default(self, connector_src):
        """A debug default is flagged as advisory — WARNING, passed=True."""
        path = connector_src(("src/main.py", _WRONG_DEFAULT_DEBUG))
        results = run_checks(path, select=["VC306"])
        # WARNINGs are advisory (passed=True); detect by file_path presence
        flagged = [
            r
            for r in results
            if r.severity == Severity.WARNING and r.file_path is not None
        ]
        assert len(flagged) >= 1

    def test_fails_info_default(self, connector_src):
        path = connector_src(("src/main.py", _WRONG_DEFAULT_INFO))
        results = run_checks(path, select=["VC306"])
        flagged = [
            r
            for r in results
            if r.severity == Severity.WARNING and r.file_path is not None
        ]
        assert len(flagged) >= 1

    def test_passes_sdk_inherits_default(self, connector_src):
        """SDK base configs already default to 'error' — should pass."""
        path = connector_src(("src/main.py", _SDK_INHERITS_DEFAULT))
        results = run_checks(path, select=["VC306"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_advisory_when_no_log_level(self, connector_src):
        """No log_level field found → advisory pass (can't verify)."""
        path = connector_src(("src/main.py", _NO_LOG_LEVEL))
        results = run_checks(path, select=["VC306"])
        # No ERROR failures — just an advisory at most
        errors = [r for r in results if r.severity == Severity.ERROR]
        assert len(errors) == 0

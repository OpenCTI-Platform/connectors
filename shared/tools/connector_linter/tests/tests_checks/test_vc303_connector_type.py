"""Unit tests for VC303 — CONNECTOR_TYPE must be hardcoded, not read from env."""

from connector_linter.models import Severity
from connector_linter.runner import run_checks

_SDK_BASED = """\
from connectors_sdk.config import BaseExternalImportConnectorConfig

class ConnectorConfig(BaseExternalImportConnectorConfig):
    pass
"""

_PYCTI_HARDCODED = """\
config = {
    "connector": {
        "type": "EXTERNAL_IMPORT",
    }
}
"""

_ENV_READ_OS = """\
import os
connector_type = os.environ["CONNECTOR_TYPE"]
"""

_ENV_READ_GETENV = """\
import os
connector_type = os.getenv("CONNECTOR_TYPE")
"""

_ENV_READ_GET_CONFIG = """\
connector_type = self.helper.get_config_variable("CONNECTOR_TYPE", ["connector", "type"])
"""

_PYDANTIC_LITERAL = """\
from typing import Literal
from pydantic import Field

class ConnectorSettings:
    type: Literal["EXTERNAL_IMPORT"] = Field(default="EXTERNAL_IMPORT")
"""


class TestVC303ConnectorType:
    """VC303 detects env reads and accepts hardcoded type definitions."""

    def test_passes_sdk_base_config(self, connector_src):
        path = connector_src(("src/main.py", _SDK_BASED))
        results = run_checks(path, select=["VC303"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_passes_pycti_hardcoded_dict(self, connector_src):
        path = connector_src(("src/main.py", _PYCTI_HARDCODED))
        results = run_checks(path, select=["VC303"])
        assert all(r.severity == Severity.WARNING for r in results)

    def test_passes_pydantic_literal(self, connector_src):
        path = connector_src(("src/main.py", _PYDANTIC_LITERAL))
        results = run_checks(path, select=["VC303"])
        assert all(r.severity == Severity.WARNING for r in results)

    def test_flags_os_environ_read(self, connector_src):
        path = connector_src(("src/main.py", _ENV_READ_OS))
        results = run_checks(path, select=["VC303"])
        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 1
        assert "environment" in failed[0].message.lower()

    def test_flags_os_getenv_read(self, connector_src):
        path = connector_src(("src/main.py", _ENV_READ_GETENV))
        results = run_checks(path, select=["VC303"])
        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 1

    def test_flags_get_config_variable(self, connector_src):
        path = connector_src(("src/main.py", _ENV_READ_GET_CONFIG))
        results = run_checks(path, select=["VC303"])
        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 1

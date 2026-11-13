"""Unit tests for VC104 — hardcoded Python configuration detection."""

import pytest
from connector_linter.runner import run_checks

_HARDCODED_CONFIG = """\
API_URL = "https://example.test"
"""

_SDK_SETTINGS_IMPORT = """\
from connectors_sdk import {base}

API_URL = "https://example.test"
"""


def _hardcoded_findings(results):
    return [r for r in results if "appears hardcoded in Python" in r.message]


class TestVC104HardcodedPythonConfig:
    """VC104 flags module-level config constants outside settings.py."""

    def test_flags_hardcoded_config_constant(self, connector_src):
        path = connector_src(("src/config.py", _HARDCODED_CONFIG))
        results = run_checks(path, select=["VC104"])
        findings = _hardcoded_findings(results)
        assert len(findings) == 1
        assert "API_URL" in findings[0].message

    @pytest.mark.parametrize(
        "base_name",
        [
            "BaseConnectorSettings",
            "BaseExternalImportConnectorSettings",
            "BaseInternalEnrichmentConnectorSettings",
            "BaseStreamConnectorSettings",
            "BaseInternalExportFileConnectorSettings",
            "BaseInternalImportFileConnectorSettings",
        ],
    )
    def test_skips_file_using_sdk_settings_base(self, connector_src, base_name):
        """A file using an SDK settings base already loads config at runtime."""
        source = _SDK_SETTINGS_IMPORT.format(base=base_name)
        path = connector_src(("src/config.py", source))
        results = run_checks(path, select=["VC104"])
        assert _hardcoded_findings(results) == []

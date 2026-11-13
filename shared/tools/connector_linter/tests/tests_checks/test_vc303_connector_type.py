"""Unit tests for VC303 — CONNECTOR_TYPE must be hardcoded, not read from env."""

import pytest
from connector_linter.models import Severity
from connector_linter.runner import run_checks

_SDK_BASED = """\
from connectors_sdk.config import BaseExternalImportConnectorConfig

class ConnectorConfig(BaseExternalImportConnectorConfig):
    pass
"""

_SDK_TYPED_SETTINGS = """\
from connectors_sdk import {base}

class ConnectorSettings({base}):
    my_api_key: str
"""

_SDK_SETTINGS_CUSTOM_CONNECTOR = """\
from connectors_sdk import BaseConfigModel, BaseExternalImportConnectorSettings
from pydantic import Field

class MyConnectorConfig(BaseConfigModel):
    name: str = "My connector"

class ConnectorSettings(BaseExternalImportConnectorSettings):
    connector: MyConnectorConfig = Field(default_factory=MyConnectorConfig)
"""

_SDK_SETTINGS_CUSTOM_CONNECTOR_PLAIN_ASSIGN = """\
from connectors_sdk import BaseExternalImportConnectorSettings

class ConnectorSettings(BaseExternalImportConnectorSettings):
    connector = None
"""

_SDK_SETTINGS_SDK_CONFIG_CONNECTOR = """\
from connectors_sdk import (
    BaseExternalImportConnectorConfig,
    BaseExternalImportConnectorSettings,
)
from pydantic import Field

class MyConnectorConfig(BaseExternalImportConnectorConfig):
    name: str = "My connector"

class ConnectorSettings(BaseExternalImportConnectorSettings):
    connector: MyConnectorConfig = Field(default_factory=MyConnectorConfig)
"""

_SDK_SETTINGS_BARE_ANNOTATION = """\
from connectors_sdk import BaseConfigModel, BaseExternalImportConnectorSettings

class MyConnectorConfig(BaseConfigModel):
    name: str = "My connector"

class ConnectorSettings(BaseExternalImportConnectorSettings):
    connector: MyConnectorConfig
"""

_SDK_SETTINGS_DIRECT_SDK_CONFIG_ANNOTATION = """\
from connectors_sdk import (
    BaseExternalImportConnectorConfig,
    BaseExternalImportConnectorSettings,
)
from pydantic import Field

class ConnectorSettings(BaseExternalImportConnectorSettings):
    connector: BaseExternalImportConnectorConfig = Field(
        default_factory=BaseExternalImportConnectorConfig,
        description="Only the description changes",
    )
"""

_SDK_SETTINGS_NESTED_CONNECTOR_ASSIGN = """\
from connectors_sdk import BaseExternalImportConnectorSettings

class ConnectorSettings(BaseExternalImportConnectorSettings):
    class Nested:
        connector = None

    def build(self):
        connector = None
        return connector
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

    @pytest.mark.parametrize(
        "base_name",
        [
            "BaseExternalImportConnectorSettings",
            "BaseInternalEnrichmentConnectorSettings",
            "BaseStreamConnectorSettings",
            "BaseInternalExportFileConnectorSettings",
            "BaseInternalImportFileConnectorSettings",
        ],
    )
    def test_passes_sdk_typed_base_settings(self, connector_src, base_name):
        """Per-type SDK settings bases set the type through their default config."""
        source = _SDK_TYPED_SETTINGS.format(base=base_name)
        path = connector_src(("src/main.py", source))
        results = run_checks(path, select=["VC303"])
        assert all(r.severity == Severity.INFO for r in results)

    @pytest.mark.parametrize(
        "source",
        [
            _SDK_SETTINGS_CUSTOM_CONNECTOR,
            _SDK_SETTINGS_CUSTOM_CONNECTOR_PLAIN_ASSIGN,
            _SDK_SETTINGS_BARE_ANNOTATION,
        ],
        ids=["annotated", "plain", "bare-annotation"],
    )
    def test_fails_settings_redefining_connector_without_type(
        self, connector_src, source
    ):
        """Redefining `connector` drops the type the settings base provided."""
        path = connector_src(("src/main.py", source))
        results = run_checks(path, select=["VC303"])
        assert not any(
            "defined via connectors-sdk" in r.message for r in results
        ), "Settings redefining `connector` must not count as SDK-defined type"
        assert len(results) == 1
        assert results[0].severity == Severity.ERROR
        assert "No CONNECTOR_TYPE definition found" in results[0].message

    def test_passes_settings_redefining_connector_with_sdk_config(self, connector_src):
        """A redefined `connector` whose config inherits the SDK one keeps the type."""
        path = connector_src(("src/main.py", _SDK_SETTINGS_SDK_CONFIG_CONNECTOR))
        results = run_checks(path, select=["VC303"])
        assert len(results) == 1
        assert results[0].severity == Severity.INFO
        assert "defined via connectors-sdk" in results[0].message
        # The hit is the config class (line 7), not the settings class (line 10)
        assert results[0].line == 7

    def test_passes_settings_redefining_connector_with_direct_sdk_config(
        self, connector_src
    ):
        """A `connector` annotated with the SDK config class itself keeps the type."""
        path = connector_src(
            ("src/main.py", _SDK_SETTINGS_DIRECT_SDK_CONFIG_ANNOTATION)
        )
        results = run_checks(path, select=["VC303"])
        assert len(results) == 1
        assert results[0].severity == Severity.INFO
        assert "defined via connectors-sdk" in results[0].message

    def test_passes_settings_with_nested_connector_assign(self, connector_src):
        """A `connector` assigned in a nested class or method is not a redefinition."""
        path = connector_src(("src/main.py", _SDK_SETTINGS_NESTED_CONNECTOR_ASSIGN))
        results = run_checks(path, select=["VC303"])
        assert len(results) == 1
        assert results[0].severity == Severity.INFO
        assert "defined via connectors-sdk" in results[0].message

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

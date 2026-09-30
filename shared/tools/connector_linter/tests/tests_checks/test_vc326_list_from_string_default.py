"""Unit tests for VC326 — ListFromString settings must define a default value."""

import json

from connector_linter.models import Severity
from connector_linter.runner import run_checks

_WITH_DEFAULT = """\
from connectors_sdk import ListFromString
from pydantic import Field


class ConnectorSettings:
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["myconnector"],
    )
"""

_WITH_EMPTY_LIST_DEFAULT = """\
from connectors_sdk import ListFromString
from pydantic import Field


class ConnectorSettings:
    report_extract_iocs: ListFromString = Field(
        description="IOC types to extract.",
        default=[],
    )
"""

_BARE_ANNOTATION_NO_DEFAULT = """\
from connectors_sdk import ListFromString


class ConnectorSettings:
    scope: ListFromString
"""

_FIELD_WITHOUT_DEFAULT = """\
from connectors_sdk import ListFromString
from pydantic import Field


class ConnectorSettings:
    scope: ListFromString = Field(
        description="The scope of the connector.",
    )
"""

_ABSTRACT_CLASS_NO_DEFAULT_OK = """\
from connectors_sdk import ListFromString
from pydantic import Field


class _BaseConnectorConfig:
    scope: ListFromString = Field(
        description="The scope of the connector.",
    )
"""

_NO_LIST_FROM_STRING = """\
class ConnectorSettings:
    api_key: str
"""

_INTERFACE_CLASS_OVERRIDDEN_BY_SUBCLASS_OK = """\
from connectors_sdk import ListFromString
from pydantic import Field


class ConfigLoaderConnectorExtra:
    \"\"\"Interface for loading Connector dedicated configuration.\"\"\"

    scope: ListFromString = Field(
        description="The scope of the connector.",
    )


class ConfigLoaderConnector(ConfigLoaderConnectorExtra):
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["myconnector"],
    )
"""


class TestVC326ListFromStringDefault:
    """VC326 flags ListFromString fields with no default value."""

    def test_passes_with_default(self, connector_src):
        path = connector_src(("src/settings.py", _WITH_DEFAULT))
        results = run_checks(path, select=["VC326"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_passes_with_empty_list_default(self, connector_src):
        path = connector_src(("src/settings.py", _WITH_EMPTY_LIST_DEFAULT))
        results = run_checks(path, select=["VC326"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_fails_bare_annotation_no_default(self, connector_src):
        path = connector_src(("src/settings.py", _BARE_ANNOTATION_NO_DEFAULT))
        results = run_checks(path, select=["VC326"])
        assert any(r.severity == Severity.ERROR for r in results)

    def test_fails_field_without_default(self, connector_src):
        path = connector_src(("src/settings.py", _FIELD_WITHOUT_DEFAULT))
        results = run_checks(path, select=["VC326"])
        assert any(r.severity == Severity.ERROR for r in results)

    def test_passes_abstract_class_without_default(self, connector_src):
        """Classes prefixed with `_` are abstract/interface bases and are skipped."""
        path = connector_src(("src/settings.py", _ABSTRACT_CLASS_NO_DEFAULT_OK))
        results = run_checks(path, select=["VC326"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_passes_no_list_from_string(self, connector_src):
        path = connector_src(("src/settings.py", _NO_LIST_FROM_STRING))
        results = run_checks(path, select=["VC326"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_passes_interface_class_overridden_by_subclass(self, connector_src):
        """An interface-style base class (no `_` prefix) that is locally
        subclassed with a default is not flagged — the concrete subclass wins.
        """
        path = connector_src(
            (
                "src/settings.py",
                _INTERFACE_CLASS_OVERRIDDEN_BY_SUBCLASS_OK,
            ),
        )
        results = run_checks(path, select=["VC326"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_fails_schema_array_property_without_default(self, connector_src):
        """A concrete class not overriding an inherited field is caught via schema."""
        path = connector_src(("src/settings.py", _NO_LIST_FROM_STRING))
        schema_path = path / "__metadata__" / "connector_config_schema.json"
        schema_path.write_text(
            json.dumps(
                {
                    "properties": {
                        "CONNECTOR_SCOPE": {
                            "description": "The scope of the connector.",
                            "items": {"type": "string"},
                            "type": "array",
                        },
                    },
                },
            ),
            encoding="utf-8",
        )
        results = run_checks(path, select=["VC326"])
        assert any(r.severity == Severity.ERROR for r in results)

    def test_passes_schema_array_property_with_default(self, connector_src):
        path = connector_src(("src/settings.py", _NO_LIST_FROM_STRING))
        schema_path = path / "__metadata__" / "connector_config_schema.json"
        schema_path.write_text(
            json.dumps(
                {
                    "properties": {
                        "CONNECTOR_SCOPE": {
                            "default": ["myconnector"],
                            "description": "The scope of the connector.",
                            "items": {"type": "string"},
                            "type": "array",
                        },
                    },
                },
            ),
            encoding="utf-8",
        )
        results = run_checks(path, select=["VC326"])
        assert all(r.severity == Severity.INFO for r in results)

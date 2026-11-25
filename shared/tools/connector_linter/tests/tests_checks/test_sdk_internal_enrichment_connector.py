"""Unit tests for enrichment checks on connectors built on the SDK base connector.

connectors-sdk's ``InternalEnrichmentConnector`` owns the listen loop, the TLP
check, the playbook handling and the bundle sending, so the connector code has
none of the patterns VC304, VC318, VC319, VC320, VC321 and VC322 look for.
"""

import pytest
from connector_linter.models import Severity
from connector_linter.runner import run_checks

# Checks satisfied by the SDK base connector
_DELEGATED_CHECKS = ["VC304", "VC318", "VC319", "VC320", "VC321", "VC322"]

_SDK_MAIN = """\
from connector.processors import IPv4Processor
from connector.settings import ConnectorSettings
from connectors_sdk import InternalEnrichmentConnector

if __name__ == "__main__":
    InternalEnrichmentConnector(
        settings=ConnectorSettings(),
        enrichment_processors=[IPv4Processor()],
    ).start()
"""

_SDK_MAIN_SUBMODULE_IMPORT = """\
from connectors_sdk.connectors.internal_enrichment.internal_enrichment_connector import (
    InternalEnrichmentConnector,
)

InternalEnrichmentConnector(settings=settings, enrichment_processors=[]).start()
"""

_SDK_PROCESSOR = """\
from connectors_sdk import BaseEnrichmentProcessor


class IPv4Processor(BaseEnrichmentProcessor):
    handled_entity_types = frozenset({"IPv4-Addr"})

    def collect(self, message):
        return self.client.get_ip(message.stix_entity["value"])

    def transform(self, data, message):
        return [self.author, self.tlp_marking]
"""

# A connector defining its own class with the same name (e.g. hostio)
_LOCAL_BASE_MAIN = """\
from lib.internal_enrichment import InternalEnrichmentConnector


class MyConnector(InternalEnrichmentConnector):
    def _process_message(self, data):
        return "done"
"""

# A legacy connector keeping its own message handling, using only the SDK
# static helpers: it delegates nothing to the SDK controller
_SDK_HELPERS_ONLY_MAIN = """\
from connectors_sdk import InternalEnrichmentConnector
from pycti import OpenCTIConnectorHelper


class MyConnector:
    def __init__(self, config):
        self.helper = OpenCTIConnectorHelper(config)

    def _process_message(self, data):
        entity_type = data["enrichment_entity"]["entity_type"]
        if not InternalEnrichmentConnector.is_entity_in_scope(entity_type, ["IPv4-Addr"]):
            return "out of scope"
        return "done"
"""

_SDK_ALIASED_MAIN = """\
from connectors_sdk import InternalEnrichmentConnector as BaseConnector

BaseConnector(settings=settings, enrichment_processors=[]).start()
"""

_SDK_GENERIC_MAIN = """\
from connectors_sdk import InternalEnrichmentConnector

InternalEnrichmentConnector[ConnectorSettings](
    settings=settings, enrichment_processors=[]
).start()
"""

_SDK_SUBCLASS = """\
from connectors_sdk import InternalEnrichmentConnector as Base


class MyConnector(Base[ConnectorSettings]):
    pass
"""


class TestSdkInternalEnrichmentConnector:
    """Enrichment checks pass on a connector built on InternalEnrichmentConnector."""

    @pytest.mark.parametrize("check_code", _DELEGATED_CHECKS)
    def test_passes_with_sdk_base_connector(self, connector_src, check_code):
        path = connector_src(
            ("src/main.py", _SDK_MAIN),
            ("src/connector/processors.py", _SDK_PROCESSOR),
            connector_type="INTERNAL_ENRICHMENT",
        )
        results = run_checks(path, select=[check_code])
        assert len(results) == 1
        assert results[0].severity == Severity.INFO
        assert "connectors-sdk InternalEnrichmentConnector" in results[0].message
        assert results[0].file_path.name == "main.py"

    @pytest.mark.parametrize("check_code", _DELEGATED_CHECKS)
    def test_passes_with_sdk_submodule_import(self, connector_src, check_code):
        """Importing from the SDK submodule is recognised too."""
        path = connector_src(
            ("src/main.py", _SDK_MAIN_SUBMODULE_IMPORT),
            connector_type="INTERNAL_ENRICHMENT",
        )
        results = run_checks(path, select=[check_code])
        assert [r.severity for r in results] == [Severity.INFO]

    @pytest.mark.parametrize("check_code", _DELEGATED_CHECKS)
    @pytest.mark.parametrize(
        "source",
        [_SDK_ALIASED_MAIN, _SDK_GENERIC_MAIN, _SDK_SUBCLASS],
        ids=["alias", "generic", "subclass"],
    )
    def test_passes_with_other_controller_uses(self, connector_src, check_code, source):
        """Aliased, generic and subclassed uses of the base are recognised."""
        path = connector_src(
            ("src/connector/connector.py", source),
            connector_type="INTERNAL_ENRICHMENT",
        )
        results = run_checks(path, select=[check_code])
        assert [r.severity for r in results] == [Severity.INFO]

    @pytest.mark.parametrize("check_code", _DELEGATED_CHECKS)
    def test_static_helpers_only_do_not_satisfy_the_checks(
        self, connector_src, check_code
    ):
        """Importing the base only to call its static helpers delegates nothing."""
        path = connector_src(
            ("src/main.py", _SDK_HELPERS_ONLY_MAIN),
            connector_type="INTERNAL_ENRICHMENT",
        )
        results = run_checks(path, select=[check_code])
        assert results
        assert all(r.severity != Severity.INFO for r in results)

    @pytest.mark.parametrize("check_code", _DELEGATED_CHECKS)
    def test_local_class_with_same_name_is_not_the_sdk(self, connector_src, check_code):
        """A connector's own InternalEnrichmentConnector does not satisfy the checks."""
        path = connector_src(
            ("src/main.py", _LOCAL_BASE_MAIN),
            connector_type="INTERNAL_ENRICHMENT",
        )
        results = run_checks(path, select=[check_code])
        assert results
        assert all(r.severity != Severity.INFO for r in results)

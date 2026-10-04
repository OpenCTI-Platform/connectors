"""Unit tests for VC327 — hunt connectors must listen to hunt runs."""

from connector_linter.models import Severity
from connector_linter.runner import run_checks

_SDK_BASED = """\
from connectors_sdk import InternalHuntConnector


class SplunkHuntConnector(InternalHuntConnector):
    languages = ("spl",)
"""

_QUALIFIED_BASE = """\
import connectors_sdk


class SplunkHuntConnector(connectors_sdk.InternalHuntConnector):
    pass
"""

_HELPER_LISTEN_HUNT = """\
class Connector:
    def run(self):
        self.helper.listen_hunt(message_callback=self.process_message)
"""

_BARE_HELPER_LISTEN_HUNT = """\
def run(helper):
    helper.listen_hunt(message_callback=process)
"""

_ALIASED_SUBMODULE_BASE = """\
import connectors_sdk.connectors.internal_hunt as hunt
from connectors_sdk.connectors.internal_hunt import InternalHuntConnector as HuntBase


class SplunkHuntConnector(HuntBase):
    pass


class SentinelHuntConnector(hunt.InternalHuntConnector):
    pass
"""

_SHADOWED_BASE = """\
from connectors_sdk import InternalHuntConnector


class InternalHuntConnector:
    pass


class Connector(InternalHuntConnector):
    pass
"""

_FOREIGN_BASE = """\
import other_sdk
from other_sdk import InternalHuntConnector


class Connector(InternalHuntConnector):
    pass


class OtherConnector(other_sdk.InternalHuntConnector):
    pass
"""

_NO_HUNT_LISTENER = """\
class Connector:
    def run(self):
        self.helper.listen(message_callback=self.process_message)
        other.listen_hunt(message_callback=self.process_message)
"""


class TestVC327HuntConnectorBase:
    """VC327 is scoped to INTERNAL_HUNT only."""

    def test_passes_with_sdk_base_class(self, connector_src):
        path = connector_src(
            ("src/main.py", _SDK_BASED), connector_type="INTERNAL_HUNT"
        )
        results = run_checks(path, select=["VC327"])
        assert len(results) == 1
        assert results[0].severity == Severity.INFO
        assert "InternalHuntConnector" in results[0].message

    def test_passes_with_qualified_base_class(self, connector_src):
        path = connector_src(
            ("src/main.py", _QUALIFIED_BASE), connector_type="INTERNAL_HUNT"
        )
        results = run_checks(path, select=["VC327"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_passes_with_aliased_sdk_imports(self, connector_src):
        path = connector_src(
            ("src/main.py", _ALIASED_SUBMODULE_BASE), connector_type="INTERNAL_HUNT"
        )
        results = run_checks(path, select=["VC327"])
        assert [r.severity for r in results] == [Severity.INFO]

    def test_flags_a_local_class_shadowing_the_sdk_base(self, connector_src):
        path = connector_src(
            ("src/main.py", _SHADOWED_BASE), connector_type="INTERNAL_HUNT"
        )
        results = run_checks(path, select=["VC327"])
        assert [r.severity for r in results] == [Severity.ERROR]

    def test_flags_a_base_class_not_imported_from_the_sdk(self, connector_src):
        path = connector_src(
            ("src/main.py", _FOREIGN_BASE), connector_type="INTERNAL_HUNT"
        )
        results = run_checks(path, select=["VC327"])
        assert [r.severity for r in results] == [Severity.ERROR]

    def test_passes_with_helper_listen_hunt(self, connector_src):
        path = connector_src(
            ("src/main.py", _HELPER_LISTEN_HUNT), connector_type="INTERNAL_HUNT"
        )
        results = run_checks(path, select=["VC327"])
        assert all(r.severity == Severity.INFO for r in results)
        assert "listen_hunt" in results[0].message

    def test_passes_with_bare_helper_listen_hunt(self, connector_src):
        path = connector_src(
            ("src/main.py", _BARE_HELPER_LISTEN_HUNT), connector_type="INTERNAL_HUNT"
        )
        results = run_checks(path, select=["VC327"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_flags_connector_without_hunt_listener(self, connector_src):
        path = connector_src(
            ("src/main.py", _NO_HUNT_LISTENER), connector_type="INTERNAL_HUNT"
        )
        results = run_checks(path, select=["VC327"])
        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 1

    def test_flags_connector_without_sources(self, connector_src):
        path = connector_src(connector_type="INTERNAL_HUNT")
        results = run_checks(path, select=["VC327"])
        assert [r.severity for r in results] == [Severity.ERROR]

    def test_skipped_for_other_types(self, connector_src):
        path = connector_src(
            ("src/main.py", _NO_HUNT_LISTENER), connector_type="INTERNAL_ENRICHMENT"
        )
        assert run_checks(path, select=["VC327"]) == []

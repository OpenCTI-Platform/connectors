"""Unit tests for VC313 — STIX SDO/SRO must use pycti.XXX.generate_id()."""

from connector_linter.models import Severity
from connector_linter.runner import run_checks

_STIX_WITH_ID = """\
import stix2

identity = stix2.Identity(
    id=pycti.Identity.generate_id(name="Acme"),
    name="Acme",
    identity_class="organization",
)
"""

_STIX_MISSING_ID = """\
import stix2

identity = stix2.Identity(
    name="Acme",
    identity_class="organization",
)
"""

_STIX_FROM_IMPORT_WITH_ID = """\
from stix2 import Identity

identity = Identity(
    id=pycti.Identity.generate_id(name="Acme"),
    name="Acme",
    identity_class="organization",
)
"""

_STIX_FROM_IMPORT_MISSING_ID = """\
from stix2 import Identity

identity = Identity(
    name="Acme",
    identity_class="organization",
)
"""

_SCO_NO_ID_NEEDED = """\
import stix2

# SCOs have deterministic IDs — no id= required
ip = stix2.IPv4Address(value="1.2.3.4")
domain = stix2.DomainName(value="example.com")
"""

_SDK_CONNECTOR = """\
from connectors_sdk.models import BaseExternalImportConnector

class MyConnector(BaseExternalImportConnector):
    pass
"""


class TestVC313PyctiGenerateId:
    """VC313 flags stix2 SDO/SRO constructors without explicit id=."""

    def test_passes_when_id_present_qualified(self, connector_src):
        path = connector_src(("src/main.py", _STIX_WITH_ID))
        results = run_checks(path, select=["VC313"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_flags_missing_id_qualified(self, connector_src):
        path = connector_src(("src/main.py", _STIX_MISSING_ID))
        results = run_checks(path, select=["VC313"])
        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 1
        assert "Identity" in failed[0].message

    def test_passes_when_id_present_from_import(self, connector_src):
        path = connector_src(("src/main.py", _STIX_FROM_IMPORT_WITH_ID))
        results = run_checks(path, select=["VC313"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_flags_missing_id_from_import(self, connector_src):
        path = connector_src(("src/main.py", _STIX_FROM_IMPORT_MISSING_ID))
        results = run_checks(path, select=["VC313"])
        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 1

    def test_sco_exempt_no_flag(self, connector_src):
        """SCOs (IPv4Address, DomainName…) are exempt — stix2 makes them deterministic."""
        path = connector_src(("src/main.py", _SCO_NO_ID_NEEDED))
        results = run_checks(path, select=["VC313"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_multiple_violations_each_reported(self, connector_src):
        src = """\
import stix2
a = stix2.Identity(name="A", identity_class="organization")
b = stix2.Malware(name="Evil", is_family=False)
"""
        path = connector_src(("src/main.py", src))
        results = run_checks(path, select=["VC313"])
        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 2

    def test_file_path_and_line_populated(self, connector_src):
        path = connector_src(("src/main.py", _STIX_MISSING_ID))
        results = run_checks(path, select=["VC313"])
        failed = [r for r in results if r.severity == Severity.ERROR]
        assert failed[0].file_path is not None
        assert failed[0].line is not None
        assert failed[0].line > 0

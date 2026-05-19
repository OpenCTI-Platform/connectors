"""Unit tests for VC301 — connector must define an author identity."""

from connector_linter.models import Severity
from connector_linter.runner import run_checks

_STIX2_IDENTITY = """\
import stix2

author = stix2.Identity(
    name="ACME Corp",
    identity_class="organization",
)
"""

_ORGANIZATION_AUTHOR = """\
from connectors_sdk.models.author import OrganizationAuthor

author = OrganizationAuthor(name="ACME Corp")
"""

_PYCTI_API = """\
class Connector:
    def __init__(self, helper):
        self.author = helper.api.identity.create(
            type="Organization",
            name="ACME Corp",
        )
"""

_IDENTITY_FROM_PYCTI = """\
from pycti import Identity

author = Identity(name="ACME Corp", identity_class="organization")
"""

_NO_AUTHOR = """\
def process():
    pass
"""

_UNRELATED_IDENTITY = """\
# Identity imported from a custom, unrelated module
from mymodule import Identity

x = Identity(name="test")
"""


class TestVC301AuthorDefined:
    """VC301 detects author identity definitions across all recognized patterns."""

    def test_passes_stix2_identity(self, connector_src):
        path = connector_src(("src/main.py", _STIX2_IDENTITY))
        results = run_checks(path, select=["VC301"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_passes_organization_author(self, connector_src):
        path = connector_src(("src/main.py", _ORGANIZATION_AUTHOR))
        results = run_checks(path, select=["VC301"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_passes_pycti_api_create(self, connector_src):
        path = connector_src(("src/main.py", _PYCTI_API))
        results = run_checks(path, select=["VC301"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_passes_identity_from_pycti(self, connector_src):
        path = connector_src(("src/main.py", _IDENTITY_FROM_PYCTI))
        results = run_checks(path, select=["VC301"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_fails_no_author(self, connector_src):
        path = connector_src(("src/main.py", _NO_AUTHOR))
        results = run_checks(path, select=["VC301"])
        assert any(r.severity == Severity.ERROR for r in results)

    def test_fails_unrelated_identity_import(self, connector_src):
        """Identity() called but not imported from stix2/pycti — should fail."""
        path = connector_src(("src/main.py", _UNRELATED_IDENTITY))
        results = run_checks(path, select=["VC301"])
        assert any(r.severity == Severity.ERROR for r in results)

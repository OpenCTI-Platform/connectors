"""Unit tests for VC505 — no direct GraphQL API calls via helper.api.*."""

from connector_linter.models import Severity
from connector_linter.runner import run_checks

_CLEAN_BUNDLE_SEND = """\
class Connector:
    def process(self):
        bundle = self._build_bundle()
        self.helper.send_stix2_bundle(bundle)
"""

_DIRECT_API_CAMPAIGN = """\
class Connector:
    def process(self):
        result = self.helper.api.campaign.read(id="xxx")
        return result
"""

_DIRECT_API_MULTIPLE = """\
class Connector:
    def process(self):
        r1 = self.helper.api.campaign.read(id="xxx")
        r2 = self.helper.api.malware.create(name="test")
"""

_ALLOWED_WORK_API = """\
class Connector:
    def process(self):
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, "test")
        self.helper.api.work.to_processed(work_id, "done")
"""

_ALLOWED_VOCAB_API = """\
class Connector:
    def setup(self):
        self.helper.api.vocabulary.list(filters=[])
        self.helper.api.marking_definition.read(id="xxx")
"""


class TestVC505NoDirectApi:
    """VC505 warns on direct helper.api.* calls outside allowed submodules."""

    def test_passes_bundle_send(self, connector_src):
        path = connector_src(("src/main.py", _CLEAN_BUNDLE_SEND))
        results = run_checks(path, select=["VC505"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_fails_direct_campaign_api(self, connector_src):
        """helper.api.campaign is advisory — WARNING with passed=True."""
        path = connector_src(("src/main.py", _DIRECT_API_CAMPAIGN))
        results = run_checks(path, select=["VC505"])
        advisories = [
            r
            for r in results
            if r.severity == Severity.WARNING and r.file_path is not None
        ]
        assert len(advisories) >= 1

    def test_fails_multiple_direct_calls(self, connector_src):
        """Each direct API call produces a separate advisory finding."""
        path = connector_src(("src/main.py", _DIRECT_API_MULTIPLE))
        results = run_checks(path, select=["VC505"])
        advisories = [
            r
            for r in results
            if r.severity == Severity.WARNING and r.file_path is not None
        ]
        assert len(advisories) >= 2

    def test_passes_work_api_allowed(self, connector_src):
        """helper.api.work is whitelisted — should not be flagged."""
        path = connector_src(("src/main.py", _ALLOWED_WORK_API))
        results = run_checks(path, select=["VC505"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_passes_vocab_marking_allowed(self, connector_src):
        """vocabulary and marking_definition are whitelisted."""
        path = connector_src(("src/main.py", _ALLOWED_VOCAB_API))
        results = run_checks(path, select=["VC505"])
        assert all(r.severity == Severity.INFO for r in results)

"""Unit tests for VC315 — connector must call initiate_work before processing."""

from connector_linter.models import Severity
from connector_linter.runner import run_checks

_WITH_INITIATE_WORK = """\
class Connector:
    def process(self, work_id):
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, "Processing"
        )
        self._do_work()
"""

_WITHOUT_INITIATE_WORK = """\
class Connector:
    def process(self):
        self._do_work()
        self.helper.api.work.to_processed(self.work_id, "Done")
"""

_INITIATE_WORK_IN_HELPER = """\
def run_import(helper):
    wid = helper.api.work.initiate_work(helper.connect_id, "Import")
    return wid
"""


class TestVC315WorkInitiated:
    """VC315 applies to EXTERNAL_IMPORT connectors only."""

    def test_passes_with_initiate_work(self, connector_src):
        path = connector_src(
            ("src/main.py", _WITH_INITIATE_WORK),
            connector_type="EXTERNAL_IMPORT",
        )
        results = run_checks(path, select=["VC315"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_fails_without_initiate_work(self, connector_src):
        path = connector_src(
            ("src/main.py", _WITHOUT_INITIATE_WORK),
            connector_type="EXTERNAL_IMPORT",
        )
        results = run_checks(path, select=["VC315"])
        assert any(r.severity == Severity.ERROR for r in results)

    def test_passes_when_in_helper_function(self, connector_src):
        """initiate_work in any function of any file is enough."""
        path = connector_src(
            ("src/utils.py", _INITIATE_WORK_IN_HELPER),
            connector_type="EXTERNAL_IMPORT",
        )
        results = run_checks(path, select=["VC315"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_skipped_for_stream_connector(self, connector_src):
        """VC315 is EXTERNAL_IMPORT-only — stream connectors skip it."""
        path = connector_src(
            ("src/main.py", _WITHOUT_INITIATE_WORK),
            connector_type="STREAM",
        )
        results = run_checks(path, select=["VC315"])
        # No findings at all (check is skipped for other types)
        assert len(results) == 0

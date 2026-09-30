"""Unit tests for VC316 — connector must close work with to_processed."""

from connector_linter.models import Severity
from connector_linter.runner import run_checks

_WITH_TO_PROCESSED_AND_ERROR = """\
class Connector:
    def process(self, work_id):
        try:
            self._do_work()
            self.helper.api.work.to_processed(work_id, "Done")
        except Exception as e:
            self.helper.api.work.to_processed(work_id, str(e), in_error=True)
"""

_WITH_TO_PROCESSED_NO_IN_ERROR = """\
class Connector:
    def process(self, work_id):
        self._do_work()
        self.helper.api.work.to_processed(work_id, "Done")
"""

_WITHOUT_TO_PROCESSED = """\
class Connector:
    def process(self):
        self._do_work()
"""


class TestVC316WorkClosed:
    """VC316 checks that work is closed with to_processed (EXTERNAL_IMPORT only)."""

    def test_passes_with_to_processed_and_in_error(self, connector_src):
        path = connector_src(
            ("src/main.py", _WITH_TO_PROCESSED_AND_ERROR),
            connector_type="EXTERNAL_IMPORT",
        )
        results = run_checks(path, select=["VC316"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_warns_missing_in_error_kwarg(self, connector_src):
        """to_processed exists but without in_error= — advisory WARNING (passed=True)."""
        path = connector_src(
            ("src/main.py", _WITH_TO_PROCESSED_NO_IN_ERROR),
            connector_type="EXTERNAL_IMPORT",
        )
        results = run_checks(path, select=["VC316"])
        # WARNINGs are advisory: passed=True; detect by severity + suggestion
        advisories = [
            r
            for r in results
            if r.severity == Severity.WARNING and r.suggestion is not None
        ]
        assert len(advisories) >= 1

    def test_fails_without_to_processed(self, connector_src):
        path = connector_src(
            ("src/main.py", _WITHOUT_TO_PROCESSED),
            connector_type="EXTERNAL_IMPORT",
        )
        results = run_checks(path, select=["VC316"])
        assert any(r.severity == Severity.ERROR for r in results)

    def test_skipped_for_stream_connector(self, connector_src):
        """VC316 only applies to EXTERNAL_IMPORT."""
        path = connector_src(
            ("src/main.py", _WITHOUT_TO_PROCESSED),
            connector_type="STREAM",
        )
        results = run_checks(path, select=["VC316"])
        assert len(results) == 0

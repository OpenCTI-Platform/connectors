"""Unit tests for VC318 — enrichment connectors must use helper.listen()."""

from connector_linter.models import Severity
from connector_linter.runner import run_checks

_WITH_LISTEN = """\
class MyConnector:
    def run(self):
        self.helper.listen(message_callback=self.process_message)
"""

_WITHOUT_LISTEN = """\
class MyConnector:
    def run(self):
        while True:
            self.process()
"""

_BARE_HELPER_LISTEN = """\
def run(helper):
    helper.listen(message_callback=process)
"""


class TestVC318HelperListen:
    """VC318 is scoped to INTERNAL_ENRICHMENT only."""

    def test_passes_when_listen_present(self, connector_src):
        path = connector_src(
            ("src/main.py", _WITH_LISTEN),
            connector_type="INTERNAL_ENRICHMENT",
        )
        results = run_checks(path, select=["VC318"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_flags_when_listen_missing(self, connector_src):
        path = connector_src(
            ("src/main.py", _WITHOUT_LISTEN),
            connector_type="INTERNAL_ENRICHMENT",
        )
        results = run_checks(path, select=["VC318"])
        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 1

    def test_skipped_for_external_import(self, connector_src):
        """VC318 does not apply to EXTERNAL_IMPORT connectors."""
        path = connector_src(
            ("src/main.py", _WITHOUT_LISTEN),
            connector_type="EXTERNAL_IMPORT",
        )
        results = run_checks(path, select=["VC318"])
        # Scoped check — should produce no results for wrong type
        assert len(results) == 0

    def test_skipped_for_stream(self, connector_src):
        path = connector_src(
            ("src/main.py", _WITHOUT_LISTEN),
            connector_type="STREAM",
        )
        results = run_checks(path, select=["VC318"])
        assert len(results) == 0

    def test_bare_helper_listen_accepted(self, connector_src):
        """helper.listen(...) without self. qualifier is also valid."""
        path = connector_src(
            ("src/main.py", _BARE_HELPER_LISTEN),
            connector_type="INTERNAL_ENRICHMENT",
        )
        results = run_checks(path, select=["VC318"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_unrelated_listen_not_matched(self, connector_src):
        """socket.listen() or other .listen() calls must not trigger VC318."""
        src = """\
import socket
s = socket.socket()
s.listen(5)
"""
        path = connector_src(
            ("src/main.py", src),
            connector_type="INTERNAL_ENRICHMENT",
        )
        results = run_checks(path, select=["VC318"])
        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 1  # no helper.listen → still flagged

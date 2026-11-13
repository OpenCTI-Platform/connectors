"""Unit tests for VC314 — external-import connectors must use a scheduler."""

from connector_linter.models import Severity
from connector_linter.runner import run_checks

_WITH_SCHEDULE_ISO = """\
class Connector:
    def run(self):
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
"""

_WITH_WHILE_TRUE = """\
import time

class Connector:
    def run(self):
        while True:
            self.process_message()
            time.sleep(60)
"""

_WITHOUT_SCHEDULER = """\
class Connector:
    def run(self):
        self.process_message()
"""

_SDK_MAIN = """\
from connectors_sdk import ExternalImportConnector as TemplateConnector

if __name__ == "__main__":
    TemplateConnector(settings=settings, state=state, data_processors=[]).start()
"""

_PAGINATED_CLIENT = """\
class Client:
    def get_all(self):
        while True:
            page = self._get_page()
            if not page:
                break
"""


class TestVC314AutoBackpressure:
    """VC314 applies to EXTERNAL_IMPORT connectors only."""

    def test_passes_with_schedule_iso(self, connector_src):
        path = connector_src(("src/main.py", _WITH_SCHEDULE_ISO))
        results = run_checks(path, select=["VC314"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_fails_with_while_true(self, connector_src):
        path = connector_src(("src/main.py", _WITH_WHILE_TRUE))
        results = run_checks(path, select=["VC314"])
        assert any(
            r.severity == Severity.ERROR and "while True" in r.message for r in results
        )

    def test_fails_without_scheduler(self, connector_src):
        path = connector_src(("src/main.py", _WITHOUT_SCHEDULER))
        results = run_checks(path, select=["VC314"])
        assert any(r.severity == Severity.ERROR for r in results)

    def test_passes_with_sdk_external_import_connector(self, connector_src):
        """The SDK base connector schedules runs, even with a paginated client."""
        path = connector_src(
            ("src/main.py", _SDK_MAIN),
            ("src/client.py", _PAGINATED_CLIENT),
        )
        results = run_checks(path, select=["VC314"])
        assert all(r.severity == Severity.INFO for r in results)
        assert any("connectors-sdk" in r.message for r in results)

    def test_skipped_for_stream_connector(self, connector_src):
        path = connector_src(
            ("src/main.py", _WITHOUT_SCHEDULER),
            connector_type="STREAM",
        )
        results = run_checks(path, select=["VC314"])
        assert len(results) == 0

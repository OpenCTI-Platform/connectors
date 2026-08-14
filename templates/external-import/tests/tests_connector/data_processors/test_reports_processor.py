"""Tests for `ReportsProcessor`, checking the generic `BaseDataProcessor`
contract every processor in this project must follow -- see
`connectors_sdk.connectors.external_import.base_data_processor.BaseDataProcessor`.

Notes:
    - These tests are generic and can be applied to any `BaseDataProcessor` subclass.
    They check the `BaseDataProcessor` contract, but the `ReportsProcessor` class
    itself is not tested for its specific behavior or use cases.

TODO:
    - [ ] Test specific behaviors and/or use cases
"""

from unittest.mock import MagicMock

from connector.data_processors.reports_processor import ReportsProcessor
from connector.state import ConnectorState
from connectors_sdk import BaseDataProcessor


def test_reports_processor_implements_base_data_processor_contract():
    """
    `ReportsProcessor` must use `BaseDataProcessor` contract. The class
    only becomes concrete once both `collect` and `transform` are implemented.
    """
    assert issubclass(ReportsProcessor, BaseDataProcessor)
    ReportsProcessor()  # should not raise (proof that `collect` and `transform` are implemented)


def test_reports_processor_implemented_methods_return_expected_value(
    connector_settings, fake_logger
):
    """
    Test that `collect()` and `transform()` follow the `BaseDataProcessor` contract
    (`BaseDataProcessor.process()` always runs `send(transform(collect()))`).
    """

    class DummyClient:
        """Dummy client that simulates fetching reports from an external API."""

        def get_reports(self, params=None):
            return []

    class DummyReportsProcessor(ReportsProcessor):
        """A dummy implementation of `ReportsProcessor` for testing purposes."""

        def inject_dependencies(self):
            """Fake dependencies to isolate the processor's behavior."""
            self.settings = connector_settings
            self.state = ConnectorState()
            self.work_manager = MagicMock()
            self.logger = fake_logger

        def post_init(self):
            """Override `post_init` to use the dummy client instead of a real API client."""
            super().post_init()
            self.client = DummyClient()

    # Given: an instance of ReportsProcessor fully initialized
    processor = DummyReportsProcessor()
    processor.inject_dependencies()
    processor.post_init()

    # When: the full processing pipeline is executed
    # Then: it should not raise any exceptions, proving that `collect` and `transform` are implemented correctly
    processor.process()

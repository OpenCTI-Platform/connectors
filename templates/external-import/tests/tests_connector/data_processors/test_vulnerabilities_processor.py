"""Tests for `VulnerabilitiesProcessor`, checking the generic
`BaseDataProcessor` contract every processor in this project must follow --
see `connectors_sdk.connectors.external_import.base_data_processor.BaseDataProcessor`.

Notes:
    - These tests are generic and can be applied to any `BaseDataProcessor` subclass.
    They check the `BaseDataProcessor` contract, but the `VulnerabilitiesProcessor` class
    itself is not tested for its specific behavior or use cases.

TODO:
    - [ ] Test specific behaviors and/or use cases
"""

from unittest.mock import MagicMock

from connector.data_processors.vulnerabilities_processor import (
    VulnerabilitiesProcessor,
)
from connector.state import ConnectorState
from connectors_sdk import ApiClientError, BaseDataProcessor
from template_client.models import CVE


def test_vulnerabilities_processor_implements_base_data_processor_contract():
    """
    `VulnerabilitiesProcessor` must use `BaseDataProcessor` contract. The class
    only becomes concrete once both `collect` and `transform` are implemented.
    """
    assert issubclass(VulnerabilitiesProcessor, BaseDataProcessor)
    VulnerabilitiesProcessor()  # should not raise (proof that `collect` and `transform` are implemented)


def test_vulnerabilities_processor_implemented_methods_return_expected_value(
    connector_settings, fake_logger
):
    """
    Test that `collect()` and `transform()` follow the `BaseDataProcessor` contract
    (`BaseDataProcessor.process()` always runs `send(transform(collect()))`).
    """

    class DummyClient:
        """Dummy client that simulates fetching CVEs from an external API."""

        def iter_cves(self, params=None):
            yield from []

    class DummyVulnerabilitiesProcessor(VulnerabilitiesProcessor):
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

    # Given: an instance of VulnerabilitiesProcessor fully initialized
    processor = DummyVulnerabilitiesProcessor()
    processor.inject_dependencies()
    processor.post_init()

    # When: the full processing pipeline is executed
    # Then: it should not raise any exceptions, proving that `collect` and `transform` are implemented correctly
    processor.process()


def test_vulnerabilities_processor_keeps_the_last_page_when_an_error_stops_the_import(
    connector_settings,
):
    """
    Test that an error while fetching the CVE pages is logged, and that the state keeps
    the last completed page, so that the next run resumes from it.
    """

    class DummyVulnerabilitiesProcessor(VulnerabilitiesProcessor):
        def inject_dependencies(self):
            """Fake dependencies, with a mock logger to check what is logged."""
            self.settings = connector_settings
            self.state = ConnectorState()
            self.work_manager = MagicMock()
            self.logger = MagicMock()

    def cves_pages():
        """One page of CVEs, then an API error."""
        yield [
            CVE(
                cveId="CVE-2026-0001",
                name="Example vulnerability",
                cvssVector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvssScore="9",
            )
        ]
        raise ApiClientError("Server error", status_code=500)

    # Given: a processor whose API fails after the first page of CVEs
    processor = DummyVulnerabilitiesProcessor()
    processor.inject_dependencies()
    processor.post_init()

    # When: the CVE pages are converted
    stix_pages = list(processor.transform(cves_pages()))

    # Then: the first page is converted, the error is logged with its traceback,
    # and the state keeps the last completed page
    assert len(stix_pages) == 1
    processor.logger.exception.assert_called_once()
    assert processor.state.vulnerabilities_current_page == 1

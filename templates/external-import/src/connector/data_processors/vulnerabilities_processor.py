"""EXAMPLE processor -- importing a large/unbounded, paginated data type.

.. important::
    `VulnerabilitiesProcessor` below is a **worked example**, not a
    processor to keep as-is. "CVEs" and the fictional `TemplateClient.iter_cves`
    endpoint it calls do not correspond to any real data source -- they exist
    purely to demonstrate the standard shape of a processor for a data type
    that can be large or unbounded. See `reports_processor.py` for the simpler,
    non-paginated alternative, used when a data type comfortably fits in memory in a single call.

What this example demonstrates, on top of the general processor pattern
(see `reports_processor.py` for the basics):
    - Fetching data page by page (`collect` returns a generator), so a
      very large import never has to hold every item in memory at once.
    - Resuming from a specific page if a previous run was interrupted
      partway through (e.g. by a network error), instead of restarting the
      whole import from scratch.

TODO:
    - [ ] Copy this file as a starting point for any of your own data
        types that can return a large or unbounded number of items, then
        delete this example once no longer needed as a reference.
    - [ ] Register your new processor in `connector/data_processors/__init__.py`
        and in `src/main.py`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Generator

from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import OrganizationAuthor, TLPMarking, Vulnerability
from template_client import TemplateClient

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from connector.state import ConnectorState
    from connectors_sdk.models import BaseIdentifiedObject
    from template_client.models import CVE


class CVEConversionError(Exception):
    """Raised when a single raw CVE cannot be converted to STIX."""

    pass


class VulnerabilitiesProcessor(BaseDataProcessor):
    """EXAMPLE processor -- fetches and converts a large, paginated data type.

    "CVEs" is a stand-in entity type used only to illustrate the paginated
    processor pattern, for data types that can be large or unbounded. Copy
    this file's structure for your own connector's high-volume data types,
    and rename everything (class name, file name, exception, fields) to
    match.

    Attributes:
        settings: The connector's configuration, injected the same way as in `ReportsProcessor`.
        state: The connector's persisted state, injected the same way as in `ReportsProcessor`.

    Notes:
        See `ReportsProcessor` for why this class only defines
        `post_init`/`collect`/`transform` (`process()`/`send()`
        are inherited from `BaseDataProcessor`, never overridden here).
        This processor's `transform` additionally *yields* STIX objects
        page by page instead of returning one list: the inherited
        `send()` detects a generator and sends each yielded page as its
        own bundle, so a single very large import never has to be held
        entirely in memory before being sent.

        Rename this class (and this file) to match the entity type you
        import.
    """

    settings: ConnectorSettings
    state: ConnectorState

    work_name = "Vulnerabilities import"

    def post_init(self):
        """Build the API client and the STIX objects shared by every CVE."""
        self.client = TemplateClient(
            api_key=self.settings.template.api_key.get_secret_value(),
            logger=self.logger,  # Pass the logger to the client for logging purposes
        )

        self.author = OrganizationAuthor(
            name="Template Connector",
            description="Template Connector for External Import",
        )
        self.tlp_marking = TLPMarking(level=self.settings.template.tlp_level)

    def collect(self) -> Generator[list[CVE], None, None]:
        """Fetch raw CVEs from the external API, page by page.

        Returns:
            Generator[list[CVE], None, None]: One page of raw CVEs at a
            time, as returned by `TemplateClient.iter_cves`.

        Notes:
            Resume logic: if `state.vulnerabilities_current_page` is set
            (a previous run was interrupted), fetching resumes from that
            page instead of starting over from page 1. The `since` filter
            follows the same fallback chain as
            `ReportsProcessor.collect`. Adapt both to whatever filter/
            pagination parameters your real API's endpoint supports (page
            number, offset, or an opaque cursor/next-token).
        """
        if self.state.last_run:
            params = {
                "since": self.state.last_run,
                "start_page": self.state.vulnerabilities_current_page or 1,
            }
        else:
            params = {
                "since": self.settings.template.import_since,
                "start_page": 1,
            }

        return self.client.iter_cves(params=params)

    def transform(
        self, cves_pages: Generator[list[CVE], None, None]
    ) -> Generator[list[BaseIdentifiedObject], None, None]:
        """Convert raw CVE pages into STIX objects and checkpoint progress.

        Args:
            cves_pages: The pages of raw CVEs returned by `collect`.

        Yields:
            list[BaseIdentifiedObject]: The STIX objects for one page (the
            shared author/marking, plus one `Vulnerability` per
            successfully converted CVE).

        Notes:
            - Conversion errors on individual CVEs are logged and skipped
              (see `CVEConversionError`), the same way
              `ReportsProcessor.transform` handles them.
            - The page checkpoint (`state.vulnerabilities_current_page`)
              is cleared (set to `None`) once every page has been
              processed successfully, and set to the last completed page
              number if an error interrupts the loop -- so the next run
              resumes instead of re-importing everything from scratch.
              Apply the same checkpoint-on-failure approach to your own
              data type, whatever form its resume marker takes (page
              number, offset, cursor/token...).
        """
        current_page = 0

        try:
            for cves_page in cves_pages:
                stix_objects: list[BaseIdentifiedObject] = []

                for cve in cves_page:
                    try:
                        stix_objects.append(self._convert_cve(cve))
                    except CVEConversionError as e:
                        self.logger.warning(
                            "Failed to convert CVE, skipping it",
                            {"cve_id": cve.cveId, "error": str(e)},
                        )

                if stix_objects:
                    yield [self.author, self.tlp_marking] + stix_objects
                    current_page += 1

            # Checkpoint: clear the resume page once every page has been processed.
            self.state.vulnerabilities_current_page = None

        except Exception as e:
            # Checkpoint: keep the last completed page so the next run resumes here
            # instead of re-importing everything from scratch.
            self.logger.error(
                "An error occurred while processing CVE pages. Saving the current page to resume on next run.",
                {"error": str(e)},
            )
            self.state.vulnerabilities_current_page = current_page

    def _convert_cve(self, cve: CVE) -> Vulnerability:
        """Convert a single raw CVE into a STIX `Vulnerability` object.

        Args:
            cve: One raw CVE, already validated against the `CVE` model.

        Returns:
            Vulnerability: The corresponding STIX 2.1 `Vulnerability`
            object.

        Raises:
            CVEConversionError: If the conversion fails for any reason.

        Notes:
            This is a minimal example mapping only a handful of fields. See
            `ReportsProcessor._convert_report` for the general checklist
            to follow when implementing your own `_convert_*` method
            (mapping every relevant field, adding related STIX objects/
            relationships, reusing `connectors-sdk` STIX models).
        """
        try:
            return Vulnerability(
                name=cve.name,
                cvss_v3_vector_string=cve.cvssVector,
                score=int(cve.cvssScore),
                author=self.author,
                markings=[self.tlp_marking],
            )
        except Exception as e:
            raise CVEConversionError(f"Failed to convert CVE: {str(e)}") from e

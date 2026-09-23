"""EXAMPLE processor -- importing a small, non-paginated data type.

.. important::
    `ReportsProcessor` below is a **worked example**, not a processor to
    keep as-is. "Reports" and the fictional `TemplateClient.get_reports`
    endpoint it calls do not correspond to any real data source -- they
    exist purely to demonstrate the standard shape of a processor for a
    data type small enough to fetch in a single call. See
    `vulnerabilities_processor.py` for the paginated alternative, used
    when a data type can be large or unbounded.

What is a "processor", and why does this template use several of them?
    A processor is a self-contained unit responsible for **one data
    type**: it knows how to fetch its own raw data (`collect`) and how
    to turn it into STIX objects (`transform`). `connectors-sdk`'s
    `BaseDataProcessor` calls these two methods for you on every
    connector run, and takes care of building/sending the resulting STIX
    bundle to OpenCTI. Splitting a connector into one processor per data
    type (instead of one big monolithic import function) makes each piece
    easier to read, test, and enable/disable independently (see the
    `import_reports`/`import_vulnerabilities` feature flags in
    `connector/settings.py`).

TODO:
    - [ ] Copy this file as a starting point for each real data type your
        connector imports (one processor per data type is the expected pattern),
        then delete this example once no longer needed as a reference.
    - [ ] Register your new processor in `connector/data_processors/__init__.py`
        and in `src/main.py`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import (
    BaseIdentifiedObject,
    OrganizationAuthor,
    Report,
    TLPMarking,
)
from template_client import TemplateClient

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from connector.state import ConnectorState
    from template_client.models import Report as TemplateReport


class ReportConversionError(Exception):
    """Raised when a single raw report cannot be converted to STIX."""

    pass


class ReportsProcessor(BaseDataProcessor):
    """EXAMPLE processor -- fetches and converts a small, non-paginated data type.

    "Reports" is a stand-in entity type used only to illustrate the
    processor pattern for data small enough to fetch in a single API call.
    Copy this file's structure for your own connector's data types, and
    rename everything (class name, file name, exception, fields) to match.

    Attributes:
        settings: The connector's configuration. Not created here:
            `BaseDataProcessor.inject_dependencies()` sets it for every processor
            before `post_init` runs.
        state: The connector's persisted state, injected the same way as `settings`.

    Notes:
        This class only defines `post_init`/`collect`/`transform` --
        it never defines `process()` or `send()` because
        `BaseDataProcessor` already provides them and calls this class'
        methods automatically, in this order, on every connector run:
            1. `post_init`: build anything the processor needs (API
               client, shared STIX objects such as the author/marking).
            2. `collect`: fetch raw data from the external source,
               resuming from the last checkpoint if there is one.
            3. `transform`: convert the raw data into STIX objects,
               skipping (not failing the whole run on) individual
               conversion errors, and update the checkpoint for the next
               run. Its return value is handed to the inherited `send()`,
               which builds the bundle and delivers it to OpenCTI -- you
               never call `send()` yourself.
    """

    settings: ConnectorSettings
    state: ConnectorState

    work_name = "Reports import"

    def post_init(self):
        """Build the API client and the STIX objects shared by every report.

        Notes:
            The `author`/`tlp_marking` objects are created once here and
            reused for every report, instead of being recreated per item.
        """
        self.client = TemplateClient(
            api_key=self.settings.template.api_key.get_secret_value(),
            logger=self.logger,  # Pass the logger to the client for logging purposes
        )

        self.author = OrganizationAuthor(
            name="Template Connector",
            description="Template Connector for External Import",
        )
        self.tlp_marking = TLPMarking(level=self.settings.template.tlp_level)

    def collect(self) -> list[TemplateReport]:
        """Fetch raw reports from the external API.

        Returns:
            list[TemplateReport]: The raw reports to convert, as returned
            by `TemplateClient.get_reports`.

        Notes:
            Resume logic: use this processor's own checkpoint
            (`state.last_report_update`) first, since it is the most
            precise; fall back to the connector-wide `state.last_run`,
            and finally to `settings.template.import_since` on a
            connector's very first run (when neither checkpoint exists
            yet). Adapt this fallback chain to whatever filter parameter(s)
            your real API's endpoint actually supports.
        """
        if self.state.last_run:
            params = {
                "updatedAfter": self.state.last_report_update or self.state.last_run
            }
        else:
            params = {
                "updatedAfter": self.settings.template.import_since,
            }

        return self.client.get_reports(params=params)

    def transform(self, reports: list[TemplateReport]):
        """Convert raw reports into STIX objects and checkpoint progress.

        Args:
            reports: The raw reports returned by `collect`.

        Returns:
            list[BaseIdentifiedObject] | None: The STIX objects to include
            in this run's bundle (the shared author/marking, plus one
            `Report` per successfully converted item), or `None` if
            there was nothing to send.

        Notes:
            Conversion errors on individual reports are logged and skipped
            (see `ReportConversionError`) rather than failing the entire
            run -- one malformed item should not block every other report.
            The checkpoint (`state.last_report_update`) is only updated
            from the last *successfully* converted report. Apply the same
            "skip and checkpoint" approach to your own entity type,
            replacing `last_report_update` with whatever checkpoint(s)
            make sense for it (see `connector/state.py`).
        """
        stix_objects: list[BaseIdentifiedObject] = []

        last_report = None
        for report in reports:
            try:
                stix_objects.append(self._convert_report(report))
                last_report = report
            except ReportConversionError as e:
                self.logger.warning(
                    "Failed to convert report, skipping it",
                    {"report_id": report.id if report else "unknown", "error": str(e)},
                )

        if stix_objects:
            try:
                return [self.author, self.tlp_marking] + stix_objects
            finally:
                # Checkpoint: remember the last processed report so the next run only
                # fetches reports updated after this point.
                if last_report:
                    self.state.last_report_update = last_report.updatedAt

    def _convert_report(self, report: TemplateReport) -> Report:
        """Convert a single raw report into a STIX `Report` object.

        Args:
            report: One raw report, already validated against the
                `TemplateReport` model.

        Returns:
            Report: The corresponding STIX 2.1 `Report` object.

        Raises:
            ReportConversionError: If the conversion fails for any reason
                (missing/invalid field, etc.). Wrapping the original
                exception keeps the original traceback while giving
                `transform` a single, specific exception type to catch.

        Notes:
            This is a minimal example mapping only a handful of fields.
            When implementing your own `_convert_*` method:
                - [ ] Map every relevant field from your raw model to the
                  matching STIX object and/or related objects: labels,
                  external references, objects it refers to,
                  relationships...
                - [ ] Add any additional STIX objects this entity should
                  produce (e.g. indicators mentioned in a report) and
                  return/append them alongside the main object.
                - [ ] Reuse `connectors-sdk` STIX models wherever
                  possible instead of building raw `stix2` objects, so
                  deterministic ID generation is handled for you.
        """
        try:
            return Report(
                name=report.title,
                publication_date=report.publishedAt,
                author=self.author,
                markings=[self.tlp_marking],
            )
        except Exception as e:
            raise ReportConversionError(f"Failed to convert report: {str(e)}") from e

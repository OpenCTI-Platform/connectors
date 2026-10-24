"""Import Rösti reports, with their IOCs, YARA rules, MITRE IDs and CVEs.

Each run asks the API for reports created or updated since the last
checkpoint (oldest change first). The IOCs of a report are converted while
their pages arrive and sent in bundles of at most ``MAX_BUNDLE_OBJECTS``
objects; the report itself goes last, with references to all of them.

The checkpoint advances after every report, whether it was imported or
skipped:

- A report whose data cannot be read or converted is skipped with a warning,
  so it cannot block the reports after it. It is imported again when it
  changes in Rösti.
- When the API key's quota is used up, the run ends early and keeps the
  checkpoint, so the next run continues there.
- Any other API or network error fails the run (``DataRetrievalError``); the
  SDK then discards the run's checkpoint and the next run retries from the
  previous one.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Generator, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import requests
from connector.converter import UNSUPPORTED_IOC_TYPES, RostiConverter
from connector.yara_rules import prepare_yara_patterns
from connectors_sdk import BaseDataProcessor
from connectors_sdk.client.exceptions import ApiClientError
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.models import BaseIdentifiedEntity, Reference
from pycti import Malware as PyctiMalware
from pycti import Tool as PyctiTool
from pydantic import ValidationError
from rosti_client import RostiClient
from rosti_client.api_client import quota_exceeded
from rosti_client.models import IOC, Mitre, Report, ReportBundle, Yara

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from connector.state import ConnectorState
    from pycti import OpenCTIConnectorHelper

# Rösti report timestamps have one-second resolution: query one second
# earlier than the checkpoint and skip the reports already sent.
CHECKPOINT_OVERLAP = dt.timedelta(seconds=1)

# Largest number of IOC objects per bundle. The repository's guidance is to
# keep bundles under about 10,000 objects; one IOC group adds a few objects
# at most, and the last bundle of a report adds YARA, MITRE, CVEs and the report.
MAX_BUNDLE_OBJECTS = 5000

# Errors of the Rösti API (after the client's retries) or of the network.
# They fail the run instead of skipping a report: the data is not wrong, it
# could not be fetched, and the next run may succeed.
API_ERRORS = (ApiClientError, requests.RequestException)


@dataclass
class ReportData:
    """One report as collected; its IOC groups are fetched page by page."""

    report: Report
    # `last_updated` of the report in the list response, used as checkpoint.
    listed_last_updated: dt.datetime | None
    # Lazy: IOC pages are requested while the groups are converted.
    ioc_groups: Iterable[list[IOC]] = field(default_factory=list)
    yara_rules: list[Yara] = field(default_factory=list)


@dataclass
class UnreadableReport:
    """A listed report whose details the API returned in an unexpected form."""

    report_id: str
    listed_last_updated: dt.datetime | None
    error: str


class ReportsProcessor(BaseDataProcessor):
    """Fetch updated reports from Rösti and convert them to STIX."""

    work_name = "Rösti reports import"
    settings: ConnectorSettings
    state: ConnectorState

    def __init__(self, client: RostiClient | None = None) -> None:
        self.client = client
        self.helper: OpenCTIConnectorHelper | None = None
        self.converter: RostiConverter | None = None
        self._software_cache: dict[str, Reference | None] = {}

    def inject_dependencies(self, settings, helper, state) -> None:
        super().inject_dependencies(settings, helper, state)
        self.helper = helper

    def post_init(self) -> None:
        config = self.settings.rosti
        if self.client is None:
            self.client = RostiClient(
                api_key=config.api_key.get_secret_value(),
                base_url=config.api_base_url,
            )
        self.converter = RostiConverter(
            tlp_level=config.tlp_level,
            default_score=config.default_score,
            software_resolver=self._resolve_software,
            replace_report_objects=config.replace_report_objects,
        )

    # ------------------------------------------------------------------
    # MITRE software lookup
    # ------------------------------------------------------------------

    def _resolve_software(self, entry: Mitre) -> Reference | None:
        """Find the Malware or Tool for a MITRE ATT&CK software entry in OpenCTI.

        ATT&CK "software" is either malware or a tool, and the Rösti API does
        not say which. OpenCTI identifies both by name, so the connector
        computes the Malware ID and the Tool ID for the entry's name and links
        whichever already exists (normally created by OpenCTI's MITRE ATT&CK
        connector). This avoids creating a duplicate of the wrong type.
        Returns None (no link) when neither exists.
        """
        if entry.id in self._software_cache:
            return self._software_cache[entry.id]
        reference = None
        if self.helper is not None:
            for candidate_id in (
                PyctiMalware.generate_id(entry.description),
                PyctiTool.generate_id(entry.description),
            ):
                try:
                    entity = self.helper.api.stix_domain_object.read(id=candidate_id)
                except Exception as e:  # pylint: disable=broad-exception-caught
                    self.logger.warning(
                        "MITRE software lookup failed",
                        meta={"mitre_id": entry.id, "error": str(e)},
                    )
                    break
                if entity:
                    reference = Reference(id=entity["standard_id"])
                    break
        if reference is None:
            self.logger.debug(
                "MITRE software not found in OpenCTI, not linked "
                "(is the MITRE ATT&CK connector running?)",
                meta={"mitre_id": entry.id, "name": entry.description},
            )
        self._software_cache[entry.id] = reference
        return reference

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def _query_start(self) -> dt.datetime:
        if self.state.last_report_updated is not None:
            return self.state.last_report_updated - CHECKPOINT_OVERLAP
        return self.settings.rosti.import_since

    def _already_sent(self, report_id: str, last_updated: dt.datetime | None) -> bool:
        checkpoint = self.state.last_report_updated
        if checkpoint is None or last_updated is None:
            return False
        if last_updated < checkpoint:
            return True
        return last_updated == checkpoint and report_id in (
            self.state.last_report_ids or []
        )

    def _collect_report(self, summary: Report) -> ReportData:
        """Fetch the details and YARA rules of a listed report."""
        config = self.settings.rosti
        report = self.client.get_report(summary.id)
        yara_rules = (
            self.client.get_report_yara_rules(report.id)
            if config.import_yara
            and report.count.yara_rules > 0
            and not report.hide_yara
            else []
        )
        ioc_groups = (
            self.client.iter_report_ioc_groups(report.id)
            if config.import_iocs and report.count.iocs > 0
            else []
        )
        return ReportData(
            report=report,
            listed_last_updated=summary.last_updated,
            ioc_groups=ioc_groups,
            yara_rules=yara_rules,
        )

    def collect(self) -> Generator[ReportData | UnreadableReport, None, None]:
        """Yield every new or updated report with its YARA rules and IOC groups.

        The IOC groups are a generator: their pages are only requested while
        ``transform`` converts them, so a large report is never held in memory.
        A report whose details do not match the expected data model is
        yielded as ``UnreadableReport``, for ``transform`` to skip.
        """
        # MITRE software may have been added to OpenCTI since the last run.
        self._software_cache = {}
        since = self._query_start()
        self.logger.info(
            "Fetching Rösti reports updated since", meta={"since": since.isoformat()}
        )

        for page in self.client.iter_updated_reports(since):
            for summary in page:
                if self._already_sent(summary.id, summary.last_updated):
                    continue
                try:
                    item = self._collect_report(summary)
                except ValidationError as e:
                    item = UnreadableReport(summary.id, summary.last_updated, str(e))
                yield item

    # ------------------------------------------------------------------
    # Transform
    # ------------------------------------------------------------------

    def _keep_ioc(self, ioc) -> bool:
        config = self.settings.rosti
        if config.ioc_types and ioc.type not in config.ioc_types:
            return False
        if config.ids_only and not ioc.ids:
            return False
        if ioc.risk is not None and ioc.risk.level > config.max_risk_level:
            return False
        return True

    def _iter_ioc_objects(
        self, bundle: ReportData | ReportBundle
    ) -> Generator[list[Any], None, None]:
        """Convert the IOCs of a report group by group (entity_ref groups combined)."""
        report = bundle.report
        skipped: dict[str, int] = {}
        combined: dict[str, int] = {}
        seen_refs: set[str] = set()
        for group in bundle.ioc_groups:
            entity_ref = group[0].entity_ref
            if entity_ref:
                if entity_ref in seen_refs:
                    self.logger.warning(
                        "IOCs of one entity_ref are not next to each other in the "
                        "API response, they are combined in parts",
                        meta={"report_id": report.id, "entity_ref": entity_ref},
                    )
                seen_refs.add(entity_ref)
            kept = [ioc for ioc in group if self._keep_ioc(ioc)]
            if not kept:
                continue
            result = self.converter.convert_ioc_group(kept)
            for ioc, reason in result.skipped:
                skipped[ioc.type] = skipped.get(ioc.type, 0) + 1
                # Types that are never imported (e.g. a bare port) are expected.
                log = (
                    self.logger.debug
                    if ioc.type in UNSUPPORTED_IOC_TYPES
                    else self.logger.warning
                )
                log(
                    "IOC skipped",
                    meta={
                        "report_id": report.id,
                        "ioc_id": ioc.id,
                        "type": ioc.type,
                        "value": ioc.value,
                        "reason": reason,
                    },
                )
            for warning in result.warnings:
                self.logger.warning(
                    "IOC group not combined",
                    meta={"report_id": report.id, "reason": warning},
                )
            for kind in result.combined:
                combined[kind] = combined.get(kind, 0) + 1
            if result.objects:
                yield result.objects
        if skipped:
            self.logger.info(
                "IOCs not imported", meta={"report_id": report.id, "by_type": skipped}
            )
        if combined:
            self.logger.debug(
                "IOC groups combined", meta={"report_id": report.id, "groups": combined}
            )

    def _other_objects(
        self, bundle: ReportData | ReportBundle
    ) -> tuple[list[Any], list[BaseIdentifiedEntity | Reference]]:
        """YARA rules, MITRE entries and CVEs of a report, with their references."""
        config = self.settings.rosti
        report = bundle.report
        converter = self.converter
        objects: list[Any] = []
        refs: list[BaseIdentifiedEntity | Reference] = []

        accepted, rejected = prepare_yara_patterns(bundle.yara_rules)
        for skipped_rule in rejected:
            self.logger.warning(
                "YARA rule does not compile, not imported",
                meta={
                    "report_id": report.id,
                    "rule": skipped_rule.rule.name,
                    "error": skipped_rule.error,
                },
            )
        for item in accepted:
            indicator = converter.convert_yara(item.rule, report.date, item.pattern)
            objects.append(indicator)
            refs.append(Reference(id=indicator.id))

        if config.import_mitre:
            for entry in report.mitre_ids or []:
                entity = converter.convert_mitre(entry)
                if entity is None:
                    continue
                if isinstance(entity, BaseIdentifiedEntity):
                    objects.append(entity)
                refs.append(entity)

        if config.import_cve:
            for cve in report.cve or []:
                vulnerability = converter.convert_cve(cve)
                objects.append(vulnerability)
                refs.append(vulnerability)
        return objects, refs

    def convert_report_chunks(
        self, bundle: ReportData | ReportBundle
    ) -> Generator[list[Any], None, None]:
        """Convert one report into bundles of at most ``MAX_BUNDLE_OBJECTS`` IOC objects.

        Every bundle carries the author and the marking. The last one holds
        the YARA rules, MITRE entries, CVEs and the report, which references
        everything sent for it (including the earlier bundles).
        """
        converter = self.converter
        meta = [converter.author, converter.tlp_marking]
        refs: list[BaseIdentifiedEntity | Reference] = []
        chunk: list[Any] = []
        for objects in self._iter_ioc_objects(bundle):
            chunk.extend(objects)
            refs.extend(Reference(id=obj.id) for obj in objects)
            if len(chunk) >= MAX_BUNDLE_OBJECTS:
                yield [*meta, *chunk]
                chunk = []
        others, other_refs = self._other_objects(bundle)
        refs.extend(other_refs)
        stix_report = converter.convert_report(bundle.report, refs)
        yield [*meta, *chunk, *others, stix_report]

    def convert_bundle(self, bundle: ReportData | ReportBundle) -> list[Any]:
        """Convert one report into a single list of STIX objects (all chunks merged)."""
        converter = self.converter
        meta = [converter.author, converter.tlp_marking]
        objects: list[Any] = []
        for chunk in self.convert_report_chunks(bundle):
            objects.extend(chunk[len(meta) :])
        return [*meta, *objects]

    def _advance_checkpoint(
        self, report_id: str, last_updated: dt.datetime | None
    ) -> None:
        if last_updated is None:
            return
        if self.state.last_report_updated == last_updated:
            self.state.last_report_ids = [
                *(self.state.last_report_ids or []),
                report_id,
            ]
        elif (
            self.state.last_report_updated is None
            or last_updated > self.state.last_report_updated
        ):
            self.state.last_report_updated = last_updated
            self.state.last_report_ids = [report_id]

    def _skip_report(self, report_id: str, error: Exception | str, sent: int) -> None:
        self.logger.warning(
            "Failed to convert report, skipping it",
            meta={
                "report_id": report_id,
                "error": str(error),
                # Bundles of the report sent before the error stay in OpenCTI.
                "bundles_sent": sent,
            },
        )

    def _report_bundles(self, bundle: ReportData) -> Generator[list[Any], None, bool]:
        """Yield the bundles of one report; return False if it had to be skipped.

        Only the conversion is guarded, not the sending of the bundles (which
        happens in the SDK while this generator is suspended at ``yield``).
        API and network errors are raised; any other error skips the report.
        """
        chunks = self.convert_report_chunks(bundle)
        sent = 0
        while True:
            try:
                chunk = next(chunks)
            except StopIteration:
                return True
            except API_ERRORS:
                raise
            except Exception as e:  # pylint: disable=broad-exception-caught
                self._skip_report(bundle.report.id, e, sent)
                return False
            yield chunk
            sent += 1

    def transform(
        self, data: Generator[ReportData | UnreadableReport, None, None]
    ) -> Generator[list[Any], None, None]:
        """Yield the bundles of each report and move the checkpoint after each report.

        - A report that cannot be read or converted is skipped with a warning
          and the checkpoint moves past it, so it does not block the import.
        - A used-up quota ends the run quietly: the checkpoint of the reports
          handled so far is kept and the next run continues there.
        - Any other API or network error is raised as ``DataRetrievalError``:
          the run is marked as failed and its checkpoint is not saved.
        """
        sent = skipped = 0
        report_id = None
        try:
            for item in data:
                if isinstance(item, UnreadableReport):
                    report_id = item.report_id
                    self._skip_report(report_id, item.error, 0)
                    imported = False
                else:
                    report_id = item.report.id
                    imported = yield from self._report_bundles(item)
                # All bundles of the report have been sent once the generator resumes here.
                self._advance_checkpoint(report_id, item.listed_last_updated)
                if imported:
                    sent += 1
                else:
                    skipped += 1
                report_id = None
        except API_ERRORS as e:
            quota = quota_exceeded(e)
            if quota is None:
                # The client's message names the request, e.g. "on GET /reports/B".
                where = f" while importing report {report_id}" if report_id else ""
                raise DataRetrievalError(
                    f"Rösti API request failed{where}: {e}. Reports imported "
                    f"before the error: {sent}. The next run retries from the "
                    "last saved checkpoint."
                ) from e
            self.logger.warning(
                "Rösti API quota exceeded, the import continues from the last "
                "checkpoint on the first run after the quota resets",
                meta={
                    "detail": quota.get("detail") or quota.get("title"),
                    "reset": quota.get("reset"),
                    "reports_sent": sent,
                },
            )
        self.logger.info(
            "Rösti import finished",
            meta={"reports_sent": sent, "reports_skipped": skipped},
        )

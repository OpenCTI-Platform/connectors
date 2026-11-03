"""WhoisFreaks newly registered domains processor."""

from __future__ import annotations

from collections.abc import Generator, Iterable
from datetime import date, datetime, timedelta, timezone
from typing import Any

import stix2
from connector.author import AUTHOR_ID as _AUTHOR_ID
from connector.author import SHARED_AUTHOR as _SHARED_AUTHOR
from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import TLPMarking
from pycti import Indicator, Note, StixCoreRelationship
from whoisfreaks_client.nrd_client import (
    NRDRecord,
    WhoisFreaksNRDClient,
    WhoisFreaksNRDSubscriptionError,
)
from whoisfreaks_client.status import WhoisFreaksStatus

_TLP_MARKINGS = {
    "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red": stix2.TLP_RED,
}

_NRD_FEEDS = {
    "nrd_gtld_with_whois": {
        "feed_type": "gtld",
        "whois": True,
    },
    "nrd_cctld_with_whois": {
        "feed_type": "cctld",
        "whois": True,
    },
    "nrd_gtld_without_whois": {
        "feed_type": "gtld",
        "whois": False,
    },
    "nrd_cctld_without_whois": {
        "feed_type": "cctld",
        "whois": False,
    },
}

_MAX_BUNDLE_OBJECTS = 10_000
_WHOIS_FIELD_PREFIX = "x_whoisfreaks_"

# Preferred display order for WHOIS columns in description / note body.
# Any other columns present in the CSV are appended after these.
_WHOIS_COLUMN_ORDER = (
    "num",
    "domain_name",
    "query_time",
    "create_date",
    "update_date",
    "expiry_date",
    "domain_registrar_id",
    "domain_registrar_name",
    "domain_registrar_whois",
    "domain_registrar_url",
    "domain_registrar_email_address",
    "domain_registrar_phone",
    "domain_registrar_authoritative_registry_name",
    "registrant_id",
    "registrant_id_type",
    "registrant_handle",
    "registrant_name",
    "registrant_company",
    "registrant_address",
    "registrant_city",
    "registrant_state",
    "registrant_zip",
    "registrant_country_code",
    "registrant_country",
    "registrant_email",
    "registrant_phone",
    "registrant_fax",
    "administrative_id",
    "administrative_id_type",
    "administrative_handle",
    "administrative_name",
    "administrative_company",
    "administrative_address",
    "administrative_city",
    "administrative_state",
    "administrative_zip",
    "administrative_country_code",
    "administrative_country",
    "administrative_email",
    "administrative_phone",
    "administrative_fax",
    "technical_id",
    "technical_id_type",
    "technical_handle",
    "technical_name",
    "technical_company",
    "technical_address",
    "technical_city",
    "technical_state",
    "technical_zip",
    "technical_country_code",
    "technical_country",
    "technical_email",
    "technical_phone",
    "technical_fax",
    "billing_id",
    "billing_id_type",
    "billing_handle",
    "billing_name",
    "billing_company",
    "billing_address",
    "billing_city",
    "billing_state",
    "billing_zip",
    "billing_country_code",
    "billing_country",
    "billing_email",
    "billing_phone",
    "billing_fax",
    "eligibility_id",
    "eligibility_name",
    "eligibility_type",
    "name_server_1",
    "name_server_2",
    "name_server_3",
    "name_server_4",
    "domain_status_1",
    "domain_status_2",
    "domain_status_3",
    "domain_status_4",
    "reseller_name",
    "reseller_email",
    "reseller_phone",
)


class NRDProcessor(BaseDataProcessor):
    """Import one WhoisFreaks NRD feed with offset-resumable pagination.

    Day selection:
    ==============
    Only the status endpoint's ``last_update`` date is ingested. Historical
    multi-day backfill is disabled. ``WHOISFREAKS_IMPORT_SINCE`` is only a
    floor — if last_update is older than that date the feed is skipped.
    """

    def __init__(self, feed_name: str) -> None:
        if feed_name not in _NRD_FEEDS:
            raise ValueError(f"Unsupported NRD feed: {feed_name}")

        self.feed_name = feed_name
        self.feed_type = _NRD_FEEDS[feed_name]["feed_type"]
        self.whois = _NRD_FEEDS[feed_name]["whois"]
        self.work_name = f"WhoisFreaks {feed_name}"
        self.status: WhoisFreaksStatus | None = None
        # Set by transform() when a record of the current page fails
        # conversion; read by the collector before advancing checkpoints.
        self._page_conversion_failed = False

    def set_status(self, status: WhoisFreaksStatus) -> None:
        """Set the shared WhoisFreaks status snapshot."""
        self.status = status

    def post_init(self) -> None:
        config = self.settings.whoisfreaks

        self.client = WhoisFreaksNRDClient(
            api_key=config.api_key.get_secret_value(),
            base_url=str(config.nrd_base_url),
            timeout=config.nrd_timeout,
            max_retries=config.max_retries,
            retry_backoff_seconds=config.retry_backoff_seconds,
        )
        # Use the shared author object so both processors produce the same
        # identity description regardless of which one sends last.
        self._author = _SHARED_AUTHOR

    def collect(self) -> Iterable[list[NRDRecord]]:
        """Collect NRD pages for the latest available day (status last_update) only.

        Historical multi-day backfill is disabled. Only ``last_update`` from
        the status API is fetched. Mid-day offset checkpoints still allow
        resume if a single large day is interrupted.
        """
        config = self.settings.whoisfreaks

        if self.status is None:
            raise RuntimeError("WhoisFreaks status has not been initialized")

        feed_status = self.status.get_nrd_feed_status(self.feed_type)

        if not feed_status.is_available:
            self.logger.warning(
                "[NRD] Feed status reports no available data; skipping",
                meta={
                    "feed_name": self.feed_name,
                    "last_update": feed_status.last_update,
                },
            )
            return []

        latest_available_date = date.fromisoformat(feed_status.last_update)
        latest_iso = latest_available_date.isoformat()

        # NRD state stores the *next* calendar day after a successful day
        # (see set_next_nrd_date(feed_date + 1)). An empty value means never run.
        next_date_str = self.state.get_next_nrd_date(self.feed_name, "")
        start_offset = self.state.get_nrd_offset(self.feed_name)
        offset_date = self.state.get_nrd_offset_date(self.feed_name)

        import_floor = config.import_since.date()
        if latest_available_date < import_floor:
            self.logger.info(
                "[NRD] last_update is older than import_since; skipping",
                meta={
                    "feed_name": self.feed_name,
                    "last_update": latest_iso,
                    "import_since": import_floor.isoformat(),
                },
            )
            return []

        # Already finished last_update (next pointer is past it).
        if next_date_str:
            next_date = date.fromisoformat(next_date_str)
            if next_date > latest_available_date:
                self.logger.info(
                    "[NRD] Day already ingested; skipping",
                    meta={
                        "feed_name": self.feed_name,
                        "last_update": latest_iso,
                        "next_date": next_date_str,
                    },
                )
                return []
        # Reuse an offset only for the snapshot it was checkpointed against.
        if start_offset > 0 and offset_date != latest_iso:
            start_offset = 0

        self.logger.info(
            "[NRD] Fetching WhoisFreaks NRD feed (last_update only)",
            meta={
                "feed_name": self.feed_name,
                "feed_type": self.feed_type,
                "whois": self.whois,
                "date": latest_iso,
                "start_offset": start_offset,
                "page_limit": config.page_limit,
            },
        )

        return self._iter_with_checkpoint(
            feed_date=latest_available_date,
            start_offset=start_offset,
            page_limit=config.page_limit,
            checkpoint_every=config.checkpoint_every_pages,
        )

    def _iter_with_checkpoint(
        self,
        feed_date: date,
        start_offset: int,
        page_limit: int,
        checkpoint_every: int,
    ) -> Iterable[list[NRDRecord]]:
        """Yield pages and update the in-memory offset at checkpoint intervals.

        transform() consumes each page before this generator resumes, so a
        conversion failure in a page is known here. From the first failed page
        on, the offset checkpoint is frozen (it stays at or before that page)
        and the day is not marked complete, so the next run retries it.
        Valid records of later pages are still yielded and imported.
        """

        offset = start_offset
        pages_since_checkpoint = 0
        conversion_failed = False
        try:
            for page in self.client.iter_feed(
                feed_type=self.feed_type,
                whois=self.whois,
                feed_date=feed_date,
                limit=page_limit,
                start_offset=start_offset,
            ):
                self._page_conversion_failed = False
                yield page

                offset += getattr(page, "source_record_count", len(page))
                pages_since_checkpoint += 1

                if self._page_conversion_failed and not conversion_failed:
                    conversion_failed = True
                    self.logger.warning(
                        "[NRD] Conversion failures; checkpoint frozen",
                        meta={
                            "feed_name": self.feed_name,
                            "date": feed_date.isoformat(),
                            "page_end_offset": offset,
                        },
                    )

                if not conversion_failed and pages_since_checkpoint >= checkpoint_every:
                    self.state.set_nrd_offset(
                        self.feed_name,
                        offset,
                        snapshot_date=feed_date.isoformat(),
                    )
                    pages_since_checkpoint = 0
                    self.logger.debug(
                        "[NRD] Updated offset",
                        meta={
                            "feed_name": self.feed_name,
                            "offset": offset,
                            "date": feed_date.isoformat(),
                        },
                    )
        except WhoisFreaksNRDSubscriptionError as exc:
            self.logger.warning(
                "[NRD] Subscription error; feed skipped",
                meta={"feed_name": self.feed_name, "error": str(exc)},
            )
            return

        if conversion_failed:
            self.logger.warning(
                "[NRD] Feed day not marked complete; will retry next run",
                meta={"feed_name": self.feed_name, "date": feed_date.isoformat()},
            )
            return

        next_date = (feed_date + timedelta(days=1)).isoformat()
        self.state.set_next_nrd_date(self.feed_name, next_date)
        self.logger.info(
            "[NRD] Completed feed day",
            meta={
                "feed_name": self.feed_name,
                "date": feed_date.isoformat(),
                "next_date": next_date,
                "records_processed_from_offset": offset,
            },
        )

    def transform(
        self,
        data: Any,
    ) -> Generator[list[Any], None, None]:
        config = self.settings.whoisfreaks
        tlp = self._get_tlp_marking(config.tlp_level)
        create_indicators = config.create_indicators_for_nrd

        for page in data:
            objects: list[Any] = [self._author, tlp]

            for record in page:
                try:
                    record_objects = self._to_stix(
                        record,
                        tlp,
                        create_indicators=create_indicators,
                    )
                except Exception as err:
                    # Skip a single bad record; do not fail the whole page
                    # Conversion failures are handled per item, not per page.
                    self._page_conversion_failed = True
                    self.logger.warning(
                        "[NRD] Skipping record that failed conversion",
                        meta={
                            "feed_name": self.feed_name,
                            "domain": getattr(record, "domain_name", None),
                            "error": str(err),
                        },
                    )
                    continue

                if len(objects) + len(record_objects) > _MAX_BUNDLE_OBJECTS:
                    yield objects
                    objects = [self._author, tlp]
                objects.extend(record_objects)

            if len(objects) > 2:
                yield objects

    @staticmethod
    def _get_tlp_marking(value: Any) -> Any:
        raw = getattr(value, "value", value)
        key = str(raw).lower().replace("tlp:", "")

        # TLP:AMBER+STRICT — use stix2 built-in if available, else AMBER.
        if key in {"clear", "amber+strict"}:
            return TLPMarking(level=key).to_stix2_object()

        return _TLP_MARKINGS.get(
            key,
            stix2.TLP_WHITE,
        )

    @staticmethod
    def _whois_property_name(column: str) -> str:
        """Map a WhoisFreaks CSV column to a STIX custom property name."""

        normalized = column.strip().lower().replace("-", "_")
        cleaned = "".join(
            char if char.isalnum() or char == "_" else "_" for char in normalized
        )
        while "__" in cleaned:
            cleaned = cleaned.replace("__", "_")
        cleaned = cleaned.strip("_")
        prop_name = f"{_WHOIS_FIELD_PREFIX}{cleaned}"
        return prop_name[:250].rstrip("_")

    def _ordered_whois_items(
        self,
        record: NRDRecord,
    ) -> list[tuple[str, str]]:
        """Return every non-empty WHOIS CSV column as (column, value) pairs.

        Known columns appear first in a stable display order; any extra columns
        present in the CSV are appended afterwards. Empty values are omitted.
        """

        if not record.fields:
            return []

        # Preserve known column order, then any extra columns from the CSV.
        seen: set[str] = set()
        ordered: list[tuple[str, str]] = []

        for column in _WHOIS_COLUMN_ORDER:
            if column not in record.fields:
                continue
            value = (record.fields.get(column) or "").strip()
            seen.add(column)
            if value:
                ordered.append((column, value))

        for column, raw_value in record.fields.items():
            if column is None or column in seen:
                continue
            value = (raw_value or "").strip()
            if value:
                ordered.append((str(column), value))

        return ordered

    def _whois_custom_properties(
        self,
        record: NRDRecord,
    ) -> dict[str, str]:
        """Expose every non-empty WHOIS CSV column on the Domain-Name observable.

        Empty values are omitted from custom properties (OpenCTI drops most
        x_* fields anyway); the full column set including empties is stored
        in the linked Note.
        """

        if not self.whois:
            return {}

        properties: dict[str, str] = {}

        for column, value in self._ordered_whois_items(record):
            if column == "domain_name" or not value:
                continue
            properties[self._whois_property_name(column)] = value

        return properties

    def _build_whois_description(self, domain: str) -> str:
        """Short summary for the Domain-Name description field.

        OpenCTI standard: keep description brief. Full response columns are
        stored losslessly in a linked STIX Note (markdown table) and as
        non-empty x_whoisfreaks_* custom properties on the observable.
        """

        whois_available = "True" if self.whois else "False"
        return (
            f"WhoisFreaks newly registered domain: {domain} "
            f"Feed: {self.feed_name} "
            f"WHOIS data available: {whois_available}"
        )

    def _build_whois_note(
        self,
        record: NRDRecord,
        domain: str,
        observable_id: str,
        tlp: Any,
    ) -> stix2.Note | None:
        """Create a Note with the full WHOIS dump linked to the domain."""

        if not self.whois:
            return None

        items = self._ordered_whois_items(record)
        if not items:
            return None

        # Markdown table for readable display in OpenCTI UI
        body_lines = [
            f"## WhoisFreaks WHOIS — `{domain}`",
            "",
            f"**Feed:** `{self.feed_name}`",
            "",
            "| Field | Value |",
            "| --- | --- |",
        ]
        for column, value in items:
            # Escape pipes so markdown tables stay intact
            safe_value = value.replace("|", "\\|").replace("\n", " ")
            body_lines.append(f"| `{column}` | {safe_value} |")

        content = "\n".join(body_lines)

        # pycti Note.generate_id(created, content, abstract=None).
        # Passing created=None keeps the ID deterministic (content hash only).
        # A random/timestamp created would flood RabbitMQ with duplicate Notes.
        note_id = Note.generate_id(None, content)

        return stix2.Note(
            id=note_id,
            abstract=f"WhoisFreaks WHOIS data for {domain}",
            content=content,
            created_by_ref=_AUTHOR_ID,
            object_marking_refs=[tlp],
            object_refs=[observable_id],
            labels=[
                "whoisfreaks",
                "whoisfreaks-nrd",
                "whoisfreaks-whois",
                f"whoisfreaks-{self.feed_name}",
            ],
            allow_custom=True,
            custom_properties={
                "note_types": ["external"],
            },
        )

    def _to_stix(
        self,
        record: NRDRecord,
        tlp: Any,
        *,
        create_indicators: bool,
    ) -> list[Any]:
        domain = record.domain_name.lower().rstrip(".")

        escaped_domain = domain.replace(
            chr(39),
            chr(92) + chr(39),
        )

        pattern = f"[domain-name:value = '{escaped_domain}']"

        labels = [
            "whoisfreaks",
            "whoisfreaks-nrd",
            f"whoisfreaks-{self.feed_name}",
        ]

        description = self._build_whois_description(domain)
        whois_props = self._whois_custom_properties(record)

        observable_custom_properties: dict[str, Any] = {
            "x_opencti_description": description,
            "x_opencti_labels": labels,
            "created_by_ref": _AUTHOR_ID,
            **whois_props,
        }

        observable = stix2.DomainName(
            value=domain,
            object_marking_refs=[tlp],
            custom_properties=observable_custom_properties,
            allow_custom=True,
        )

        objects: list[Any] = [observable]

        # Full WHOIS as a linked Note (visible in OpenCTI entity view)
        note = self._build_whois_note(
            record=record,
            domain=domain,
            observable_id=observable.id,
            tlp=tlp,
        )
        if note is not None:
            objects.append(note)

        if not create_indicators:
            return objects

        indicator = stix2.Indicator(
            id=Indicator.generate_id(pattern),
            name=domain,
            description=description,
            indicator_types=["anomalous-activity"],
            pattern_type="stix",
            pattern=pattern,
            valid_from=datetime.now(timezone.utc),
            labels=labels,
            object_marking_refs=[tlp],
            created_by_ref=_AUTHOR_ID,
            allow_custom=True,
            custom_properties={
                "x_opencti_main_observable_type": "Domain-Name",
                **whois_props,
            },
        )

        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "based-on",
                indicator.id,
                observable.id,
            ),
            source_ref=indicator.id,
            target_ref=observable.id,
            relationship_type="based-on",
            object_marking_refs=[tlp],
            created_by_ref=_AUTHOR_ID,
        )

        objects.extend([indicator, relationship])
        return objects

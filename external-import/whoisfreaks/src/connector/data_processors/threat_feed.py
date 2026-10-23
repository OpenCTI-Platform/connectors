"""WhoisFreaks daily threat-feed processor."""

from __future__ import annotations

from collections.abc import Generator, Iterable
from datetime import date
from typing import Any

import stix2
from connector.author import AUTHOR_ID as _AUTHOR_ID
from connector.author import SHARED_AUTHOR as _SHARED_AUTHOR
from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import TLPMarking
from pycti import Indicator, Note, StixCoreRelationship
from whoisfreaks_client import (
    WhoisFreaksClient,
    WhoisFreaksSubscriptionError,
)
from whoisfreaks_client.models import ThreatFeedRecord
from whoisfreaks_client.status import WhoisFreaksStatus

_TLP_MARKINGS = {
    "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red": stix2.TLP_RED,
}

_MAX_BUNDLE_OBJECTS = 10_000


class ThreatFeedProcessor(BaseDataProcessor):
    """Import one WhoisFreaks threat feed with offset-resumable pagination."""

    def __init__(self, feed_type: str) -> None:
        if feed_type not in {"malware", "phishing", "spam"}:
            raise ValueError(f"Unsupported threat feed: {feed_type}")

        self.feed_type = feed_type
        self.work_name = f"WhoisFreaks {feed_type} threat feed"
        self.status: WhoisFreaksStatus | None = None
        # Set by transform() when a record of the current page fails
        # conversion; read by the collector before advancing checkpoints.
        self._page_conversion_failed = False

    def set_status(self, status: WhoisFreaksStatus) -> None:
        """Set the shared WhoisFreaks status snapshot."""
        self.status = status

    def post_init(self) -> None:
        config = self.settings.whoisfreaks

        self.client = WhoisFreaksClient(
            api_key=config.api_key.get_secret_value(),
            base_url=str(config.api_base_url),
            timeout=config.threat_timeout,
            max_retries=config.max_retries,
            retry_backoff_seconds=config.retry_backoff_seconds,
        )
        # Use the shared author object so both processors produce the same
        # identity description regardless of which one sends last.
        self._author = _SHARED_AUTHOR

    def collect(self) -> Iterable[list[ThreatFeedRecord]]:
        """Collect the latest threat-feed snapshot.

        The status endpoint's latest snapshot is ingested when it has not
        already completed. Older platform objects are left for OpenCTI
        retention policies; the connector does not delete or revoke them.
        """
        config = self.settings.whoisfreaks

        if self.status is None:
            raise RuntimeError("WhoisFreaks status has not been initialized")

        feed_status = self.status.get_threat_feed_status(self.feed_type)

        if not feed_status.is_available:
            self.logger.warning(
                "[THREAT_FEED] Feed status reports no available data; skipping",
                meta={
                    "feed_type": self.feed_type,
                    "last_update": feed_status.last_update,
                },
            )
            return []

        latest_available_date = date.fromisoformat(feed_status.last_update)
        latest_iso = latest_available_date.isoformat()

        # Only ever ingest the latest available snapshot (status last_update).
        # Historical day-range backfill is disabled; import_since is only a
        # floor for the latest snapshot date.
        last_completed = self.state.get_next_date(self.feed_type, "")
        start_offset = self.state.get_threat_offset(self.feed_type)
        offset_date = self.state.get_threat_offset_date(self.feed_type)

        # Floor: do not pull a last_update older than import_since.
        import_floor = config.import_since.date()
        if latest_available_date < import_floor:
            self.logger.info(
                "[THREAT_FEED] last_update is older than import_since; skipping",
                meta={
                    "feed_type": self.feed_type,
                    "last_update": latest_iso,
                    "import_since": import_floor.isoformat(),
                },
            )
            return []

        # Already fully ingested this snapshot (and not mid-day resume).
        if last_completed == latest_iso and start_offset == 0:
            self.logger.info(
                "[THREAT_FEED] Snapshot already ingested; skipping",
                meta={
                    "feed_type": self.feed_type,
                    "last_update": latest_iso,
                },
            )
            return []

        # Reuse an offset only for the snapshot it was checkpointed against.
        if start_offset > 0 and offset_date != latest_iso:
            start_offset = 0

        self.logger.info(
            "[THREAT_FEED] Fetching WhoisFreaks threat-feed snapshot",
            meta={
                "feed_type": self.feed_type,
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
    ) -> Iterable[list[ThreatFeedRecord]]:
        """Yield pages and update the in-memory offset at checkpoint intervals.

        transform() consumes each page before this generator resumes, so a
        conversion failure in a page is known here. From the first failed page
        on, the offset checkpoint is frozen (it stays at or before that page)
        and the snapshot is not marked complete, so the next run retries it.
        Valid records of later pages are still yielded and imported.
        """

        offset = start_offset
        pages_since_checkpoint = 0
        conversion_failed = False
        try:
            for page in self.client.iter_threat_feed(
                feed_type=self.feed_type,
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
                        "[THREAT_FEED] Conversion failures; checkpoint frozen",
                        meta={
                            "feed_type": self.feed_type,
                            "date": feed_date.isoformat(),
                            "page_end_offset": offset,
                        },
                    )

                if not conversion_failed and pages_since_checkpoint >= checkpoint_every:
                    self.state.set_threat_offset(
                        self.feed_type,
                        offset,
                        snapshot_date=feed_date.isoformat(),
                    )
                    pages_since_checkpoint = 0
                    self.logger.debug(
                        "[THREAT_FEED] Updated offset",
                        meta={
                            "feed_type": self.feed_type,
                            "offset": offset,
                            "date": feed_date.isoformat(),
                        },
                    )
        except WhoisFreaksSubscriptionError as exc:
            self.logger.warning(
                "[THREAT_FEED] Subscription error; feed skipped",
                meta={"feed_type": self.feed_type, "error": str(exc)},
            )
            return

        if conversion_failed:
            self.logger.warning(
                "[THREAT_FEED] Snapshot not marked complete; will retry next run",
                meta={"feed_type": self.feed_type, "date": feed_date.isoformat()},
            )
            return

        # The SDK persists state after all processors complete successfully.
        completed_date = feed_date.isoformat()
        self.state.set_next_date(self.feed_type, completed_date)
        self.logger.info(
            "[THREAT_FEED] Completed snapshot",
            meta={
                "feed_type": self.feed_type,
                "date": completed_date,
                "records_processed_from_offset": offset,
            },
        )

    def transform(
        self,
        data: Any,
    ) -> Generator[list[Any], None, None]:
        config = self.settings.whoisfreaks
        tlp = self._get_tlp_marking(config.tlp_level)

        for page in data:
            objects: list[Any] = [self._author, tlp]

            for record in page:
                try:
                    record_objects = self._to_stix(record, tlp)
                except Exception as err:
                    # Skip a single bad record; do not fail the whole page
                    # Conversion failures are handled per item, not per page.
                    self._page_conversion_failed = True
                    self.logger.warning(
                        "[THREAT_FEED] Skipping record that failed conversion",
                        meta={
                            "feed_type": self.feed_type,
                            "domain": getattr(record, "domain", None),
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

    def _to_stix(
        self,
        record: ThreatFeedRecord,
        tlp: Any,
    ) -> list[Any]:
        domain = record.domain.lower().rstrip(".")

        pattern = "[domain-name:value = '" + domain.replace("'", "\\'") + "']"

        confidence = round(record.confidence_score * 100)
        first_seen = record.first_seen.isoformat()
        last_seen = record.last_seen.isoformat()
        pivots = record.no_of_threat_matched_pivots

        # All threat-feed CSV columns in source order.
        feed_columns = record.source_fields or {
            "domain": domain,
            "threat_type": record.threat_type,
            "confidence": str(record.confidence_score),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "No_of_threat_matched_pivots": str(pivots),
        }

        # Short description (OpenCTI standard). Full columns go in the Note.
        description = (
            f"WhoisFreaks {self.feed_type} threat feed record for {domain} "
            f"(confidence={record.confidence_score}, "
            f"threat_type={record.threat_type})."
        )

        labels = [
            "whoisfreaks",
            f"whoisfreaks-{self.feed_type}",
            f"threat-type-{record.threat_type}",
        ]

        feed_custom_props = {
            "x_whoisfreaks_domain": domain,
            "x_whoisfreaks_threat_type": record.threat_type,
            "x_whoisfreaks_confidence": str(record.confidence_score),
            "x_whoisfreaks_first_seen": first_seen,
            "x_whoisfreaks_last_seen": last_seen,
            "x_whoisfreaks_no_of_threat_matched_pivots": str(pivots),
            "x_whoisfreaks_feed_type": self.feed_type,
        }

        observable = stix2.DomainName(
            value=domain,
            object_marking_refs=[tlp],
            allow_custom=True,
            custom_properties={
                "x_opencti_description": description,
                "x_opencti_score": confidence,
                "x_opencti_labels": labels,
                "created_by_ref": _AUTHOR_ID,
                **feed_custom_props,
            },
        )

        indicator = stix2.Indicator(
            id=Indicator.generate_id(pattern),
            name=domain,
            description=description,
            indicator_types=["malicious-activity"],
            pattern_type="stix",
            pattern=pattern,
            # last_seen is the last observation, not an expiry from the source,
            # so no valid_until is set; it stays in the x_whoisfreaks_* fields.
            valid_from=record.first_seen,
            labels=labels,
            object_marking_refs=[tlp],
            created_by_ref=_AUTHOR_ID,
            allow_custom=True,
            custom_properties={
                "x_opencti_score": confidence,
                "x_opencti_main_observable_type": "Domain-Name",
                **feed_custom_props,
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

        note_body_lines = [
            f"## WhoisFreaks {self.feed_type} threat feed — `{domain}`",
            "",
            "| Field | Value |",
            "| --- | --- |",
        ]
        for column, value in feed_columns.items():
            text_value = str(value).strip() if value is not None else ""
            if not text_value:
                continue  # drop empty columns
            safe = text_value.replace("|", "\\|").replace("\n", " ")
            note_body_lines.append(f"| `{column}` | {safe} |")
        note_content = "\n".join(note_body_lines)

        # pycti Note.generate_id(created, content, abstract=None).
        # Passing created=None keeps the ID deterministic (content hash only).
        # A random/timestamp created would flood RabbitMQ with duplicate Notes.
        note = stix2.Note(
            id=Note.generate_id(None, note_content),
            abstract=f"WhoisFreaks {self.feed_type} fields for {domain}",
            content=note_content,
            created_by_ref=_AUTHOR_ID,
            object_marking_refs=[tlp],
            object_refs=[indicator.id, observable.id],
            labels=[
                "whoisfreaks",
                f"whoisfreaks-{self.feed_type}",
                "whoisfreaks-threat-feed",
            ],
            allow_custom=True,
            custom_properties={
                "note_types": ["external"],
            },
        )

        return [
            observable,
            indicator,
            relationship,
            note,
        ]

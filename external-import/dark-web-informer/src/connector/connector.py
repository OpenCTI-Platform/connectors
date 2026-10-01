"""Core implementation of the Dark Web Informer external-import connector.

Passthrough mode: fetches Dark Web Informer's prebuilt STIX 2.1 bundles and
sends them to OpenCTI without re-deriving the mapping. DWI publishes valid,
field-complete bundles (identities, indicators, observables, malware,
intrusion-sets, reports and their relationships), so no conversion layer is
needed. Deduplication is handled by OpenCTI via the deterministic STIX IDs.

DWI only publishes full snapshots, so the connector keeps a per-source cursor
(the most recent ``modified``/``created`` timestamp seen) in its state and, on
the next runs, only forwards the objects changed since then, plus the objects
they reference so the bundle stays consistent.

The only objects the connector adds are provenance ones: a "Dark Web Informer"
organization author and a TLP marking, attached to the ingested objects that do
not already carry their own. DWI's own values always win, and when a bundle
already carries DWI's author identity, that identity is reused instead of adding
a second one.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from connector.settings import ConnectorSettings
from connector.state import ConnectorState
from connectors_sdk.models.organization_author import OrganizationAuthor
from connectors_sdk.models.tlp_marking import TLPMarking
from dark_web_informer_client import DarkWebInformerClient
from pycti import OpenCTIConnectorHelper

__all__ = ["DarkWebInformerConnector"]

# STIX Cyber Observables carry their author under an OpenCTI custom property,
# since created_by_ref is not a valid SCO field in STIX 2.1.
_SCO_TYPES = frozenset(
    {
        "artifact",
        "autonomous-system",
        "bank-account",
        "credential",
        "cryptocurrency-wallet",
        "directory",
        "domain-name",
        "email-addr",
        "email-message",
        "file",
        "hostname",
        "ipv4-addr",
        "ipv6-addr",
        "mac-addr",
        "media-content",
        "mutex",
        "network-traffic",
        "payment-card",
        "persona",
        "phone-number",
        "process",
        "software",
        "text",
        "tracking-number",
        "url",
        "user-account",
        "user-agent",
        "windows-registry-key",
        "x509-certificate",
    }
)

# STIX types that carry neither an author nor markings.
_UNATTRIBUTABLE_TYPES = frozenset({"marking-definition", "language-content"})


def _parse_timestamp(value: object) -> datetime | None:
    """Parse a STIX timestamp, tolerating any sub-second precision."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _object_timestamp(obj: dict) -> datetime | None:
    """Return when an object last changed, or None if it carries no timestamp.

    SCOs have neither ``modified`` nor ``created`` in STIX 2.1.
    """
    return _parse_timestamp(obj.get("modified")) or _parse_timestamp(obj.get("created"))


def _referenced_ids(obj: dict) -> set[str]:
    """Return the STIX IDs an object points to through its *_ref(s) properties."""
    refs: set[str] = set()
    for key, value in obj.items():
        if key.endswith("_ref") and isinstance(value, str):
            refs.add(value)
        elif key.endswith("_refs") and isinstance(value, list):
            refs.update(v for v in value if isinstance(v, str))
    return refs


class DarkWebInformerConnector:
    """External-import connector ingesting Dark Web Informer STIX bundles."""

    def __init__(
        self, helper: OpenCTIConnectorHelper, settings: ConnectorSettings
    ) -> None:
        self.helper = helper
        self.settings = settings
        self.state = ConnectorState()
        self.state.inject_dependencies(helper)
        config = settings.dark_web_informer

        self.client = DarkWebInformerClient(
            helper=helper,
            base_url=str(config.base_url),
            api_key=config.api_key.get_secret_value(),
        )
        self.sources = list(config.sources)
        self.use_preview = config.use_preview_endpoint
        self.preview_limit = config.preview_limit

        author = OrganizationAuthor(
            name="Dark Web Informer",
            description="Threat intelligence collected and published by Dark Web Informer.",
            organization_type="vendor",
        )
        marking = TLPMarking(level=config.tlp_level)
        # serialize() rather than dict(): the stix2 objects hold STIXdatetime
        # and marking values that json.dumps cannot encode.
        self.author_stix = json.loads(author.to_stix2_object().serialize())
        self.marking_stix = json.loads(marking.to_stix2_object().serialize())

    @staticmethod
    def _bundle_objects(bundle: dict) -> list | None:
        """Return the objects carried by a native DWI bundle, or None if empty."""
        if not isinstance(bundle, dict):
            return None
        return bundle.get("objects") or None

    @staticmethod
    def _bundle_cursor(objects: list) -> datetime | None:
        """Return the most recent object timestamp of a bundle."""
        timestamps = [
            ts
            for obj in objects
            if isinstance(obj, dict) and (ts := _object_timestamp(obj)) is not None
        ]
        return max(timestamps, default=None)

    @staticmethod
    def _changed_since(objects: list, cursor: datetime) -> list:
        """Return the objects changed after ``cursor``, with what they reference.

        Objects without a timestamp (observables, markings...) are only kept
        when a changed object references them, directly or transitively.
        """
        by_id = {
            obj["id"]: obj
            for obj in objects
            if isinstance(obj, dict) and isinstance(obj.get("id"), str)
        }
        kept: set[str] = set()
        pending = [
            oid
            for oid, obj in by_id.items()
            if (ts := _object_timestamp(obj)) is not None and ts > cursor
        ]
        while pending:
            oid = pending.pop()
            if oid in kept or oid not in by_id:
                continue
            kept.add(oid)
            pending.extend(_referenced_ids(by_id[oid]) - kept)

        # Preserve DWI's original ordering.
        return [
            obj for obj in objects if isinstance(obj, dict) and obj.get("id") in kept
        ]

    @staticmethod
    def _bundle_author(objects: list) -> dict | None:
        """Return the identity DWI declares as author in its bundle, if any.

        This is the identity most referenced through created_by_ref (or
        x_opencti_created_by_ref for observables) among the bundle's objects.
        """
        identities = {
            obj["id"]: obj
            for obj in objects
            if isinstance(obj, dict) and obj.get("type") == "identity"
        }
        refs = Counter(
            ref
            for obj in objects
            if isinstance(obj, dict)
            and (
                ref := obj.get("created_by_ref") or obj.get("x_opencti_created_by_ref")
            )
            in identities
        )
        if not refs:
            return None
        return identities[refs.most_common(1)[0][0]]

    def _with_provenance(self, bundle: dict, objects: list) -> dict:
        """Return the bundle with the author and TLP marking attached.

        DWI's objects are otherwise untouched: an object that already declares
        its own author or markings keeps them. When the bundle already carries
        DWI's own author identity, it is reused for the objects without one, so
        the ingested data only ever has a single creator.
        """
        dwi_author = self._bundle_author(objects)
        author_id = (dwi_author or self.author_stix)["id"]
        marking_id = self.marking_stix["id"]
        attributed: list = [self.marking_stix]
        if dwi_author is None:
            attributed.insert(0, self.author_stix)

        for obj in objects:
            if not isinstance(obj, dict):
                attributed.append(obj)
                continue
            obj_type = obj.get("type")
            if obj_type in _UNATTRIBUTABLE_TYPES or obj.get("id") == author_id:
                attributed.append(obj)
                continue

            if obj.get("created_by_ref") or obj.get("x_opencti_created_by_ref"):
                pass  # DWI already declares an author for this object
            elif obj_type in _SCO_TYPES:
                obj = dict(obj, x_opencti_created_by_ref=author_id)
            else:
                obj = dict(obj, created_by_ref=author_id)

            if not obj.get("object_marking_refs"):
                obj = dict(obj, object_marking_refs=[marking_id])

            attributed.append(obj)

        return {**bundle, "objects": attributed}

    def _send_bundle(self, bundle: dict, work_id: str) -> int:
        """Forward a native DWI STIX bundle to OpenCTI.

        Returns the number of DWI objects sent (0 if empty/invalid), excluding
        the author and marking the connector adds.
        """
        objects = self._bundle_objects(bundle)
        if not objects:
            return 0
        # DWI bundles are third-party payloads we do not rewrite, so let OpenCTI
        # drop dangling references instead of failing the whole bundle.
        self.helper.send_stix2_bundle(
            json.dumps(self._with_provenance(bundle, objects)),
            work_id=work_id,
            cleanup_inconsistent_bundle=True,
        )
        return len(objects)

    def _fetch_bundle(self, source: str) -> dict:
        if self.use_preview:
            return self.client.get_stix_preview(source=source, limit=self.preview_limit)
        return self.client.get_stix_bundle(source)

    def process_message(self) -> None:
        now = datetime.now(timezone.utc)
        self.state.load(force=True)
        cursors: dict[str, datetime] = dict(self.state.cursors or {})
        self.helper.connector_logger.info(
            "Starting Dark Web Informer run",
            {
                "sources": self.sources,
                "last_run": str(self.state.last_run),
                "cursors": {k: v.isoformat() for k, v in cursors.items()},
            },
        )
        work_id: str | None = None
        try:
            total = 0
            for source in self.sources:
                bundle = self._fetch_bundle(source)
                objects = self._bundle_objects(bundle)
                if not objects:
                    self.helper.connector_logger.info(
                        "Empty bundle, nothing to ingest", {"source": source}
                    )
                    continue

                bundle_cursor = self._bundle_cursor(objects)
                previous_cursor = cursors.get(source)
                if previous_cursor is not None:
                    objects = self._changed_since(objects, previous_cursor)
                    self.helper.connector_logger.info(
                        "Filtered bundle on previous cursor",
                        {
                            "source": source,
                            "cursor": previous_cursor.isoformat(),
                            "objects": len(objects),
                        },
                    )

                if objects:
                    # Register the work lazily, so a run that finds no data
                    # anywhere does not leave an empty job behind in OpenCTI.
                    if work_id is None:
                        work_id = self.helper.api.work.initiate_work(
                            self.helper.connect_id, "Dark Web Informer run"
                        )
                    count = self._send_bundle({**bundle, "objects": objects}, work_id)
                    self.helper.connector_logger.info(
                        "Sent bundle", {"source": source, "objects": count}
                    )
                    total += count
                else:
                    self.helper.connector_logger.info(
                        "No new objects since last run", {"source": source}
                    )

                # Persist each source's cursor as soon as it is ingested, so a
                # failure on a later source does not resend this one.
                if bundle_cursor is not None and (
                    previous_cursor is None or bundle_cursor > previous_cursor
                ):
                    cursors[source] = bundle_cursor
                    self.state.cursors = cursors
                    self.state.save()

            self.state.cursors = cursors
            self.state.last_run = now
            self.state.save()
            if work_id is None:
                self.helper.connector_logger.info("No new data to ingest")
            else:
                self.helper.api.work.to_processed(
                    work_id, f"Dark Web Informer run complete ({total} objects)"
                )
        except Exception as err:
            self.helper.connector_logger.error(
                "Dark Web Informer run failed", {"error": str(err)}
            )
            if work_id is not None:
                self.helper.api.work.to_processed(
                    work_id, f"Run failed: {err}", in_error=True
                )

    def run(self) -> None:
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.settings.connector.duration_period,
        )

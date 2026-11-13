"""PolySwarm feed connector: import the PolySwarm TAXII feed into OpenCTI.

On each run, for every configured TAXII API root (collection):

    1. resume from the collection's cursor (or, on the first run, from
       `POLYSWARM_FEED_BACKFILL_DAYS` days ago);
    2. fetch one page at a time, convert it and send it as one bundle;
    3. save the cursor after every page, so a failure never loses progress;
    4. stop once `POLYSWARM_MAX_OBJECTS_PER_RUN` objects were sent, keeping the
       TAXII `next` token so the next run continues where this one stopped.

When `POLYSWARM_HUNTING_ENABLED` is true, the live hunting source runs after
the feed. Feed and hunting are isolated: a failure in one does not discard
the other's progress.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

import stix2
from connector.converter import FeedConverter
from connector.hunting import HuntingSource
from connector.quota import REFRESH_SECONDS, QuotaMonitor, is_quota_exhausted_error
from connector.state import CollectionCursor, ConnectorState
from connectors_sdk import ApiClientError
from connectors_sdk.models import TLPMarking
from polyswarm_client import (
    PolySwarmAccountClient,
    PolySwarmTaxiiClient,
    TaxiiAuthenticationError,
    TaxiiPage,
    TaxiiPermissionError,
)
from pycti import Identity

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from pycti import OpenCTIConnectorHelper

AUTHOR_NAME = "PolySwarm"


def build_author() -> dict[str, Any]:
    """The PolySwarm organization identity, shared by all PolySwarm connectors."""
    author = stix2.Identity(
        id=Identity.generate_id(name=AUTHOR_NAME, identity_class="organization"),
        name=AUTHOR_NAME,
        identity_class="organization",
        description="PolySwarm malware intelligence platform.",
        external_references=[
            {"source_name": "PolySwarm", "url": "https://polyswarm.io/"}
        ],
    )
    return json.loads(author.serialize())


def build_tlp_marking(level: str) -> dict[str, Any]:
    """The TLP marking definition for a TLP level, as a STIX dict."""
    return json.loads(TLPMarking(level=level).to_stix2_object().serialize())


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class PolySwarmFeedConnector:
    """External import connector for the PolySwarm TAXII feed."""

    # Number of samples (per-sample bundles) requested per TAXII page.
    PAGE_LIMIT = 100

    def __init__(
        self,
        config: ConnectorSettings,
        helper: OpenCTIConnectorHelper,
        taxii_client: PolySwarmTaxiiClient | None = None,
        hunting_client: Any = None,
        account_client: Any = None,
    ) -> None:
        """Initialize the connector.

        Args:
            config: The connector settings.
            helper: The OpenCTI connector helper.
            taxii_client: Optional TAXII client (injected in tests).
            hunting_client: Optional live hunting client, handed to the
                hunting source (injected in tests).
            account_client: Optional account client with ``account_features()``
                (injected in tests), used to read the plan and quotas.
        """
        self.config = config
        self.helper = helper
        self.logger = helper.connector_logger
        polyswarm = config.polyswarm
        self.taxii_client = taxii_client or PolySwarmTaxiiClient(
            api_url=polyswarm.api_url,
            account_number=polyswarm.account_number,
            api_key=polyswarm.api_key.get_secret_value(),
        )
        self.hunting_client = hunting_client
        # Read-only account plan and quota visibility; never raises. Re-read
        # about hourly, a little under an hour so an hourly run never skips it.
        self.quota = QuotaMonitor(
            account_client
            or PolySwarmAccountClient(
                api_url=polyswarm.api_url,
                api_key=polyswarm.api_key.get_secret_value(),
            ),
            self.logger,
            warn_below=polyswarm.quota_warn_below,
            refresh_seconds=REFRESH_SECONDS - 30,
        )
        self.author = build_author()
        self.tlp_marking = build_tlp_marking(polyswarm.tlp_level)
        # Feed objects sent in the current run, counted as each page is sent
        # so a collection that fails part way still uses up its share.
        self._feed_sent = 0

    # ------------------------------------------------------------------
    # Scheduling
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Run `process_message` every `CONNECTOR_DURATION_PERIOD`."""
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

    def process_message(self) -> None:
        """One connector run: feed collections, then live hunting if enabled."""
        try:
            self._run_once()
        except (KeyboardInterrupt, SystemExit):
            self.logger.info("Connector stopped by user or system")
            sys.exit(0)
        except Exception as err:
            self.logger.error(
                "Unexpected error during connector run", {"error": str(err)}
            )

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def _run_once(self) -> None:
        polyswarm = self.config.polyswarm
        now = datetime.now(tz=timezone.utc)
        self.quota.refresh()

        state = ConnectorState()
        state.inject_dependencies(self.helper)
        state.load(force=True)
        self.logger.info("Connector run starting", {"state": state.to_json()})

        converter = FeedConverter(
            author=self.author,
            tlp_marking=self.tlp_marking,
            indicator_valid_days=polyswarm.feed_indicator_valid_days,
            logger=self.logger,
            now=now,
            families=polyswarm.feed_families,
            exclude_families=polyswarm.feed_exclude_families,
            min_confidence=polyswarm.feed_min_confidence,
        )
        max_objects = polyswarm.max_objects_per_run
        self._feed_sent = 0
        for collection in polyswarm.feed_collections:
            if self._feed_sent >= max_objects:
                self.logger.info(
                    "Maximum objects per run reached, remaining collections "
                    "resume on the next run",
                    {"collection": collection, "max_objects_per_run": max_objects},
                )
                break
            try:
                self._import_collection(
                    collection, state, converter, now, max_objects - self._feed_sent
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as err:
                self.logger.error(
                    "PolySwarm feed import failed, progress up to the last sent "
                    "page is kept",
                    {"collection": collection, "error": self._describe_error(err)},
                )

        if converter.skipped_items:
            self.logger.warning(
                "Some PolySwarm feed items were malformed and skipped",
                {"skipped_items": converter.skipped_items},
            )

        if converter.filtered_items:
            self.logger.info(
                "Some PolySwarm feed samples were skipped by the family or "
                "confidence filters",
                {"filtered_items": converter.filtered_items},
            )

        if polyswarm.hunting_enabled:
            try:
                self._import_hunting(state)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as err:
                self.logger.error(
                    "PolySwarm live hunting import failed, its state is unchanged",
                    {"error": self._describe_error(err)},
                )

        state.last_run = now
        state.save()
        self.logger.info(
            "Connector run completed",
            {"objects_sent": self._feed_sent, "state": state.to_json()},
        )

    def _import_collection(
        self,
        collection: str,
        state: ConnectorState,
        converter: FeedConverter,
        now: datetime,
        budget: int,
    ) -> int:
        """Import one TAXII collection, page by page. Return objects sent.

        Every sent page is also added to ``self._feed_sent`` right away, so
        the run total stays right when the collection fails part way.
        """
        cursor = state.get_cursor(collection)
        if not cursor.added_after:
            cursor.added_after = _format_timestamp(
                now - timedelta(days=self.config.polyswarm.feed_backfill_days)
            )
            self.logger.info(
                "First run for collection, backfilling",
                {"collection": collection, "added_after": cursor.added_after},
            )

        collection_id = self.taxii_client.get_collection_id(collection)
        work_id = None
        sent = 0
        try:
            while True:
                page = self._fetch_page(collection, collection_id, cursor)
                objects = converter.convert_page(page.objects)
                if objects:
                    if work_id is None:
                        work_id = self._initiate_work(f"feed {collection}")
                    self._send(objects, work_id)
                    sent += len(objects)
                    self._feed_sent += len(objects)

                if page.date_added_last:
                    cursor.added_after = page.date_added_last
                cursor.next_token = page.next if page.more else None
                state.set_cursor(collection, cursor)
                state.save()

                self.logger.info(
                    "PolySwarm feed page imported",
                    {
                        "collection": collection,
                        "items": len(page.objects),
                        "objects_sent": len(objects),
                        "more": page.more,
                    },
                )
                if not cursor.next_token:
                    break
                if sent >= budget:
                    self.logger.info(
                        "Maximum objects per run reached, the collection resumes "
                        "on the next run",
                        {"collection": collection, "objects_sent": sent},
                    )
                    break
        except Exception as err:
            if work_id is not None:
                self.helper.api.work.to_processed(
                    work_id,
                    f"PolySwarm feed {collection} failed: {self._describe_error(err)}",
                    in_error=True,
                )
            raise

        if work_id is not None:
            self.helper.api.work.to_processed(
                work_id, f"PolySwarm feed {collection}: {sent} objects sent"
            )
        return sent

    def _fetch_page(
        self, collection: str, collection_id: str, cursor: CollectionCursor
    ) -> TaxiiPage:
        """Fetch the next page, from the `next` token when there is one.

        An unusable `next` token (expired, rejected) falls back to a fresh
        query from `added_after`, which is the last page's date added.
        """
        if cursor.next_token:
            try:
                return self.taxii_client.get_objects(
                    collection,
                    collection_id,
                    next_token=cursor.next_token,
                    limit=self.PAGE_LIMIT,
                )
            except (TaxiiAuthenticationError, TaxiiPermissionError):
                raise
            except ApiClientError as err:
                self.logger.warning(
                    "TAXII 'next' token rejected, resuming from 'added_after'",
                    {"collection": collection, "error": str(err)},
                )
                cursor.next_token = None
        return self.taxii_client.get_objects(
            collection,
            collection_id,
            added_after=cursor.added_after,
            limit=self.PAGE_LIMIT,
        )

    def _import_hunting(self, state: ConnectorState) -> None:
        """Run the live hunting source and store its sub-state under `hunting`."""
        source = HuntingSource(
            config=self.config.polyswarm,
            author=self.author,
            tlp_marking=self.tlp_marking,
            logger=self.logger,
            client=self.hunting_client,
        )
        objects, hunting_state = source.collect(dict(state.hunting or {}))
        if objects:
            work_id = self._initiate_work("live hunting")
            try:
                self._send(objects, work_id)
            except Exception as err:
                self.helper.api.work.to_processed(
                    work_id,
                    f"PolySwarm live hunting failed: {self._describe_error(err)}",
                    in_error=True,
                )
                raise
            self.helper.api.work.to_processed(
                work_id, f"PolySwarm live hunting: {len(objects)} objects sent"
            )
        state.hunting = hunting_state
        state.save()

    def _describe_error(self, err: Exception) -> str:
        """The error text; a quota failure also shows the remaining quota."""
        if not is_quota_exhausted_error(err):
            return str(err)
        return (
            f"PolySwarm quota exhausted or rate limited (HTTP 429): {err}. "
            f"Account: {self.quota.exhausted_summary()}"
        )

    # ------------------------------------------------------------------
    # OpenCTI helpers
    # ------------------------------------------------------------------

    def _initiate_work(self, name: str) -> str:
        friendly_name = (
            f"{self.helper.connect_name} {name} @ "
            f"{datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}"
        )
        return self.helper.api.work.initiate_work(self.helper.connect_id, friendly_name)

    def _send(self, objects: list[dict[str, Any]], work_id: str) -> None:
        bundle = self.helper.stix2_create_bundle(
            [self.author, self.tlp_marking, *objects]
        )
        self.helper.send_stix2_bundle(bundle, work_id=work_id)

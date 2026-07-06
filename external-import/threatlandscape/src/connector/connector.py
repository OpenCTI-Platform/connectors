import sys
from datetime import datetime, timezone
from typing import Optional

import requests
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from threatlandscape_client import ThreatLandscapeClient

# Flush and start a new work bundle after accumulating this many STIX objects.
# Keeps memory bounded on large first-run imports.
_BATCH_FLUSH_THRESHOLD = 5_000


class ThreatLandscapeConnector:
    """
    External Import connector for the Threat Landscape threat intelligence API.

    Fetches continuously updated STIX 2.1 bundles from ``/stix_bundles`` and
    forwards them to OpenCTI. Bundles are already fully formed by the source —
    no STIX conversion is performed. Incremental sync is driven by a ``seq_id``
    cursor stored in connector state.
    """

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Args:
            config: Validated connector settings.
            helper: OpenCTI connector helper.
        """
        self.config = config
        self.helper = helper

        self.client = ThreatLandscapeClient(
            helper=self.helper,
            base_url=self.config.threatlandscape.api_base_url,
            api_key=self.config.threatlandscape.api_key,
        )
        self.converter = ConverterToStix(helper=self.helper)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_last_seq_id(self) -> Optional[int]:
        """Return the ``last_seq_id`` persisted from the previous run, or ``None``."""
        state = self.helper.get_state()
        if state and "last_seq_id" in state:
            return int(state["last_seq_id"])
        return None

    def _get_last_ioc_seq_id(self) -> Optional[int]:
        """Return the ``ioc_last_seq_id`` persisted from the previous IOC run, or ``None``."""
        state = self.helper.get_state()
        if state and "ioc_last_seq_id" in state:
            return int(state["ioc_last_seq_id"])
        return None

    def _first_run_since_date(self) -> str:
        """
        Compute the ISO 8601 UTC timestamp for the first-run lookback window.

        Returns:
            UTC timestamp string in the format expected by the PostgREST API.
        """
        now = datetime.now(timezone.utc)
        since = now - self.config.threatlandscape.import_since
        return since.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _flush_batch(self, stix_objects: list, work_label: str) -> None:
        """
        Send a batch of STIX objects to OpenCTI under a single work entry.

        Args:
            stix_objects: Flat list of STIX object dicts to bundle and send.
            work_label: Human-readable label shown in the OpenCTI UI.
        """
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, work_label)
        self.helper.connector_logger.info(
            "Sending STIX bundle to OpenCTI",
            meta={"work_id": work_id, "objects_count": len(stix_objects)},
        )

        bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(
            bundle,
            work_id=work_id,
            cleanup_inconsistent_bundle=True,
        )

        self.helper.api.work.to_processed(
            work_id,
            f"{self.helper.connect_name}: imported {len(stix_objects)} STIX objects",
        )

    def _collect_and_send(
        self,
        since_seq_id: Optional[int],
        since_date: Optional[str],
    ) -> Optional[int]:
        """
        Paginate through the API, accumulate STIX objects, and send batches to
        OpenCTI. Tracks and returns the highest ``seq_id`` seen.

        Uses cursor-based pagination: the first page filters by ``since_date``
        or ``since_seq_id`` (depending on whether this is a first or incremental
        run), and subsequent pages filter by ``seq_id > <max_seen>``.

        Routes to the Intelligence API (``/stix_bundles``) or the IOC API
        (``/actionable_iocs``) based on ``config.threatlandscape.feed``.

        Args:
            since_seq_id: Cursor for incremental runs (``seq_id > value``).
            since_date: Date filter for the first run.

        Returns:
            The highest ``seq_id`` encountered across all pages, or ``None`` if
            no rows were returned.
        """
        feed = self.config.threatlandscape.feed
        page_size = self.config.threatlandscape.page_size
        is_ioc = feed == "ioc"

        # Derive optional source_type filter for intelligence feeds.
        source_type = None
        if feed == "intelligence-osint":
            source_type = "osint"
        elif feed == "intelligence-darknet":
            source_type = "darknet"

        max_seq_id: Optional[int] = None
        stix_objects: list = []
        batch_index = 1
        total_objects_sent = 0

        while True:
            try:
                if is_ioc:
                    rows = self.client.get_actionable_iocs(
                        since_seq_id=since_seq_id,
                        since_date=since_date,
                        page_size=page_size,
                        offset=0,
                    )
                else:
                    rows = self.client.get_stix_bundles(
                        since_seq_id=since_seq_id,
                        since_date=since_date,
                        source_type=source_type,
                        page_size=page_size,
                        offset=0,
                    )
            except requests.HTTPError as err:
                self.helper.connector_logger.error(
                    "API request failed; aborting run",
                    meta={
                        "error": str(err),
                        "since_seq_id": since_seq_id,
                        "since_date": since_date,
                    },
                )
                raise

            if not rows:
                break

            for row in rows:
                objects = self.converter.extract_objects(row["stix_bundle"])
                stix_objects.extend(objects)

                seq_id = row.get("seq_id")
                if seq_id is not None and (max_seq_id is None or seq_id > max_seq_id):
                    max_seq_id = seq_id

            # Flush when we have accumulated enough objects to avoid excessive
            # memory usage on large first-run imports.
            if len(stix_objects) >= _BATCH_FLUSH_THRESHOLD:
                label = f"{self.helper.connect_name} — batch {batch_index}"
                self._flush_batch(stix_objects, label)
                total_objects_sent += len(stix_objects)
                stix_objects = []
                batch_index += 1

            if len(rows) < page_size:
                # Last page reached.
                break

            # Advance cursor for next page — switch to seq_id-based filtering
            # after the first page, regardless of how this run started.
            if max_seq_id is not None:
                since_seq_id = max_seq_id
                since_date = None

        # Send any remaining objects that did not fill a full batch.
        if stix_objects:
            label = (
                f"{self.helper.connect_name} — batch {batch_index}"
                if batch_index > 1
                else self.helper.connect_name
            )
            self._flush_batch(stix_objects, label)
            total_objects_sent += len(stix_objects)

        self.helper.connector_logger.info(
            "Import complete",
            meta={"total_objects_sent": total_objects_sent, "max_seq_id": max_seq_id},
        )

        return max_seq_id

    # ------------------------------------------------------------------
    # Main entry points
    # ------------------------------------------------------------------

    def process_message(self) -> None:
        """
        Main processing method invoked by the scheduler on each run.

        Determines whether this is a first run (no saved cursor) or an
        incremental run, fetches new bundles accordingly, and updates state.
        """
        self.helper.connector_logger.info(
            "Starting connector run",
            meta={"connector_name": self.helper.connect_name},
        )

        try:
            feed = self.config.threatlandscape.feed
            is_ioc = feed == "ioc"
            last_seq_id = (
                self._get_last_ioc_seq_id() if is_ioc else self._get_last_seq_id()
            )

            if last_seq_id is None:
                since_date = self._first_run_since_date()
                self.helper.connector_logger.info(
                    "First run — fetching from date",
                    meta={"feed": feed, "since_date": since_date},
                )
                max_seq_id = self._collect_and_send(
                    since_seq_id=None, since_date=since_date
                )
            else:
                self.helper.connector_logger.info(
                    "Incremental run — fetching after cursor",
                    meta={"feed": feed, "last_seq_id": last_seq_id},
                )
                max_seq_id = self._collect_and_send(
                    since_seq_id=last_seq_id, since_date=None
                )

            # Persist state only after a fully successful run.
            if max_seq_id is not None:
                state_key = "ioc_last_seq_id" if is_ioc else "last_seq_id"
                current_state = self.helper.get_state() or {}
                new_state = {
                    **current_state,
                    state_key: max_seq_id,
                    "last_run": datetime.now(timezone.utc).isoformat(),
                }
                self.helper.set_state(new_state)
                self.helper.connector_logger.info(
                    "State updated", meta={state_key: max_seq_id}
                )
            else:
                self.helper.connector_logger.info("No new data found")

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stopped")
            sys.exit(0)

        except Exception as err:
            self.helper.connector_logger.error(
                "Connector run failed", meta={"error": str(err)}
            )
            raise

    def run(self) -> None:
        """Start the connector and schedule periodic execution."""
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

"""
Connect to Cognyte Luminar and ingest feeds into OpenCTI.

Pipeline per run and per feed (TAXII collection alias), one bounded batch at
a time:

    EXTRACT    LuminarManager.get_objects()        (luminar_manager.py)
    TRANSFORM  ConverterToStix.convert_batch()     (converter_to_stix.py)
                 incl. expiration filtering        (expiration.py)
                 and OpenCTI relationship schema   (relationship_schema.py)
    LOAD       ConnectorLuminar._send_batch()      (this module)

The per-feed checkpoint (X-TAXII-Date-Added-Last of the last ingested batch)
is persisted after each batch is sent, so a failed run resumes where it
stopped.
"""

import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from pycti import OpenCTIConnectorHelper

from .config_loader import ConfigConnector
from .converter_to_stix import (
    PHASE_CONTAINER_TYPES,
    SRO_TYPES,
    ConversionStats,
    ConverterToStix,
)
from .expiration import parse_stix_timestamp
from .luminar_manager import (
    EXPECTED_COLLECTION_ALIASES,
    LUMINAR_DATE_FORMAT,
    LuminarAPIError,
    LuminarManager,
)
from .relationship_schema import RelationshipSchema

# Luminar does not return objects strictly ordered by date_added (measured
# inversions up to ~0.5 ms across page boundaries), so resuming exactly at the
# saved X-TAXII-Date-Added-Last could skip objects. Re-reading this window is
# harmless: OpenCTI upserts the re-delivered objects.
CHECKPOINT_OVERLAP = timedelta(seconds=1)


# A batch is sent in phases, each only after OpenCTI has ingested the previous
# one, so referenced objects are stored before the objects referencing them.
# Ordering inside one bundle is not enough: pycti's splitter re-sorts by
# dependency count and parallel workers may still process a relationship
# before its endpoint (MISSING_REFERENCE_ERROR, observed on merged entities).
# observed-data stays with the entities (PHASE_CONTAINER_TYPES).
# Give up waiting only when ingestion stops progressing: a large batch on a
# slow platform can legitimately take hours (≈270k objects took >3 h in tests).
INGESTION_STALL_TIMEOUT = timedelta(minutes=15)
INGESTION_POLL_SECONDS = 5
INGESTION_PROGRESS_LOG_SECONDS = 60


class IngestionError(Exception):
    """Sending a bundle to OpenCTI failed; fatal for the current run."""


class ConnectorLuminar:
    """
    OpenCTI external-import connector for Cognyte Luminar.
    """

    def __init__(self) -> None:
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.logger = self.helper.connector_logger

        self.duration_period = self.config.duration_period
        self.initial_fetch_date = self._initial_fetch_timestamp(
            self.config.initial_fetch_date
        )
        self.converter = ConverterToStix(
            self.logger,
            create_observable=bool(self.config.create_observable),
            mask_credentials=bool(self.config.mask_credentials),
        )
        self.client = LuminarManager(
            cognyte_client_id=str(self.config.luminar_client_id),
            cognyte_client_secret=str(self.config.luminar_client_secret),
            cognyte_account_id=str(self.config.luminar_account_id),
            cognyte_base_url=str(self.config.luminar_base_url),
            added_after=self.initial_fetch_date,
            logger=self.logger,
        )

    # ----- configuration / state -----

    @staticmethod
    def _initial_fetch_timestamp(value: Any) -> str:
        """Convert LUMINAR_INITIAL_FETCH_DATE (YYYY-MM-DD) to a TAXII
        ``added_after`` timestamp."""
        text = str(value).strip()
        try:
            day = datetime.strptime(text, "%Y-%m-%d")
        except ValueError as err:
            raise ValueError(
                f"LUMINAR_INITIAL_FETCH_DATE must be YYYY-MM-DD, got {text!r}"
            ) from err
        return day.strftime(LUMINAR_DATE_FORMAT)

    @staticmethod
    def _normalize_checkpoint(value: Any) -> Optional[str]:
        parsed = parse_stix_timestamp(value)
        return parsed.strftime(LUMINAR_DATE_FORMAT) if parsed else None

    def _load_checkpoints(self) -> Dict[str, str]:
        """Return per-feed ``added_after`` checkpoints from the connector state.

        State layout: ``{"feeds": {"<alias>": "<timestamp>"}, "last_run_end": ...}``.
        The legacy single ``last_run`` value (wall-clock time of the previous
        run) is migrated once into every feed that has no checkpoint yet.
        """
        state = self.helper.get_state() or {}
        feeds = state.get("feeds") if isinstance(state.get("feeds"), dict) else {}
        legacy = self._normalize_checkpoint(state.get("last_run"))

        checkpoints: Dict[str, str] = {}
        for alias in EXPECTED_COLLECTION_ALIASES:
            stored = feeds.get(alias)
            checkpoint = self._normalize_checkpoint(stored)
            if stored is not None and checkpoint is None:
                self.logger.warning(
                    "[CONNECTOR] Ignoring unparseable stored checkpoint",
                    {"feed": alias, "checkpoint": stored},
                )
            checkpoint = checkpoint or legacy
            if checkpoint:
                checkpoints[alias] = checkpoint

        if "last_run" in state:
            self.logger.info(
                "[CONNECTOR] Migrating legacy last_run state to per-feed checkpoints",
                {"last_run": state.get("last_run")},
            )
            state.pop("last_run", None)
            state["feeds"] = {**feeds, **checkpoints}
            self.helper.set_state(state)
        return checkpoints

    @staticmethod
    def _resume_timestamp(checkpoint: str) -> str:
        """``added_after`` for resuming from a checkpoint (see CHECKPOINT_OVERLAP)."""
        parsed = parse_stix_timestamp(checkpoint)
        return (parsed - CHECKPOINT_OVERLAP).strftime(LUMINAR_DATE_FORMAT)

    def _save_checkpoint(self, alias: str, checkpoint: str) -> None:
        normalized = self._normalize_checkpoint(checkpoint)
        if normalized is None:
            # Never persist a value that cannot be reused as added_after.
            self.logger.warning(
                "[CONNECTOR] Unparseable TAXII checkpoint; previous one kept",
                {"feed": alias, "checkpoint": checkpoint},
            )
            return
        checkpoint = normalized
        state = self.helper.get_state() or {}
        feeds = dict(state.get("feeds") or {})
        previous = parse_stix_timestamp(feeds.get(alias))
        if previous is not None and parse_stix_timestamp(checkpoint) <= previous:
            # Re-read overlap window: never move a checkpoint backwards.
            return
        feeds[alias] = checkpoint
        state["feeds"] = feeds
        self.helper.set_state(state)
        # set_state() only updates memory; the helper's ping thread persists it
        # later. Push it now so a crash cannot lose already-ingested progress.
        try:
            self.helper.force_ping()
        except Exception as err:  # pylint: disable=broad-exception-caught
            self.logger.warning(
                "[CONNECTOR] Could not persist checkpoint immediately; "
                "it will be sent with the next ping",
                {"feed": alias, "error": f"{err.__class__.__name__}: {err}"},
            )

    # ----- load -----

    @staticmethod
    def _split_phases(
        stix_objects: List[Dict[str, Any]],
    ) -> List[Tuple[str, List[Dict[str, Any]]]]:
        """Entities (incl. author and markings) -> relationships/sightings ->
        containers (reports and groupings may reference relationships)."""
        entities, relationships, containers = [], [], []
        for stix_object in stix_objects:
            if stix_object["type"] in SRO_TYPES:
                relationships.append(stix_object)
            elif stix_object["type"] in PHASE_CONTAINER_TYPES:
                containers.append(stix_object)
            else:
                entities.append(stix_object)
        phases = [
            ("entities", entities),
            ("relationships", relationships),
            ("containers", containers),
        ]
        return [(name, objects) for name, objects in phases if objects]

    def _send_batch(self, stix_objects: List[Dict[str, Any]], work_id: str) -> int:
        """Send one converted batch phase by phase. Returns messages sent."""
        phases = self._split_phases(stix_objects)
        sent = 0
        for index, (phase, objects) in enumerate(phases):
            # Later phases reference objects of earlier phases that are not in
            # their own bundle: pycti's cleanup would strip those references.
            # The converter already guarantees reference integrity per batch.
            sent += self._send_bundle(
                objects, work_id, cleanup_inconsistent=phase == "entities"
            )
            if index < len(phases) - 1:
                self._wait_for_ingestion(work_id, phase)
        return sent

    def _send_bundle(
        self,
        stix_objects: List[Dict[str, Any]],
        work_id: str,
        cleanup_inconsistent: bool,
    ) -> int:
        try:
            bundle = self.helper.stix2_create_bundle(stix_objects)
            bundles_sent = self.helper.send_stix2_bundle(
                bundle,
                work_id=work_id,
                update=True,
                cleanup_inconsistent_bundle=cleanup_inconsistent,
            )
        except Exception as err:
            raise IngestionError(
                f"Failed to send bundle to OpenCTI: {err.__class__.__name__}: {err}"
            ) from err
        return len(bundles_sent)

    def _wait_for_ingestion(self, work_id: Optional[str], phase: str) -> None:
        """Block until OpenCTI has processed every message expected by the work
        so far (errors count as processed). Gives up when the processed count
        has not increased for INGESTION_STALL_TIMEOUT and continues: the next
        phase may then hit missing references, which OpenCTI reports on the
        work."""
        if not work_id:
            return
        last_progress_at = last_log = time.monotonic()
        last_processed = -1
        while True:
            try:
                work = self.helper.api.work.get_work(work_id)
            except Exception as err:  # pylint: disable=broad-exception-caught
                self.logger.warning(
                    "[CONNECTOR] Could not read work progress",
                    {"error": f"{err.__class__.__name__}: {err}"},
                )
                work = None
            if work == {}:
                self.logger.warning(
                    "[CONNECTOR] Work not found; not waiting for ingestion",
                    {"work_id": work_id},
                )
                return
            tracking = (work or {}).get("tracking") or {}
            expected = tracking.get("import_expected_number") or 0
            processed = tracking.get("import_processed_number") or 0
            if work and processed >= expected:
                return
            now = time.monotonic()
            if processed > last_processed:
                last_processed, last_progress_at = processed, now
            elif now - last_progress_at > INGESTION_STALL_TIMEOUT.total_seconds():
                self.logger.warning(
                    "[CONNECTOR] Ingestion made no progress; sending next phase",
                    {"phase": phase, "expected": expected, "processed": processed},
                )
                return
            if now - last_log >= INGESTION_PROGRESS_LOG_SECONDS:
                self.logger.info(
                    "[CONNECTOR] Waiting for OpenCTI to ingest phase",
                    {"phase": phase, "expected": expected, "processed": processed},
                )
                last_log = now
            time.sleep(INGESTION_POLL_SECONDS)

    # ----- per-feed pipeline -----

    def _process_feed(
        self,
        alias: str,
        checkpoint: Optional[str],
        schema: RelationshipSchema,
        work_id: str,
        run_stats: ConversionStats,
    ) -> Optional[str]:
        """Run extract -> transform -> load for one feed.

        Returns an error message when the feed stopped early (its checkpoint
        stays at the last ingested batch), None on success. Raises
        IngestionError when OpenCTI cannot accept data.
        """
        added_after = self._resume_timestamp(checkpoint) if checkpoint else None
        self.logger.info(
            "[CONNECTOR] Processing feed",
            {
                "feed": alias,
                "checkpoint": checkpoint,
                "added_after": added_after or self.initial_fetch_date,
            },
        )
        batches = 0
        bundles = 0
        try:
            for result in self.client.get_objects(alias, added_after=added_after):
                raw_objects = result["results"]["data"]
                batch_checkpoint = result["results"]["last_success"]

                if raw_objects:
                    batches += 1
                    try:
                        stix_objects, stats = self.converter.convert_batch(
                            alias, raw_objects, schema, datetime.now(timezone.utc)
                        )
                    except Exception as err:  # pylint: disable=broad-exception-caught
                        # Unexpected transform failure (object-level errors are
                        # handled inside the converter). Stop this feed without
                        # advancing its checkpoint so the batch is retried.
                        self.logger.error(
                            "[CONNECTOR] Batch transformation failed",
                            {
                                "feed": alias,
                                "error": f"{err.__class__.__name__}: {err}",
                            },
                        )
                        return f"transformation failed: {err}"
                    run_stats.merge(stats)
                    self.logger.info(
                        "[CONNECTOR] Batch converted",
                        {"feed": alias, "batch": batches, **stats.as_dict()},
                    )
                    if stix_objects:
                        bundles += self._send_batch(stix_objects, work_id)

                if not result["results"].get("hydration_complete", True):
                    # Referenced objects could not be fetched, so some
                    # relationships/refs were dropped from this batch. Keep the
                    # checkpoint so the next run re-reads it (re-sending the
                    # objects already ingested is idempotent).
                    message = "referenced-object lookup (match[id]) failed"
                    self.logger.error(
                        "[CONNECTOR] Feed stopped: incomplete batch, checkpoint kept",
                        {"feed": alias, "error": message},
                    )
                    return result["error"] or message
                if batch_checkpoint:
                    self._save_checkpoint(alias, batch_checkpoint)
                if result["error"]:
                    self.logger.error(
                        "[CONNECTOR] Feed extraction stopped early",
                        {"feed": alias, "error": result["error"]},
                    )
                    return result["error"]
        except (LuminarAPIError, ValueError) as err:
            self.logger.error(
                "[CONNECTOR] Feed extraction failed",
                {"feed": alias, "error": str(err)},
            )
            return str(err)

        self.logger.info(
            "[CONNECTOR] Feed completed",
            {"feed": alias, "batches": batches, "bundles_sent": bundles},
        )
        return None

    # ----- run -----

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.logger.info(
            "[CONNECTOR] Starting run", {"connector_name": self.helper.connect_name}
        )
        work_id = None
        try:
            checkpoints = self._load_checkpoints()
            schema = RelationshipSchema.from_platform(self.helper.api, self.logger)

            friendly_name = (
                f"{self.helper.connect_name} run @ "
                f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}"
            )
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name, is_multipart=True
            )

            run_stats = ConversionStats()
            errors: List[str] = []
            for alias in EXPECTED_COLLECTION_ALIASES:
                error = self._process_feed(
                    alias, checkpoints.get(alias), schema, work_id, run_stats
                )
                if error:
                    errors.append(f"{alias}: {error}")

            unprocessed = sorted(
                set(self.client.taxi_collection) - set(EXPECTED_COLLECTION_ALIASES)
            )
            if unprocessed:
                self.logger.info(
                    "[CONNECTOR] Luminar collections not processed by this connector",
                    {"aliases": unprocessed},
                )

            state = self.helper.get_state() or {}
            state["last_run_end"] = datetime.now(timezone.utc).strftime(
                LUMINAR_DATE_FORMAT
            )
            self.helper.set_state(state)

            message = (
                f"{self.helper.connect_name} run finished: "
                f"{run_stats.output} objects ingested, {run_stats.expired} expired "
                f"skipped, {run_stats.malformed} malformed skipped"
            )
            if errors:
                message += f"; errors: {'; '.join(errors)}"
            self.logger.info(
                "[CONNECTOR] Run completed",
                {"errors": errors, **run_stats.as_dict()},
            )
            self.helper.api.work.to_processed(work_id, message, in_error=bool(errors))

        except (KeyboardInterrupt, SystemExit):
            self.logger.info(
                "[CONNECTOR] Connector stopped",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:  # pylint: disable=broad-exception-caught
            self.logger.error(
                "[CONNECTOR] Run failed",
                {"error": f"{err.__class__.__name__}: {err}"},
            )
            if work_id:
                self.helper.api.work.to_processed(
                    work_id, f"Run failed: {err}", in_error=True
                )

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.duration_period,
        )

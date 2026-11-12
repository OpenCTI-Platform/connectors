"""Entry point class for the Checkfirst external-import connector."""

import sys
import time
from concurrent.futures import Future, ProcessPoolExecutor, ThreadPoolExecutor
from contextlib import nullcontext
from datetime import datetime, timezone
from typing import Any

from checkfirst_client import CheckfirstClient
from checkfirst_client.api_models import Article
from connector.connector_state import ConnectorState
from connector.converter_to_stix import ConversionError, ConverterToStix
from connector.parallel_convert import convert_row_in_worker, init_convert_worker
from connector.settings import ConnectorSettings
from connectors_sdk.models import BaseIdentifiedEntity
from pycti import OpenCTIConnectorHelper
from utils.run_reporter import SkipReason, run_reporter


class BundleSendError(Exception):
    pass


class CheckfirstImportConnector:
    """Minimal external-import connector implementation.

    This follows the standard external-import connector template:
    - `process_message()` does one ingestion pass
    - `run()` schedules runs via `OpenCTIConnectorHelper.schedule_iso()`

    The actual API ingestion + STIX mapping is implemented under
    `checkfirst_dataset/` and reused here.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.logger = self.helper.connector_logger

        self.state = ConnectorState(helper)
        self.api_client = CheckfirstClient(
            helper=helper,
            base_url=self.config.checkfirst.api_url,
            api_key=self.config.checkfirst.api_key.get_secret_value(),
        )
        self.converter = ConverterToStix(
            helper=helper,
            tlp_level=self.config.checkfirst.tlp_level.value,
        )

    def _create_pravda_infrastructure_entities(self) -> list[BaseIdentifiedEntity]:
        """Create entities for known Pravda network infrastructure.
        Called only on a fresh walk (no cursor, or force_reprocess).
        """
        self.logger.info(
            "[CONNECTOR] Creating Pravda network infrastructure (first run)"
        )

        campaign, attributed_to = self.converter.get_campaign_for_year(year=2023)
        pravda_network_entities = self.converter.convert_pravda_network_infrastructure(
            campaign
        )

        return [campaign, attributed_to] + pravda_network_entities

    def _send_infrastructure_bundle(self) -> None:
        """Send a one-off bundle of known Pravda network infrastructure objects.
        Executed only on a fresh walk (no cursor, or force_reprocess).
        """
        self.logger.info("[CONNECTOR] Sending Pravda network infrastructure bundle")
        octi_objects = self._create_pravda_infrastructure_entities()
        self._send_bundle(octi_objects)
        run_reporter.bundles_sent += 1

        self.logger.info(
            "[CONNECTOR] Pravda network infrastructure sent to OpenCTI",
        )

    def _create_row_entities(self, row: Article) -> list[BaseIdentifiedEntity]:
        self.logger.debug(
            "[CONNECTOR] Converting row to OpenCTI objects",
            {"row_number": row.row_number, "row_id": row.id},
        )

        campaign, attributed_to = self.converter.get_campaign_for_year(
            year=row.published_date.year
        )
        article_entities = self.converter.convert_article(row, campaign)

        return [campaign, attributed_to] + article_entities

    def _convert_batch(
        self,
        rows: list[Article],
        pool: ProcessPoolExecutor | None,
    ) -> list[tuple[Article, list[BaseIdentifiedEntity] | None, str | None]]:
        """Convert a batch of articles, optionally via a process pool.

        Result order matches ``rows`` so the watermark can advance contiguously.
        """
        if not rows:
            return []

        if pool is None:
            results: list[
                tuple[Article, list[BaseIdentifiedEntity] | None, str | None]
            ] = []
            for row in rows:
                try:
                    results.append((row, self._create_row_entities(row), None))
                except ConversionError as err:
                    results.append((row, None, str(err)))
            return results

        worker_results = list(pool.map(convert_row_in_worker, rows))
        return [
            (row, entities, error)
            for row, (_row_id, _row_number, entities, error) in zip(
                rows, worker_results, strict=True
            )
        ]

    def _prepare_rows_bundle(
        self, octi_objects: set[BaseIdentifiedEntity]
    ) -> list[BaseIdentifiedEntity]:
        """Prepare the list of OCTI objects to be sent in a bundle.

        Deduplicates by STIX id (keep first). For Channels, merge external
        references onto the kept instance so article URLs are not lost.
        """
        self.logger.debug(
            "[CONNECTOR] Deduplicating OpenCTI objects for bundle",
            {"octi_objects_count": len(octi_objects)},
        )

        by_id: dict[str, BaseIdentifiedEntity] = {}
        for octi_object in octi_objects:
            existing = by_id.get(octi_object.id)
            if existing is None:
                by_id[octi_object.id] = octi_object
                continue
            if (
                octi_object.id.startswith("channel--")
                and octi_object.external_references
            ):
                if existing.external_references is None:
                    existing.external_references = list(octi_object.external_references)
                else:
                    existing.external_references.extend(octi_object.external_references)

        bundle_objects = list(by_id.values())
        self.logger.debug(
            "[CONNECTOR] Bundle ready to be sent",
            {"bundle_objects_count": len(bundle_objects)},
        )

        return bundle_objects

    def _persist_cursor(self, cursor: str | None) -> None:
        """Save the exclusive `_id` watermark after a successful bundle send."""
        if not cursor:
            return
        self.state.last_cursor = cursor
        self.state.save()

    def _prepare_and_send_bundle(
        self,
        octi_objects: set[BaseIdentifiedEntity],
        *,
        rows_count: int,
        last_cursor: str | None,
    ) -> dict[str, Any]:
        """Prepare, serialize, and send one bundle; return timing breakdown.

        Safe to run in a background thread so the main loop can convert the next
        batch meanwhile. Cursor persistence stays on the main thread after success.
        """
        prepare_started = time.perf_counter()
        bundle_objects = self._prepare_rows_bundle(octi_objects)
        prepare_seconds = time.perf_counter() - prepare_started

        self.logger.info(
            "[BENCH] Bundle prepare completed",
            {
                "rows_count": rows_count,
                "octi_objects_count": len(octi_objects),
                "bundle_objects_count": len(bundle_objects),
                "last_cursor": last_cursor,
                "prepare_seconds": round(prepare_seconds, 3),
            },
        )

        send_timings = self._send_bundle(bundle_objects)
        return {
            "rows_count": rows_count,
            "last_cursor": last_cursor,
            "prepare_seconds": round(prepare_seconds, 3),
            **send_timings,
        }

    def _send_rows_bundles(
        self,
        after: str | None,
        pool: ProcessPoolExecutor | None = None,
    ) -> None:
        self.logger.info(
            "[CONNECTOR] Fetching data from API",
            {
                "api_endpoint": self.config.checkfirst.api_endpoint,
                "after": after,
                "convert_workers": self.config.checkfirst.convert_workers,
                "convert_batch_size": self.config.checkfirst.convert_batch_size,
                "bundle_size": self.config.checkfirst.bundle_size,
            },
        )

        # Set of _unique_ OCTI objects to be sent
        # (uniqueness is determined by comparing objects' whole content, not just their IDs)
        octi_objects: set[BaseIdentifiedEntity] = set()

        rows_yielded = 0
        rows_in_bundle = 0
        # Last article `_id` seen in the current (or just-finished) bundle.
        # Advanced for mapped and skipped rows alike so a bad row cannot stall
        # the watermark.
        last_row_id: str | None = None

        batch_size = int(self.config.checkfirst.convert_batch_size)
        bundle_size = int(self.config.checkfirst.bundle_size)
        pending_rows: list[Article] = []

        # At most one in-flight prepare+send so the watermark stays ordered.
        # Convert (process pool) overlaps with this thread's work.
        in_flight: Future[dict[str, Any]] | None = None
        in_flight_cursor: str | None = None

        def await_in_flight_send() -> None:
            """Block until the pending send finishes, then persist its cursor."""
            nonlocal in_flight, in_flight_cursor
            if in_flight is None:
                return

            wait_started = time.perf_counter()
            already_done = in_flight.done()
            try:
                timings = in_flight.result()
            except Exception as err:
                in_flight = None
                in_flight_cursor = None
                if isinstance(err, BundleSendError):
                    raise
                raise BundleSendError(err) from err

            wait_seconds = time.perf_counter() - wait_started
            run_reporter.bundles_sent += 1
            self._persist_cursor(in_flight_cursor)

            self.logger.info(
                "[BENCH] In-flight bundle committed",
                {
                    "wait_seconds": round(wait_seconds, 3),
                    "already_done": already_done,
                    "overlapped": already_done,
                    "last_cursor": in_flight_cursor,
                    "prepare_seconds": timings.get("prepare_seconds"),
                    "to_stix2_seconds": timings.get("to_stix2_seconds"),
                    "initiate_work_seconds": timings.get("initiate_work_seconds"),
                    "create_bundle_seconds": timings.get("create_bundle_seconds"),
                    "send_bundle_seconds": timings.get("send_bundle_seconds"),
                    "to_processed_seconds": timings.get("to_processed_seconds"),
                    "total_send_seconds": timings.get("total_seconds"),
                    "objects_count": timings.get("objects_count"),
                    "rows_count": timings.get("rows_count"),
                },
            )
            in_flight = None
            in_flight_cursor = None

        def submit_bundle_send() -> None:
            """Hand current objects to the send thread and start a new accumulator."""
            nonlocal octi_objects, rows_in_bundle, in_flight, in_flight_cursor

            cursor = last_row_id or self.api_client.last_seen_id
            self.logger.info(
                "Submitting bundle send (overlap enabled)",
                {
                    "octi_objects_count": len(octi_objects),
                    "rows_count": rows_in_bundle,
                    "last_cursor": cursor,
                },
            )

            # One in-flight send at a time (ordered watermark).
            await_in_flight_send()

            owned_objects = octi_objects
            owned_rows = rows_in_bundle
            owned_cursor = cursor
            octi_objects = set()
            rows_in_bundle = 0

            in_flight_cursor = owned_cursor
            in_flight = send_executor.submit(
                self._prepare_and_send_bundle,
                owned_objects,
                rows_count=owned_rows,
                last_cursor=owned_cursor,
            )

        with ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="checkfirst-send"
        ) as send_executor:

            def flush_convert_batch() -> None:
                nonlocal rows_in_bundle, last_row_id, pending_rows, rows_yielded

                if not pending_rows:
                    return

                batch = pending_rows
                pending_rows = []

                send_in_flight = in_flight is not None and not in_flight.done()
                convert_started = time.perf_counter()
                converted = self._convert_batch(batch, pool)
                convert_seconds = time.perf_counter() - convert_started

                mapped_in_batch = sum(
                    1 for _row, entities, error in converted if error is None
                )
                self.logger.info(
                    "[BENCH] Convert batch completed",
                    {
                        "rows": len(batch),
                        "mapped": mapped_in_batch,
                        "failed": len(batch) - mapped_in_batch,
                        "duration_seconds": round(convert_seconds, 3),
                        "rows_per_second": (
                            round(len(batch) / convert_seconds, 2)
                            if convert_seconds > 0
                            else None
                        ),
                        "convert_workers": self.config.checkfirst.convert_workers,
                        "overlapped_with_send": send_in_flight,
                    },
                )

                for row, row_octi_objects, error in converted:
                    self.logger.debug(
                        "[CONNECTOR] Processing row from API",
                        {"row_number": row.row_number, "row_id": row.id},
                    )

                    rows_yielded += 1
                    run_reporter.rows_seen += 1
                    last_row_id = row.id

                    if error is not None or row_octi_objects is None:
                        run_reporter.skip(SkipReason.ROW_MAPPING_ERROR)
                        self.logger.warning(
                            "Skipping row due to conversion error",
                            {
                                "row_number": row.row_number,
                                "row_id": row.id,
                                "error": error,
                            },
                        )
                        continue

                    # Rows share many same entities, so only original objects are added
                    # (OCTI models are hashable and comparable for this very purpose)
                    for row_octi_object in row_octi_objects:
                        if row_octi_object not in octi_objects:
                            octi_objects.add(row_octi_object)

                    run_reporter.rows_mapped += 1
                    rows_in_bundle += 1

                    # Hand a full bundle to the send thread; keep converting.
                    if len(octi_objects) >= bundle_size:
                        submit_bundle_send()

            for row in self.api_client.iter_api_rows(
                api_endpoint=self.config.checkfirst.api_endpoint,
                after=after,
                since=self.config.checkfirst.since,
                until=self.config.checkfirst.until,
                max_row_bytes=self.config.checkfirst.max_row_bytes,
            ):
                pending_rows.append(row)
                if len(pending_rows) >= batch_size:
                    flush_convert_batch()

            flush_convert_batch()
            await_in_flight_send()

            # Every fetched row has now been converted or skipped, and every
            # bundle sent: the last `_id` seen by the client, skipped tail
            # included, is a safe watermark. (Intermediate sends use
            # `last_row_id` instead, so unsent rows are never checkpointed.)
            watermark = self.api_client.last_seen_id or last_row_id

            if not rows_yielded and not self.api_client.last_seen_id:
                # Log and let the connector end the run
                self.logger.info("No rows fetched from API", {"after": after})
            else:
                # Send remaining rows (octi_objects may be empty if the tail was
                # only skipped rows — still advance the cursor past them).
                if octi_objects:
                    self.logger.info(
                        "Sending final bundle",
                        {
                            "octi_objects_count": len(octi_objects),
                            "rows_count": rows_in_bundle,
                            "last_cursor": watermark,
                        },
                    )
                    self._prepare_and_send_bundle(
                        octi_objects,
                        rows_count=rows_in_bundle,
                        last_cursor=watermark,
                    )
                    run_reporter.bundles_sent += 1
                self._persist_cursor(watermark)

    def _send_bundle(
        self,
        octi_objects: list[BaseIdentifiedEntity],
    ) -> dict[str, Any]:
        """Assemble and send a STIX bundle to OpenCTI.

        Returns a timing breakdown for ``[BENCH]`` logs. Does not persist state or
        bump ``run_reporter.bundles_sent`` (caller does that on the main thread).

        Note: ``to_stix2_object()`` cannot run in a process pool — stix2 custom
        observables are local classes and are not picklable.
        """
        try:
            if not octi_objects:
                return {
                    "objects_count": 0,
                    "to_stix2_seconds": 0.0,
                    "initiate_work_seconds": 0.0,
                    "create_bundle_seconds": 0.0,
                    "send_bundle_seconds": 0.0,
                    "to_processed_seconds": 0.0,
                    "total_seconds": 0.0,
                    "sent_bundles": 0,
                }

            total_started = time.perf_counter()
            objects_for_stix = self.converter.required_objects + octi_objects

            to_stix_started = time.perf_counter()
            stix_objects = [obj.to_stix2_object() for obj in objects_for_stix]
            to_stix2_seconds = time.perf_counter() - to_stix_started

            self.logger.info(
                "[CONNECTOR] Sending STIX objects to OpenCTI...",
                {"objects_count": len(stix_objects)},
            )

            now = datetime.now(tz=timezone.utc)
            initiate_started = time.perf_counter()
            work_id = self.helper.api.work.initiate_work(
                connector_id=self.config.connector.id,
                friendly_name=f"{self.config.connector.name} - {now.isoformat()}",
            )
            initiate_work_seconds = time.perf_counter() - initiate_started

            create_started = time.perf_counter()
            bundle = self.helper.stix2_create_bundle(stix_objects)
            create_bundle_seconds = time.perf_counter() - create_started

            send_started = time.perf_counter()
            sent_bundles = self.helper.send_stix2_bundle(
                bundle=bundle,
                work_id=work_id,
                cleanup_inconsistent_bundle=True,
            )
            send_bundle_seconds = time.perf_counter() - send_started

            run_current_summary = run_reporter.to_summary()
            processed_started = time.perf_counter()
            self.helper.api.work.to_processed(
                work_id=work_id,
                message=run_current_summary,
            )
            to_processed_seconds = time.perf_counter() - processed_started
            total_seconds = time.perf_counter() - total_started

            timings = {
                "sent_bundles": len(sent_bundles),
                "objects_count": len(stix_objects),
                "to_stix2_seconds": round(to_stix2_seconds, 3),
                "initiate_work_seconds": round(initiate_work_seconds, 3),
                "create_bundle_seconds": round(create_bundle_seconds, 3),
                "send_bundle_seconds": round(send_bundle_seconds, 3),
                "to_processed_seconds": round(to_processed_seconds, 3),
                "total_seconds": round(total_seconds, 3),
            }
            self.logger.info("[BENCH] STIX bundle sent to OpenCTI", timings)
            return timings
        except Exception as err:
            self.logger.error("[CONNECTOR] Bundle send failed", {"error": str(err)})
            run_reporter.error(SkipReason.BUNDLE_SEND_ERROR)

            raise BundleSendError(err) from err

    def process_message(self) -> None:
        """One connector run: fetch API data and push bundles to OpenCTI."""
        self.logger.info(
            "[CONNECTOR] Running connector...",
            {
                "connector_name": self.config.connector.name,
                "convert_workers": self.config.checkfirst.convert_workers,
                "convert_batch_size": self.config.checkfirst.convert_batch_size,
                "bundle_size": self.config.checkfirst.bundle_size,
            },
        )

        # Ensure clean metrics for each run
        run_reporter.reset()
        run_started = time.perf_counter()

        workers = self.config.checkfirst.convert_workers
        pool_context = (
            ProcessPoolExecutor(
                max_workers=workers,
                initializer=init_convert_worker,
                initargs=(str(self.config.checkfirst.tlp_level),),
            )
            if workers > 1
            else nullcontext()
        )

        try:
            with pool_context as pool:
                # Get the current state
                current_state = self.state.load()
                if current_state.last_run is not None:
                    self.logger.info(
                        "[CONNECTOR] Connector last run",
                        {"last_run": current_state.last_run},
                    )
                else:
                    self.logger.info("[CONNECTOR] Connector has never run...")

                # Determine the exclusive `_id` cursor for this run.
                # force_reprocess clears the watermark and restarts from the start.
                # Legacy `last_page` state (offset pagination) is ignored: page
                # numbers are meaningless under keyset pagination, and STIX IDs
                # are deterministic so a fresh walk does not create duplicates.
                if self.config.checkfirst.force_reprocess:
                    after = None
                    self.state.last_cursor = None
                    self.logger.info(
                        "[CONNECTOR] Force reprocess enabled; starting from the beginning"
                    )
                else:
                    after = current_state.last_cursor

                # On a fresh walk, send a one-off bundle with known Pravda network
                # infrastructure entities.
                if after is None:
                    self._send_infrastructure_bundle()
                else:
                    self.logger.info(
                        "[CONNECTOR] Resuming from cursor", {"after": after}
                    )

                # On each run, fetch rows from the API and send bundle of mapped STIX objects
                self._send_rows_bundles(
                    after,
                    pool if isinstance(pool, ProcessPoolExecutor) else None,
                )

        except BundleSendError:
            # Bundle send failure is logged in `_send_bundle` and can't be recovered,
            # so we just end the run here and go to `finally` statement to get run summary.
            # Cursor was not advanced past the failed bundle (no gaps).
            pass
        except (KeyboardInterrupt, SystemExit):
            self.logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.config.connector.name},
            )
            sys.exit(0)
        except Exception as err:
            self.logger.error(
                "[CONNECTOR] Unexpected error. See connector's log for more details.",
                {"error": str(err)},
            )
        finally:
            self.state.last_run = datetime.now(timezone.utc)
            self.state.save()

            run_summary = run_reporter.to_summary()
            self.logger.info(
                "[BENCH] Run summary",
                {
                    "summary": run_summary,
                    "duration_seconds": round(time.perf_counter() - run_started, 3),
                    "convert_workers": workers,
                    "bundle_size": self.config.checkfirst.bundle_size,
                },
            )

            run_reporter.reset()

    def run(self) -> None:
        """Start the connector using the standard scheduler."""
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,  # type: ignore
        )

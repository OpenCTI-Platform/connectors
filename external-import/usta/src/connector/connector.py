"""
USTA OpenCTI External Import Connector.

Orchestrates the full import lifecycle:
  1. Read / initialize connector state
  2. Fetch IOCs from all enabled USTA endpoints (paginated)
  3. Convert to STIX 2.1 objects via ConverterToStix
  4. Send bundles to OpenCTI in batches
  5. Update state on success
"""

from __future__ import annotations

import io
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from itertools import islice
from typing import Any, Callable
from urllib.parse import unquote, urlparse

import requests
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from usta_client import UstaClient, UstaClientError

_MAX_PDF_BYTES = 50 * 1024 * 1024  # 50 MB


@dataclass
class _FeedConfig:
    """
    Runtime configuration for a single USTA data feed.

    Attributes:
        label: Human-readable feed name used in log messages and work item names.
        state_key: Key under which the per-feed cursor (last ``created``
            timestamp) is persisted in the OpenCTI connector state.
        enabled: When ``False`` the feed is skipped entirely this run.
        collect: Callable that accepts a start-timestamp string and returns
            ``(stix_objects, last_created_cursor)``.
    """

    label: str
    state_key: str
    enabled: bool
    collect: Callable[[str], tuple[list, str | None]]


class UstaConnector:
    """
    External Import connector for USTA Threat Intelligence.

    Imports six data families:
      - Malicious URLs  (C2 infrastructure, RAT callbacks, stealer panels)
      - Phishing Sites  (credential harvesting domains)
      - Malware Hashes  (file indicators for known malware families)
      - Compromised Credentials  (account takeover prevention tickets)
      - Credit Card Tickets      (fraud intelligence)
      - Deep Sight Tickets       (intelligence reports: ransomware, leaks, APT activity)
    """

    # Maximum objects per STIX bundle before splitting into a new batch
    BUNDLE_BATCH_SIZE = 5000

    # State keys
    STATE_KEY_LAST_RUN_START = "last_run_start"
    STATE_KEY_LAST_RUN_WITH_DATA = "last_run_with_data"
    STATE_KEY_MALICIOUS_URLS_CURSOR = "malicious_urls_last_created"
    STATE_KEY_PHISHING_SITES_CURSOR = "phishing_sites_last_created"
    STATE_KEY_MALWARE_HASHES_CURSOR = "malware_hashes_last_created"
    STATE_KEY_COMPROMISED_CREDS_CURSOR = "compromised_creds_last_created"
    STATE_KEY_CREDIT_CARDS_CURSOR = "credit_cards_last_created"
    STATE_KEY_DEEP_SIGHT_CURSOR = "deep_sight_last_created"

    def __init__(
        self,
        config: ConnectorSettings,
        helper: OpenCTIConnectorHelper,
    ) -> None:
        """
        Args:
            config: Fully validated connector settings, including USTA API
                credentials and per-feed enable flags.
            helper: Initialised OpenCTI connector helper — used for API calls,
                state management, bundle sending, and structured logging.
        """
        self.config = config
        self.helper = helper
        self.work_id: str | None = None

        # API client
        self.client = UstaClient(
            helper=self.helper,
            base_url=str(self.config.usta.api_base_url),
            api_key=self.config.usta.api_key.get_secret_value(),
            page_size=self.config.usta.page_size,
        )

        # STIX converter
        self.converter = ConverterToStix(
            helper=self.helper,
            author_name="USTA",
            tlp_level=self.config.usta.tlp_level,
            confidence_level=self.config.usta.confidence_level,
            store_credential_password=self.config.usta.store_credential_password,
        )

    # ------------------------------------------------------------------
    # State helpers
    # ------------------------------------------------------------------

    def _get_state(self) -> dict[str, Any]:
        """Retrieve current state or return an empty dict."""
        state = self.helper.get_state()
        return state if state is not None else {}

    def _compute_default_start(self) -> str:
        """
        Compute the default start timestamp for the very first run,
        based on the configured import_start_date duration.
        """
        delta: timedelta = self.config.usta.import_start_date
        start_dt = datetime.now(timezone.utc) - delta
        return start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _get_start_for_feed(self, state: dict, state_key: str) -> str:
        """
        Determine the start timestamp for a specific feed.
        Uses per-feed cursor if available, otherwise falls back to
        default start date.
        """
        cursor_value = state.get(state_key)
        if cursor_value:
            return cursor_value
        return self._compute_default_start()

    # ------------------------------------------------------------------
    # Work management
    # ------------------------------------------------------------------

    def _initiate_work(self, friendly_name: str) -> str:
        """Create a new work item in OpenCTI."""
        self.work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        self.helper.connector_logger.info(
            "[CONNECTOR] Work initiated",
            {"work_id": self.work_id, "name": friendly_name},
        )
        return self.work_id

    def _complete_work(self, message: str, in_error: bool = False) -> None:
        """Mark the current work item as completed or failed."""
        if self.work_id:
            self.helper.api.work.to_processed(self.work_id, message, in_error=in_error)
            self.helper.connector_logger.info(
                "[CONNECTOR] Work completed",
                {"work_id": self.work_id, "message": message, "in_error": in_error},
            )
            self.work_id = None

    # ------------------------------------------------------------------
    # Bundle sending with batching
    # ------------------------------------------------------------------

    def _send_stix_objects(
        self,
        stix_objects: list[Any],
        work_id: str,
        feed_label: str,
    ) -> int:
        """
        Send STIX objects to OpenCTI in batches of up to ``BUNDLE_BATCH_SIZE``.

        Every batch is augmented with the connector author Identity and all
        four standard TLP marking definitions so that
        ``cleanup_inconsistent_bundle`` never discards objects whose per-record
        TLP (e.g. ``amber`` on a Deep Sight ticket) differs from the
        connector-level default.

        Args:
            stix_objects: Flat list of STIX objects to send.
            work_id: OpenCTI work item ID to associate with the bundle.
            feed_label: Human-readable feed name used in log messages.

        Returns:
            Total number of STIX objects sent (author and TLP markings
            injected per batch are not counted).
        """
        if not stix_objects:
            return 0

        total_sent = 0
        batch_num = 0

        stix_iter = iter(stix_objects)

        while batch := list(islice(stix_iter, self.BUNDLE_BATCH_SIZE)):
            batch_num += 1

            # Include author + all TLP markings in every batch so that
            # cleanup_inconsistent_bundle never drops objects whose per-record
            # TLP (e.g. amber on a deep-sight ticket) differs from the
            # connector-level default.
            batch_with_meta = (
                batch
                + [
                    self.converter.author,
                ]
                + list(self.converter.TLP_MARKINGS)
            )

            bundle = self.helper.stix2_create_bundle(batch_with_meta)
            self.helper.send_stix2_bundle(
                bundle,
                work_id=work_id,
                cleanup_inconsistent_bundle=True,
            )

            total_sent += len(batch)
            self.helper.connector_logger.info(
                f"[CONNECTOR] {feed_label} batch sent",
                {
                    "batch": batch_num,
                    "objects_in_batch": len(batch),
                    "total_sent": total_sent,
                },
            )

        return total_sent

    # ------------------------------------------------------------------
    # Generic feed collector (DRY core)
    # ------------------------------------------------------------------

    def _collect_feed(  # pylint: disable=too-many-locals
        self,
        client_method: Callable[..., Any],
        converter_method: Callable[[dict], list],
        label: str,
        start: str,
    ) -> tuple[list[Any], str | None]:
        """
        Collect one data feed, deduplicate STIX objects by ID, and return them.

        Deduplication is done in-memory using each object's STIX ID so that
        shared SDOs (e.g. the same Malware SDO referenced by many records) are
        only included once per bundle, reducing bundle size and server-side load.

        Returns:
            Tuple of (stix_objects, last_created_timestamp).
        """
        stix_objects: list[Any] = []
        seen_ids: set[str] = set()
        last_created: str | None = None
        record_count = 0
        failed_count = 0

        for page in client_method(start=start):
            for record in page:
                try:
                    for obj in converter_method(record):
                        if obj.id not in seen_ids:
                            seen_ids.add(obj.id)
                            stix_objects.append(obj)
                    record_count += 1
                    created = record.get("created")
                    if created:
                        last_created = created
                except Exception as e:  # pylint: disable=broad-exception-caught
                    failed_count += 1
                    self.helper.connector_logger.warning(
                        f"[CONNECTOR] Failed to convert {label} record — skipping",
                        {
                            "record_id": record.get("id"),
                            "error_type": type(e).__name__,
                            "error": str(e),
                        },
                    )

        self.helper.connector_logger.info(
            f"[CONNECTOR] {label} collection finished",
            {
                "records_ok": record_count,
                "records_failed": failed_count,
                "stix_objects": len(stix_objects),
                "last_created_cursor": last_created,
            },
        )
        return stix_objects, last_created

    # ------------------------------------------------------------------
    # Per-feed collection methods (thin delegates to _collect_feed)
    # ------------------------------------------------------------------

    def _collect_malicious_urls(self, start: str) -> tuple[list[Any], str | None]:
        """Collect malicious URL IOCs and convert to STIX."""
        return self._collect_feed(
            self.client.get_malicious_urls,
            self.converter.convert_malicious_url,
            "Malicious URLs",
            start,
        )

    def _collect_phishing_sites(self, start: str) -> tuple[list[Any], str | None]:
        """Collect phishing site IOCs and convert to STIX."""
        return self._collect_feed(
            self.client.get_phishing_sites,
            self.converter.convert_phishing_site,
            "Phishing Sites",
            start,
        )

    def _collect_malware_hashes(self, start: str) -> tuple[list[Any], str | None]:
        """Collect malware hash IOCs and convert to STIX."""
        return self._collect_feed(
            self.client.get_malware_hashes,
            self.converter.convert_malware_hash,
            "Malware Hashes",
            start,
        )

    def _collect_compromised_credentials(
        self, start: str
    ) -> tuple[list[Any], str | None]:
        """Collect compromised credentials tickets and convert to STIX."""
        return self._collect_feed(
            self.client.get_compromised_credentials,
            self.converter.convert_compromised_credential,
            "Compromised Credentials",
            start,
        )

    def _collect_credit_card_tickets(self, start: str) -> tuple[list[Any], str | None]:
        """Collect credit card fraud tickets and convert to STIX."""
        return self._collect_feed(
            self.client.get_credit_card_tickets,
            self.converter.convert_credit_card_ticket,
            "Credit Card Tickets",
            start,
        )

    def _collect_deep_sight_tickets(  # pylint: disable=too-many-locals
        self, start: str
    ) -> tuple[list[Any], str | None]:
        """
        Collect Deep Sight intelligence tickets, download any attached report
        PDFs immediately, and convert to STIX.

        PDFs are embedded directly in the STIX Report via the x_opencti_files
        custom property so OpenCTI attaches them atomically during bundle
        ingestion — no async timing issues.
        """
        stix_objects: list[Any] = []
        seen_ids: set[str] = set()
        last_created: str | None = None
        record_count = 0
        failed_count = 0

        for page in self.client.get_deep_sight_tickets(start=start):
            for record in page:
                record_id = record.get("id")
                try:
                    # Download PDF before conversion so the converter can embed it
                    content = record.get("content") or {}
                    report_url = content.get("report")
                    if report_url:
                        parsed_url = urlparse(report_url)
                        if parsed_url.scheme != "https" or not parsed_url.hostname:
                            self.helper.connector_logger.warning(
                                "[CONNECTOR] Deep Sight report URL must use HTTPS"
                                " — skipping attachment download",
                                {"ticket_id": record_id, "report_url": report_url},
                            )
                        else:
                            filename = self._extract_filename_from_url(report_url)
                            try:
                                with requests.get(
                                    report_url,
                                    timeout=60,
                                    stream=True,
                                    allow_redirects=False,
                                ) as response:
                                    response.raise_for_status()
                                    buf = io.BytesIO()
                                    total = 0
                                    too_large = False
                                    for chunk in response.iter_content(
                                        chunk_size=65536
                                    ):
                                        total += len(chunk)
                                        if total > _MAX_PDF_BYTES:
                                            too_large = True
                                            break
                                        buf.write(chunk)
                                if too_large:
                                    self.helper.connector_logger.warning(
                                        "[CONNECTOR] Deep Sight report PDF exceeds size"
                                        " limit — skipping attachment",
                                        {
                                            "ticket_id": record_id,
                                            "limit_bytes": _MAX_PDF_BYTES,
                                        },
                                    )
                                else:
                                    record["_pdf_data"] = buf.getvalue()
                                    record["_pdf_filename"] = filename
                                    self.helper.connector_logger.debug(
                                        "[CONNECTOR] Downloaded Deep Sight report PDF",
                                        {
                                            "ticket_id": record_id,
                                            "filename": filename,
                                            "file_size_bytes": total,
                                        },
                                    )
                            except (
                                Exception  # pylint: disable=broad-exception-caught
                            ) as dl_err:
                                self.helper.connector_logger.warning(
                                    "[CONNECTOR] Failed to download Deep Sight report PDF"
                                    " — continuing without attachment",
                                    {
                                        "ticket_id": record_id,
                                        "error_type": type(dl_err).__name__,
                                        "error": str(dl_err),
                                    },
                                )

                    converted = self.converter.convert_deep_sight_ticket(record)
                    for obj in converted:
                        if obj.id not in seen_ids:
                            seen_ids.add(obj.id)
                            stix_objects.append(obj)
                    record_count += 1
                    created = record.get("created")
                    if created:
                        last_created = created

                except Exception as e:  # pylint: disable=broad-exception-caught
                    failed_count += 1
                    self.helper.connector_logger.warning(
                        "[CONNECTOR] Failed to convert Deep Sight ticket record — skipping",
                        {
                            "ticket_id": record_id,
                            "error_type": type(e).__name__,
                            "error": str(e),
                        },
                    )

        self.helper.connector_logger.info(
            "[CONNECTOR] Deep Sight Tickets collection finished",
            {
                "records_ok": record_count,
                "records_failed": failed_count,
                "stix_objects": len(stix_objects),
                "last_created_cursor": last_created,
            },
        )
        return stix_objects, last_created

    @staticmethod
    def _extract_filename_from_url(url: str) -> str:
        """Extract and URL-decode the filename from a pre-signed CDN path."""
        path = urlparse(url).path
        raw_name = path.rsplit("/", 1)[-1] if "/" in path else ""
        filename = unquote(raw_name)
        if not filename or not filename.lower().endswith(".pdf"):
            filename = (filename or "report") + ".pdf"
        return filename

    # ------------------------------------------------------------------
    # Main processing method
    # ------------------------------------------------------------------

    def process_message(self) -> None:  # pylint: disable=too-many-locals
        """
        Main processing method called by the scheduler on each run.

        Implements graceful degradation: if one feed fails, the others
        continue to be processed.  Each feed's work item is always closed
        (with in_error=True on failure) so OpenCTI never has orphaned works.
        """
        try:
            run_start_mono = time.monotonic()
            run_start = datetime.now(timezone.utc)
            current_start_iso = run_start.isoformat()
            current_state = self._get_state()

            last_run_start = current_state.get(self.STATE_KEY_LAST_RUN_START)
            last_run_with_data = current_state.get(self.STATE_KEY_LAST_RUN_WITH_DATA)

            self.helper.connector_logger.info(
                "[CONNECTOR] Starting USTA import run",
                {
                    "connector_name": self.config.connector.name,
                    "last_run_start": last_run_start or "Never run",
                    "last_run_with_data": last_run_with_data or "Never ingested data",
                    "import_malicious_urls": self.config.usta.import_malicious_urls,
                    "import_phishing_sites": self.config.usta.import_phishing_sites,
                    "import_malware_hashes": self.config.usta.import_malware_hashes,
                    "import_compromised_credentials": (
                        self.config.usta.import_compromised_credentials
                    ),
                    "import_credit_cards": self.config.usta.import_credit_cards,
                    "import_deep_sight_tickets": self.config.usta.import_deep_sight_tickets,
                },
            )

            total_objects_sent = 0
            new_state = dict(current_state)
            new_state[self.STATE_KEY_LAST_RUN_START] = current_start_iso

            feeds = [
                _FeedConfig(
                    label="Malicious URLs",
                    state_key=self.STATE_KEY_MALICIOUS_URLS_CURSOR,
                    enabled=self.config.usta.import_malicious_urls,
                    collect=self._collect_malicious_urls,
                ),
                _FeedConfig(
                    label="Phishing Sites",
                    state_key=self.STATE_KEY_PHISHING_SITES_CURSOR,
                    enabled=self.config.usta.import_phishing_sites,
                    collect=self._collect_phishing_sites,
                ),
                _FeedConfig(
                    label="Malware Hashes",
                    state_key=self.STATE_KEY_MALWARE_HASHES_CURSOR,
                    enabled=self.config.usta.import_malware_hashes,
                    collect=self._collect_malware_hashes,
                ),
                _FeedConfig(
                    label="Compromised Credentials",
                    state_key=self.STATE_KEY_COMPROMISED_CREDS_CURSOR,
                    enabled=self.config.usta.import_compromised_credentials,
                    collect=self._collect_compromised_credentials,
                ),
                _FeedConfig(
                    label="Credit Card Tickets",
                    state_key=self.STATE_KEY_CREDIT_CARDS_CURSOR,
                    enabled=self.config.usta.import_credit_cards,
                    collect=self._collect_credit_card_tickets,
                ),
                _FeedConfig(
                    label="Deep Sight Tickets",
                    state_key=self.STATE_KEY_DEEP_SIGHT_CURSOR,
                    enabled=self.config.usta.import_deep_sight_tickets,
                    collect=self._collect_deep_sight_tickets,
                ),
            ]

            for feed in feeds:
                if not feed.enabled:
                    self.helper.connector_logger.debug(
                        f"[CONNECTOR] {feed.label} feed is disabled — skipping",
                        {"feed": feed.label},
                    )
                    continue

                try:
                    start = self._get_start_for_feed(current_state, feed.state_key)
                    self.helper.connector_logger.info(
                        f"[CONNECTOR] Starting {feed.label} feed",
                        {"feed": feed.label, "start_cursor": start},
                    )
                    stix_objects, last_created = feed.collect(start)

                    if stix_objects:
                        work_id = self._initiate_work(
                            f"USTA - {feed.label} - {current_start_iso}"
                        )
                        try:
                            sent = self._send_stix_objects(
                                stix_objects, work_id, feed.label
                            )
                            self._complete_work(
                                f"Imported {sent} STIX objects from {feed.label.lower()}"
                            )
                            total_objects_sent += sent
                        except Exception as send_err:
                            self._complete_work(
                                f"{feed.label} send failed: {send_err}",
                                in_error=True,
                            )
                            raise
                    else:
                        self.helper.connector_logger.info(
                            f"[CONNECTOR] {feed.label} feed produced no new STIX"
                            " objects — nothing to send",
                            {"feed": feed.label, "start_cursor": start},
                        )

                    if last_created:
                        new_state[feed.state_key] = last_created
                        self.helper.connector_logger.info(
                            f"[CONNECTOR] {feed.label} cursor advanced",
                            {"feed": feed.label, "new_cursor": last_created},
                        )

                except UstaClientError as e:
                    self.helper.connector_logger.error(
                        f"[CONNECTOR] {feed.label} feed failed with a non-retryable API error",
                        {
                            "feed": feed.label,
                            "error_type": type(e).__name__,
                            "error": str(e),
                            "hint": "Check API key permissions and USTA endpoint availability",
                        },
                    )
                except Exception as e:  # pylint: disable=broad-exception-caught
                    self.helper.connector_logger.error(
                        f"[CONNECTOR] {feed.label} feed failed with an unexpected error",
                        {
                            "feed": feed.label,
                            "error_type": type(e).__name__,
                            "error": str(e),
                        },
                    )

            # ---- Update state ----
            if total_objects_sent > 0:
                new_state[self.STATE_KEY_LAST_RUN_WITH_DATA] = datetime.now(
                    timezone.utc
                ).isoformat()

            self.helper.set_state(new_state)

            elapsed = time.monotonic() - run_start_mono
            self.helper.connector_logger.info(
                "[CONNECTOR] Import run completed",
                {
                    "total_objects_sent": total_objects_sent,
                    "duration_seconds": round(elapsed, 2),
                },
            )

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[CONNECTOR] Connector stopped by signal")
            sys.exit(0)
        except Exception as err:  # pylint: disable=broad-exception-caught
            self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected error in process_message — run aborted",
                {
                    "error_type": type(err).__name__,
                    "error": str(err),
                },
            )

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Start the connector with scheduled execution.

        Uses schedule_process() for scheduled execution.
        Handles both periodic and run-and-terminate modes automatically.
        """
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

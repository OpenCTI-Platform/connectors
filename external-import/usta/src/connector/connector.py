"""
USTA Prodaft OpenCTI External Import Connector.

Orchestrates the full import lifecycle:
  1. Read / initialize connector state
  2. Fetch IOCs from all enabled USTA endpoints (paginated)
  3. Convert to STIX 2.1 objects via ConverterToStix
  4. Send bundles to OpenCTI in batches
  5. Update state on success

Implements all patterns specified in:
  - 01-common-implementation.md
  - 02-external-import-specifications.md
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from usta_client import UstaClient, UstaClientError


class UstaProdaftConnector:
    """
    External Import connector for USTA Prodaft Threat Intelligence.

    Imports five data families:
      - Malicious URLs  (C2 infrastructure, RAT callbacks, stealer panels)
      - Phishing Sites  (credential harvesting domains)
      - Malware Hashes  (file indicators for known malware families)
      - Compromised Credentials  (account takeover prevention tickets)
      - Credit Card Tickets      (fraud intelligence)
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

    def __init__(
        self,
        config: ConnectorSettings,
        helper: OpenCTIConnectorHelper,
    ) -> None:
        self.config = config
        self.helper = helper
        self.work_id: str | None = None

        # API client
        self.client = UstaClient(
            helper=self.helper,
            base_url=str(self.config.usta_prodaft.api_base_url),
            api_key=self.config.usta_prodaft.api_key,
            page_size=self.config.usta_prodaft.page_size,
        )

        # STIX converter
        self.converter = ConverterToStix(
            helper=self.helper,
            author_name="USTA",
            tlp_level=self.config.usta_prodaft.tlp_level,
            confidence_level=self.config.usta_prodaft.confidence_level,
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
        delta: timedelta = self.config.usta_prodaft.import_start_date
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

    def _complete_work(self, message: str) -> None:
        """Mark the current work item as completed."""
        if self.work_id:
            self.helper.api.work.to_processed(self.work_id, message)
            self.helper.connector_logger.info(
                "[CONNECTOR] Work completed",
                {"work_id": self.work_id, "message": message},
            )
            self.work_id = None

    # ------------------------------------------------------------------
    # Bundle sending with batching
    # ------------------------------------------------------------------

    def _send_stix_objects(
        self,
        stix_objects: list,
        work_id: str,
        feed_label: str,
    ) -> int:
        """
        Send STIX objects to OpenCTI in batches.

        Always includes the author and TLP marking in every batch
        to satisfy cleanup_inconsistent_bundle requirements.

        Returns:
            Total number of STIX objects sent.
        """
        if not stix_objects:
            return 0

        total_sent = 0
        batch_num = 0

        for i in range(0, len(stix_objects), self.BUNDLE_BATCH_SIZE):
            batch = stix_objects[i : i + self.BUNDLE_BATCH_SIZE]
            batch_num += 1

            # Include author + marking in every batch
            batch_with_meta = batch + [
                self.converter.author,
                self.converter.tlp_marking,
            ]

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
    # Per-feed collection methods
    # ------------------------------------------------------------------

    def _collect_malicious_urls(self, start: str) -> tuple[list, str | None]:
        """
        Collect malicious URL IOCs and convert to STIX.

        Returns:
            Tuple of (stix_objects, last_created_timestamp).
        """
        stix_objects: list = []
        last_created: str | None = None
        record_count = 0

        for page in self.client.get_malicious_urls(start=start):
            for record in page:
                try:
                    converted = self.converter.convert_malicious_url(record)
                    stix_objects.extend(converted)
                    record_count += 1
                    created = record.get("created")
                    if created:
                        last_created = created
                except Exception as e:
                    self.helper.connector_logger.warning(
                        "[CONNECTOR] Failed to convert malicious URL record",
                        {"record_id": record.get("id"), "error": str(e)},
                    )
                    continue

        self.helper.connector_logger.info(
            "[CONNECTOR] Malicious URLs collected",
            {"records": record_count, "stix_objects": len(stix_objects)},
        )
        return stix_objects, last_created

    def _collect_phishing_sites(self, start: str) -> tuple[list, str | None]:
        """
        Collect phishing site IOCs and convert to STIX.

        Returns:
            Tuple of (stix_objects, last_created_timestamp).
        """
        stix_objects: list = []
        last_created: str | None = None
        record_count = 0

        for page in self.client.get_phishing_sites(start=start):
            for record in page:
                try:
                    converted = self.converter.convert_phishing_site(record)
                    stix_objects.extend(converted)
                    record_count += 1
                    created = record.get("created")
                    if created:
                        last_created = created
                except Exception as e:
                    self.helper.connector_logger.warning(
                        "[CONNECTOR] Failed to convert phishing site record",
                        {"record_id": record.get("id"), "error": str(e)},
                    )
                    continue

        self.helper.connector_logger.info(
            "[CONNECTOR] Phishing sites collected",
            {"records": record_count, "stix_objects": len(stix_objects)},
        )
        return stix_objects, last_created

    def _collect_malware_hashes(self, start: str) -> tuple[list, str | None]:
        """
        Collect malware hash IOCs and convert to STIX.

        Returns:
            Tuple of (stix_objects, last_created_timestamp).
        """
        stix_objects: list = []
        last_created: str | None = None
        record_count = 0

        for page in self.client.get_malware_hashes(start=start):
            for record in page:
                try:
                    converted = self.converter.convert_malware_hash(record)
                    stix_objects.extend(converted)
                    record_count += 1
                    created = record.get("created")
                    if created:
                        last_created = created
                except Exception as e:
                    self.helper.connector_logger.warning(
                        "[CONNECTOR] Failed to convert malware hash record",
                        {"record_id": record.get("id"), "error": str(e)},
                    )
                    continue

        self.helper.connector_logger.info(
            "[CONNECTOR] Malware hashes collected",
            {"records": record_count, "stix_objects": len(stix_objects)},
        )
        return stix_objects, last_created

    def _collect_compromised_credentials(self, start: str) -> tuple[list, str | None]:
        """
        Collect compromised credentials tickets and convert to STIX.

        Returns:
            Tuple of (stix_objects, last_created_timestamp).
        """
        stix_objects: list = []
        last_created: str | None = None
        record_count = 0

        for page in self.client.get_compromised_credentials(start=start):
            for record in page:
                try:
                    converted = self.converter.convert_compromised_credential(record)
                    stix_objects.extend(converted)
                    record_count += 1
                    created = record.get("created")
                    if created:
                        last_created = created
                except Exception as e:
                    self.helper.connector_logger.warning(
                        "[CONNECTOR] Failed to convert compromised credential record",
                        {"record_id": record.get("id"), "error": str(e)},
                    )
                    continue

        self.helper.connector_logger.info(
            "[CONNECTOR] Compromised credentials collected",
            {"records": record_count, "stix_objects": len(stix_objects)},
        )
        return stix_objects, last_created

    def _collect_credit_card_tickets(self, start: str) -> tuple[list, str | None]:
        """
        Collect credit card fraud tickets and convert to STIX.

        Returns:
            Tuple of (stix_objects, last_created_timestamp).
        """
        stix_objects: list = []
        last_created: str | None = None
        record_count = 0

        for page in self.client.get_credit_card_tickets(start=start):
            for record in page:
                try:
                    converted = self.converter.convert_credit_card_ticket(record)
                    stix_objects.extend(converted)
                    record_count += 1
                    created = record.get("created")
                    if created:
                        last_created = created
                except Exception as e:
                    self.helper.connector_logger.warning(
                        "[CONNECTOR] Failed to convert credit card ticket",
                        {"record_id": record.get("id"), "error": str(e)},
                    )
                    continue

        self.helper.connector_logger.info(
            "[CONNECTOR] Credit card tickets collected",
            {"records": record_count, "stix_objects": len(stix_objects)},
        )
        return stix_objects, last_created

    # ------------------------------------------------------------------
    # Main processing method
    # ------------------------------------------------------------------

    def process_message(self) -> None:
        """
        Main processing method called by the scheduler on each run.

        Implements graceful degradation: if one feed fails, the others
        continue to be processed.
        """
        try:
            run_start = datetime.now(timezone.utc)
            current_start_iso = run_start.isoformat()
            current_state = self._get_state()

            last_run_start = current_state.get(self.STATE_KEY_LAST_RUN_START)
            last_run_with_data = current_state.get(self.STATE_KEY_LAST_RUN_WITH_DATA)

            self.helper.connector_logger.info(
                "[CONNECTOR] Starting USTA Prodaft import run",
                {
                    "connector_name": self.config.connector.name,
                    "last_run_start": last_run_start or "Never run",
                    "last_run_with_data": last_run_with_data or "Never ingested data",
                    "import_malicious_urls": self.config.usta_prodaft.import_malicious_urls,
                    "import_phishing_sites": self.config.usta_prodaft.import_phishing_sites,
                    "import_malware_hashes": self.config.usta_prodaft.import_malware_hashes,
                    "import_compromised_credentials": self.config.usta_prodaft.import_compromised_credentials,
                    "import_credit_cards": self.config.usta_prodaft.import_credit_cards,
                },
            )

            total_objects_sent = 0
            new_state = dict(current_state)  # Copy existing state
            new_state[self.STATE_KEY_LAST_RUN_START] = current_start_iso

            # ---- Malicious URLs ----
            if self.config.usta_prodaft.import_malicious_urls:
                try:
                    start = self._get_start_for_feed(
                        current_state, self.STATE_KEY_MALICIOUS_URLS_CURSOR
                    )
                    stix_objects, last_created = self._collect_malicious_urls(start)

                    if stix_objects:
                        work_id = self._initiate_work(
                            f"USTA Prodaft - Malicious URLs - {current_start_iso}"
                        )
                        sent = self._send_stix_objects(
                            stix_objects, work_id, "Malicious URLs"
                        )
                        self._complete_work(
                            f"Imported {sent} STIX objects from malicious URLs"
                        )
                        total_objects_sent += sent

                    if last_created:
                        new_state[self.STATE_KEY_MALICIOUS_URLS_CURSOR] = last_created

                except UstaClientError as e:
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Malicious URLs feed failed (non-retryable)",
                        {"error": str(e)},
                    )
                except Exception as e:
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Malicious URLs feed failed",
                        {"error": str(e)},
                    )

            # ---- Phishing Sites ----
            if self.config.usta_prodaft.import_phishing_sites:
                try:
                    start = self._get_start_for_feed(
                        current_state, self.STATE_KEY_PHISHING_SITES_CURSOR
                    )
                    stix_objects, last_created = self._collect_phishing_sites(start)

                    if stix_objects:
                        work_id = self._initiate_work(
                            f"USTA Prodaft - Phishing Sites - {current_start_iso}"
                        )
                        sent = self._send_stix_objects(
                            stix_objects, work_id, "Phishing Sites"
                        )
                        self._complete_work(
                            f"Imported {sent} STIX objects from phishing sites"
                        )
                        total_objects_sent += sent

                    if last_created:
                        new_state[self.STATE_KEY_PHISHING_SITES_CURSOR] = last_created

                except UstaClientError as e:
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Phishing Sites feed failed (non-retryable)",
                        {"error": str(e)},
                    )
                except Exception as e:
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Phishing Sites feed failed",
                        {"error": str(e)},
                    )

            # ---- Malware Hashes ----
            if self.config.usta_prodaft.import_malware_hashes:
                try:
                    start = self._get_start_for_feed(
                        current_state, self.STATE_KEY_MALWARE_HASHES_CURSOR
                    )
                    stix_objects, last_created = self._collect_malware_hashes(start)

                    if stix_objects:
                        work_id = self._initiate_work(
                            f"USTA Prodaft - Malware Hashes - {current_start_iso}"
                        )
                        sent = self._send_stix_objects(
                            stix_objects, work_id, "Malware Hashes"
                        )
                        self._complete_work(
                            f"Imported {sent} STIX objects from malware hashes"
                        )
                        total_objects_sent += sent

                    if last_created:
                        new_state[self.STATE_KEY_MALWARE_HASHES_CURSOR] = last_created

                except UstaClientError as e:
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Malware Hashes feed failed (non-retryable)",
                        {"error": str(e)},
                    )
                except Exception as e:
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Malware Hashes feed failed",
                        {"error": str(e)},
                    )

            # ---- Compromised Credentials ----
            if self.config.usta_prodaft.import_compromised_credentials:
                try:
                    start = self._get_start_for_feed(
                        current_state, self.STATE_KEY_COMPROMISED_CREDS_CURSOR
                    )
                    stix_objects, last_created = self._collect_compromised_credentials(
                        start
                    )

                    if stix_objects:
                        work_id = self._initiate_work(
                            f"USTA Prodaft - Compromised Credentials - {current_start_iso}"
                        )
                        sent = self._send_stix_objects(
                            stix_objects, work_id, "Compromised Credentials"
                        )
                        self._complete_work(
                            f"Imported {sent} STIX objects from compromised credentials"
                        )
                        total_objects_sent += sent

                    if last_created:
                        new_state[self.STATE_KEY_COMPROMISED_CREDS_CURSOR] = last_created

                except UstaClientError as e:
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Compromised Credentials feed failed (non-retryable)",
                        {"error": str(e)},
                    )
                except Exception as e:
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Compromised Credentials feed failed",
                        {"error": str(e)},
                    )

            # ---- Credit Card Tickets ----
            if self.config.usta_prodaft.import_credit_cards:
                try:
                    start = self._get_start_for_feed(
                        current_state, self.STATE_KEY_CREDIT_CARDS_CURSOR
                    )
                    stix_objects, last_created = self._collect_credit_card_tickets(
                        start
                    )

                    if stix_objects:
                        work_id = self._initiate_work(
                            f"USTA Prodaft - Credit Card Tickets - {current_start_iso}"
                        )
                        sent = self._send_stix_objects(
                            stix_objects, work_id, "Credit Card Tickets"
                        )
                        self._complete_work(
                            f"Imported {sent} STIX objects from credit card tickets"
                        )
                        total_objects_sent += sent

                    if last_created:
                        new_state[self.STATE_KEY_CREDIT_CARDS_CURSOR] = last_created

                except UstaClientError as e:
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Credit Card Tickets feed failed (non-retryable)",
                        {"error": str(e)},
                    )
                except Exception as e:
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Credit Card Tickets feed failed",
                        {"error": str(e)},
                    )

            # ---- Update state ----
            if total_objects_sent > 0:
                new_state[self.STATE_KEY_LAST_RUN_WITH_DATA] = (
                    datetime.now(timezone.utc).isoformat()
                )

            self.helper.set_state(new_state)

            elapsed = time.time() - run_start.timestamp()
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
        except Exception as err:
            self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected error in process_message",
                {"error": str(err)},
            )

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Start the connector with scheduled execution.

        Uses schedule_process() as required since OpenCTI 6.2.12.
        Handles both periodic and run-and-terminate modes automatically.
        """
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

import sys
import time
from datetime import datetime, timezone

from connector.converter_to_stix import ConverterToStix
from connector.utils import is_newer_than
from ctm360_cyna_client.api_client import CTM360CynaClient
from pycti import OpenCTIConnectorHelper


class CTM360CynaConnector:
    """OpenCTI EXTERNAL_IMPORT connector for CTM360 CYNA (Cyber News & Alerts).

    Fetches cyber news items from the CYNA API using cursor-based pagination,
    converts them to STIX objects (an Identity author, Reports, CVE
    Vulnerabilities, and the relationships between them), and imports them into
    OpenCTI.
    """

    def __init__(self, config, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = CTM360CynaClient(
            helper=self.helper,
            base_url=str(config.ctm360_cyna.api_base_url),
            api_key=config.ctm360_cyna.api_key.get_secret_value(),
        )
        self.converter = ConverterToStix(self.helper)
        self._interval = config.ctm360_cyna.import_interval
        self._page_size = config.ctm360_cyna.page_size
        self._max_pages = config.ctm360_cyna.max_pages

    def run(self):
        """Main entry point — startup validation and import loop."""
        # Startup ping to validate API connectivity
        try:
            self.client.ping()
            self.helper.connector_logger.info("[CONNECTOR] API connection verified")
        except Exception as exc:
            self.helper.connector_logger.error(
                "[CONNECTOR] API ping failed — stopping", meta={"error": str(exc)}
            )
            sys.exit(1)

        self.helper.connector_logger.info(
            "[CONNECTOR] Starting import loop",
            meta={
                "interval_seconds": self._interval,
                "page_size": self._page_size,
                "max_pages": self._max_pages,
            },
        )
        while True:
            try:
                self._import_data()
            except (KeyboardInterrupt, SystemExit):
                self.helper.connector_logger.info("[CONNECTOR] Stopping")
                break
            except Exception as e:
                self.helper.connector_logger.error(
                    "[CONNECTOR] Import cycle failed", meta={"error": str(e)}
                )
            time.sleep(self._interval)

    def _import_data(self):
        """Execute a single import cycle.

        Reads state, fetches all news pages, filters by last_run,
        converts to STIX, sends bundle, and saves state.
        """
        state = self.helper.get_state() or {}
        last_run = state.get("last_run", None)
        now = datetime.now(timezone.utc)

        friendly_name = f"CTM360-CYNA import @ {now.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        # Tracks whether the total-conversion-failure path already marked the work
        # item as errored, so the except block does not report it a second time.
        work_marked_in_error = False

        try:
            # Fetch all news items using cursor-based pagination
            self.helper.connector_logger.info(
                "[CONNECTOR] Fetching news items",
                meta={"last_run": last_run, "page_size": self._page_size},
            )
            all_items = self.client.get_all_news(
                page_size=self._page_size,
                max_pages=self._max_pages,
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Fetched items from API",
                meta={"total_items": len(all_items)},
            )

            # Client-side time filtering — skip items older than last_run
            if last_run:
                filtered_items = []
                for item in all_items:
                    # Tolerate non-dict entries (the converter already skips
                    # them per-item); keep them so the converter can log/skip
                    # rather than raising AttributeError and aborting the cycle.
                    metadata = (
                        item.get("metadata", {}) if isinstance(item, dict) else {}
                    )
                    pub_date = metadata.get("published_date")
                    if is_newer_than(pub_date, last_run):
                        filtered_items.append(item)
                self.helper.connector_logger.info(
                    "[CONNECTOR] Filtered by last_run",
                    meta={
                        "before_filter": len(all_items),
                        "after_filter": len(filtered_items),
                        "last_run": last_run,
                    },
                )
                all_items = filtered_items

            # Convert to STIX objects
            stix_objects = self.converter.news_to_stix(all_items)

            # Total failure guard — at least Identity + 1 real object expected
            if len(stix_objects) <= 1 and len(all_items) > 0:
                error_msg = f"All {len(all_items)} news items failed STIX conversion"
                work_marked_in_error = True
                self.helper.api.work.to_processed(work_id, error_msg, in_error=True)
                raise ValueError(error_msg)

            if stix_objects:
                bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(
                    bundle,
                    update=True,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )
                msg = f"Imported {len(stix_objects)} STIX objects from {len(all_items)} news items"
            else:
                msg = "No new data to import"

            self.helper.connector_logger.info(
                "[CONNECTOR] Import done", meta={"msg": msg}
            )
            self.helper.api.work.to_processed(work_id, msg)
            self.helper.set_state({"last_run": now.strftime("%Y-%m-%dT%H:%M:%SZ")})

        except Exception as e:
            if not work_marked_in_error:
                self.helper.connector_logger.error(
                    "[CONNECTOR] Import failed", meta={"error": str(e)}
                )
                self.helper.api.work.to_processed(work_id, str(e), in_error=True)
            raise

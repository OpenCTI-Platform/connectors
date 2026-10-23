"""WhoisFreaks OpenCTI external-import connector entry point."""

from __future__ import annotations

import sys
import traceback
from datetime import datetime, timezone
from typing import Any

from connector import ConnectorSettings, ConnectorState
from connector.data_processors import NRDProcessor, ThreatFeedProcessor
from connectors_sdk import ExternalImportConnector
from whoisfreaks_client.status import (
    WhoisFreaksStatus,
    WhoisFreaksStatusClient,
)


class WhoisFreaksExternalImportConnector(ExternalImportConnector):
    """OpenCTI connector with one shared status snapshot per run."""

    def __init__(
        self,
        settings: ConnectorSettings,
        state: ConnectorState,
        data_processors: list[Any],
    ) -> None:
        super().__init__(
            settings=settings,
            state=state,
            data_processors=data_processors,
        )

        config = settings.whoisfreaks

        self.status_client = WhoisFreaksStatusClient(
            api_key=config.api_key.get_secret_value(),
            base_url=str(config.status_api_base_url),
        )

        self.status: WhoisFreaksStatus | None = None

    def callback(self) -> None:
        """Run all enabled processors using one shared status snapshot."""

        connector_name = self.settings.connector.name

        self.logger.info(
            "[CONNECTOR] Starting connector",
            meta={"connector_name": connector_name},
        )

        try:
            self.state.load(force=True)

            if self.state.last_run:
                self.logger.info(
                    "[CONNECTOR] Connector last run",
                    meta={"last_run_datetime": str(self.state.last_run)},
                )
            else:
                self.logger.info("[CONNECTOR] Connector has never run")

            self.logger.info(
                "[CONNECTOR] Enabled feeds",
                meta={
                    "threat_feeds": list(self.settings.whoisfreaks.feed_types),
                    "nrd_feeds": list(self.settings.whoisfreaks.nrd_feed_types),
                },
            )

            self.logger.info("[CONNECTOR] Fetching WhoisFreaks feed status")

            self.status = self.status_client.get_status()

            for processor in self.data_processors:
                processor.set_status(self.status)

            self.logger.info(
                "[CONNECTOR] Running processors",
                meta={"connector_name": connector_name},
            )

            for processor in self.data_processors:
                processor.process()

            self.state.last_run = datetime.now(tz=timezone.utc)
            self.state.save()

            self.logger.info(
                "[CONNECTOR] Run completed",
                meta={
                    "connector_name": connector_name,
                    "last_run": str(self.state.last_run),
                },
            )

        except (KeyboardInterrupt, SystemExit):
            self.logger.info(
                "[CONNECTOR] Connector stopped",
                meta={"connector_name": connector_name},
            )
            sys.exit(0)

        except Exception as err:
            self.logger.exception(
                "[CONNECTOR] Unexpected error",
                meta={"error": str(err)},
            )
            raise


if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        state = ConnectorState()

        # Only instantiate processors for feeds the operator enabled.
        # Toggle via WHOISFREAKS_FEED_TYPES / WHOISFREAKS_NRD_FEED_TYPES
        # according to the subscription level.
        nrd_processors = [
            NRDProcessor(feed_name=feed_name)
            for feed_name in settings.whoisfreaks.nrd_feed_types
            if feed_name
            in {
                "nrd_gtld_with_whois",
                "nrd_cctld_with_whois",
                "nrd_gtld_without_whois",
                "nrd_cctld_without_whois",
            }
        ]
        threat_feed_processors = [
            ThreatFeedProcessor(feed_type=feed_type)
            for feed_type in settings.whoisfreaks.feed_types
            if feed_type in {"malware", "phishing", "spam"}
        ]

        if not threat_feed_processors and not nrd_processors:
            # Exit cleanly with a clear message instead of letting the SDK
            # raise ValueError("At least one BaseDataProcessor must be provided.")
            # which would produce a confusing traceback for the operator.
            print(
                "ERROR: No valid feeds configured. "
                "Set WHOISFREAKS_FEED_TYPES and/or WHOISFREAKS_NRD_FEED_TYPES "
                "to feeds covered by your WhoisFreaks subscription.",
                file=sys.stderr,
            )
            sys.exit(1)

        connector = WhoisFreaksExternalImportConnector(
            settings=settings,
            state=state,
            data_processors=[
                *nrd_processors,
                *threat_feed_processors,
            ],
        )

        connector.start()

    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        exit(1)

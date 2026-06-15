import sys
from datetime import datetime, timezone

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from ctm360_threatcover_client import (
    Ctm360ThreatcoverAPIError,
    Ctm360ThreatcoverClient,
)
from pycti import OpenCTIConnectorHelper


class Ctm360ThreatcoverConnector:
    """
    External-import connector that polls a CTM360 ThreatCover TAXII 2.1 collection
    and imports its STIX 2.1 objects into OpenCTI.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = Ctm360ThreatcoverClient(
            helper,
            api_root_url=self.config.ctm360_threatcover.api_root_url,
            api_token=self.config.ctm360_threatcover.api_token.get_secret_value(),
            collection_id=self.config.ctm360_threatcover.collection_id,
            verify_ssl=self.config.ctm360_threatcover.verify_ssl,
        )
        self.converter = ConverterToStix(
            helper, tlp_level=self.config.ctm360_threatcover.tlp_level
        )

    def _collect_intelligence(self, added_after) -> list:
        raw_objects = self.client.get_objects(added_after=added_after)
        if not raw_objects:
            return []
        stix_objects = self.converter.process_objects(raw_objects)
        if stix_objects:
            stix_objects.append(self.converter.author)
            stix_objects.append(self.converter.tlp_marking)
        return stix_objects

    @staticmethod
    def _now_rfc3339() -> str:
        now = datetime.now(timezone.utc)
        return now.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def process_message(self) -> None:
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting CTM360 ThreatCover connector..."
        )
        try:
            current_state = self.helper.get_state() or {}
            added_after = current_state.get("added_after")
            run_started = self._now_rfc3339()

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, "CTM360 ThreatCover run"
            )

            stix_objects = self._collect_intelligence(added_after)
            if stix_objects:
                bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(
                    bundle, work_id=work_id, cleanup_inconsistent_bundle=True
                )

            current_state["added_after"] = run_started
            current_state["last_run"] = run_started
            self.helper.set_state(current_state)
            self.helper.api.work.to_processed(
                work_id, "CTM360 ThreatCover connector successfully run"
            )
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[CONNECTOR] Connector stopped...")
            sys.exit(0)
        except Ctm360ThreatcoverAPIError as err:
            self.helper.connector_logger.error(str(err))
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

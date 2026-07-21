import sys
from datetime import datetime, timedelta, timezone

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from corelight_investigator_client import (
    CorelightInvestigatorAPIError,
    CorelightInvestigatorClient,
)
from pycti import OpenCTIConnectorHelper


class CorelightInvestigatorConnector:
    """
    External-import connector that pulls Corelight Investigator alerts/detections into
    OpenCTI as STIX Incidents.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = CorelightInvestigatorClient(
            helper,
            api_base_url=self.config.corelight_investigator.api_base_url,
            api_key=self.config.corelight_investigator.api_key.get_secret_value(),
            alerts_path=self.config.corelight_investigator.alerts_path,
            max_alerts=self.config.corelight_investigator.max_alerts,
            ssl_verify=self.config.corelight_investigator.ssl_verify,
        )
        self.converter = ConverterToStix(
            helper, tlp_level=self.config.corelight_investigator.tlp_level
        )

    def _since(self) -> str:
        state = self.helper.get_state() or {}
        last_run = state.get("last_run")
        if last_run:
            return last_run
        window = self.config.corelight_investigator.import_window_days
        since = datetime.now(timezone.utc) - timedelta(days=window)
        return since.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def _collect_intelligence(self, since: str) -> list:
        alerts = self.client.get_alerts(since=since)
        stix_objects: list = []
        for alert in alerts:
            incident = self.converter.create_incident(alert)
            if incident is None:
                continue
            stix_objects.append(incident)
            stix_objects.extend(
                self.converter.create_observables(alert, incident["id"])
            )
        if stix_objects:
            stix_objects.append(self.converter.author)
            stix_objects.append(self.converter.tlp_marking)
        return stix_objects

    def process_message(self) -> None:
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting Corelight Investigator connector..."
        )
        work_id = None
        try:
            now = datetime.now(timezone.utc)
            since = self._since()

            # Only initiate a work when there is data to ingest, so empty runs
            # do not clutter the OpenCTI jobs UI with zero-bundle works.
            stix_objects = self._collect_intelligence(since)
            if stix_objects:
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, "Corelight Investigator run"
                )
                bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(
                    bundle, work_id=work_id, cleanup_inconsistent_bundle=True
                )

            current_state = self.helper.get_state() or {}
            current_state["last_run"] = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            self.helper.set_state(current_state)
            if work_id:
                self.helper.api.work.to_processed(
                    work_id, "Corelight Investigator connector successfully run"
                )
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[CONNECTOR] Connector stopped...")
            sys.exit(0)
        except CorelightInvestigatorAPIError as err:
            self.helper.connector_logger.error(str(err))
            if work_id:
                self.helper.api.work.to_processed(work_id, str(err), in_error=True)
        except Exception as err:
            self.helper.connector_logger.error(str(err))
            if work_id:
                self.helper.api.work.to_processed(work_id, str(err), in_error=True)

    def run(self) -> None:
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

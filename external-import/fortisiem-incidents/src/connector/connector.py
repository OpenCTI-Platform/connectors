import sys
from datetime import datetime, timedelta, timezone

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from fortisiem_client import FortiSIEMClient
from pycti import OpenCTIConnectorHelper

# FortiSIEM incident fields that may carry network observables.
_OBSERVABLE_FIELDS = ["srcIpAddr", "destIpAddr", "hostIpAddr", "hostName"]


class FortiSIEMIncidentsConnector:
    """
    External-import connector that pulls FortiSIEM incidents into OpenCTI as
    STIX Incidents, with related network observables.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = FortiSIEMClient(config, helper)
        self.converter = ConverterToStix(
            helper, tlp_level=self.config.fortisiem_incidents.tlp_level
        )

    def _since(self, current_state: dict) -> str:
        if current_state and "last_run" in current_state:
            return current_state["last_run"]
        window = timedelta(days=self.config.fortisiem_incidents.import_window_days)
        return (datetime.now(timezone.utc) - window).isoformat()

    def _collect_intelligence(self, since: str) -> list:
        stix_objects: list = []
        incidents = self.client.get_incidents(since)
        for incident in incidents:
            stix_incident = self.converter.create_incident(incident)
            if stix_incident is None:
                continue
            stix_objects.append(stix_incident)
            for field in _OBSERVABLE_FIELDS:
                observable = self.converter.create_observable(incident.get(field, ""))
                if observable is None:
                    continue
                stix_objects.append(observable)
                stix_objects.append(
                    self.converter.create_relationship(
                        stix_incident["id"], "related-to", observable["id"]
                    )
                )

        if stix_objects:
            stix_objects.append(self.converter.author)
            stix_objects.append(self.converter.tlp_marking)
        return stix_objects

    def process_message(self) -> None:
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting FortiSIEM Incidents connector..."
        )
        work_id = None
        try:
            now = datetime.now(timezone.utc)
            current_state = self.helper.get_state() or {}
            since = self._since(current_state)

            # If the fetch fails, _collect_intelligence raises (FortiSIEMClientError),
            # so the state below is NOT advanced and the same window is retried on the
            # next run instead of being silently skipped. The work is only initiated
            # once there is data to import, so runs without new incidents do not
            # create empty works in the OpenCTI UI.
            stix_objects = self._collect_intelligence(since)
            if stix_objects:
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, "FortiSIEM Incidents run"
                )
                bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(
                    bundle, work_id=work_id, cleanup_inconsistent_bundle=True
                )

            current_state["last_run"] = now.isoformat()
            self.helper.set_state(current_state)
            if work_id:
                self.helper.api.work.to_processed(
                    work_id, "FortiSIEM Incidents connector successfully run"
                )
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[CONNECTOR] Connector stopped...")
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))
            if work_id:
                self.helper.api.work.to_processed(work_id, str(err), in_error=True)

    def run(self) -> None:
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

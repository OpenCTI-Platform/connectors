import sys
from datetime import datetime, timezone

from arcsight_client import ArcSightClient
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class ArcSightIncidentsConnector:
    """
    External-import connector that pulls ArcSight ESM cases into OpenCTI as STIX
    Incidents.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = ArcSightClient(config, helper)
        self.converter = ConverterToStix(
            helper, tlp_level=self.config.arcsight_incidents.tlp_level
        )

    def _collect_intelligence(self) -> list:
        stix_objects: list = []
        for case in self.client.get_cases():
            # ArcSight security events referenced by the case are detections
            # -> Incidents.
            incident_ids = []
            for event in self.client.get_case_events(case):
                incident = self.converter.create_incident(event)
                if incident is not None:
                    stix_objects.append(incident)
                    incident_ids.append(incident["id"])

            # The ArcSight case itself is a case-management artifact
            # -> Case-Incident, referencing the event Incidents it groups.
            case_incident = self.converter.create_case_incident(
                case, object_refs=incident_ids
            )
            if case_incident is not None:
                stix_objects.append(case_incident)

        if stix_objects:
            stix_objects.append(self.converter.author)
            stix_objects.append(self.converter.tlp_marking)
        return stix_objects

    def process_message(self) -> None:
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting ArcSight Incidents connector..."
        )
        work_id = None
        try:
            now = datetime.now(timezone.utc)
            current_state = self.helper.get_state() or {}

            stix_objects = self._collect_intelligence()
            # Only initiate a work when there is data to import, so an empty
            # run does not clutter the OpenCTI jobs UI with empty works.
            if stix_objects:
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, "ArcSight Incidents run"
                )
                bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(
                    bundle, work_id=work_id, cleanup_inconsistent_bundle=True
                )

            current_state["last_run"] = now.isoformat()
            self.helper.set_state(current_state)
            if work_id:
                self.helper.api.work.to_processed(
                    work_id, "ArcSight Incidents connector successfully run"
                )
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[CONNECTOR] Connector stopped...")
            sys.exit(0)
        except Exception as err:
            # Do not log or forward str(err): the ESM auth flow passes the
            # password/token as query parameters and a requests exception string
            # usually embeds the full request URL, so it could leak credentials.
            self.helper.connector_logger.error(
                "[CONNECTOR] Run failed", meta={"error_type": type(err).__name__}
            )
            if work_id:
                self.helper.api.work.to_processed(
                    work_id,
                    f"ArcSight Incidents connector run failed: {type(err).__name__}",
                    in_error=True,
                )

    def run(self) -> None:
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

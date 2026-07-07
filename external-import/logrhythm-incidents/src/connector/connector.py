import sys
from datetime import datetime, timezone

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from logrhythm_client import LogRhythmClient
from pycti import OpenCTIConnectorHelper


class LogRhythmIncidentsConnector:
    """
    External-import connector that pulls LogRhythm cases into OpenCTI as STIX
    Case-Incidents, with the alarms attached to each case imported as Incidents.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = LogRhythmClient(config, helper)
        self.converter = ConverterToStix(
            helper, tlp_level=self.config.logrhythm_incidents.tlp_level
        )

    def _collect_intelligence(self) -> list:
        stix_objects: list = []
        for case in self.client.get_cases():
            case_id = case.get("id") or case.get("number")

            # LogRhythm alarms attached to the case are detections -> Incidents.
            # Skip the alarms lookup entirely when the case carries no usable
            # identifier (the request would be a guaranteed 404).
            incident_ids = []
            alarms = self.client.get_case_alarms(case_id) if case_id else []
            for alarm in alarms:
                incident = self.converter.create_incident(alarm)
                if incident is not None:
                    stix_objects.append(incident)
                    incident_ids.append(incident["id"])

            # The LogRhythm case itself is a case-management artifact -> Case-Incident,
            # referencing the alarm Incidents it groups.
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
            "[CONNECTOR] Starting LogRhythm Incidents connector..."
        )
        work_id = None
        error_message = None
        try:
            now = datetime.now(timezone.utc)
            current_state = self.helper.get_state() or {}

            stix_objects = self._collect_intelligence()
            # Only create a work when there is data to ingest, so empty runs
            # do not clutter the OpenCTI jobs view with empty work items.
            if stix_objects:
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, "LogRhythm Incidents run"
                )
                bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(
                    bundle, work_id=work_id, cleanup_inconsistent_bundle=True
                )

            current_state["last_run"] = now.isoformat()
            self.helper.set_state(current_state)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[CONNECTOR] Connector stopped...")
            sys.exit(0)
        except Exception as err:
            error_message = str(err)
            self.helper.connector_logger.error(error_message)
        finally:
            # Always close the work so a failed run does not leave an
            # "in progress" work item hanging in OpenCTI, and flag it in
            # error so failed runs stay visible in the platform.
            if work_id is not None:
                self.helper.api.work.to_processed(
                    work_id,
                    error_message or "LogRhythm Incidents connector run completed",
                    in_error=error_message is not None,
                )

    def run(self) -> None:
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

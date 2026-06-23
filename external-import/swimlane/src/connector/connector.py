import sys
from datetime import datetime, timezone

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from swimlane_client import SwimlaneClient


class SwimlaneConnector:
    """
    External-import connector that pulls Swimlane records into OpenCTI as STIX
    Case-Incidents.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = SwimlaneClient(config, helper)
        self.converter = ConverterToStix(
            helper, tlp_level=self.config.swimlane.tlp_level
        )

    def _collect_intelligence(self) -> list:
        stix_objects: list = []
        for record in self.client.get_records():
            case_incident = self.converter.create_case_incident(record)
            if case_incident is not None:
                stix_objects.append(case_incident)

        if stix_objects:
            stix_objects.append(self.converter.author)
            stix_objects.append(self.converter.tlp_marking)
        return stix_objects

    def process_message(self) -> None:
        self.helper.connector_logger.info("[CONNECTOR] Starting Swimlane connector...")
        work_id = None
        error_message = None
        try:
            now = datetime.now(timezone.utc)
            current_state = self.helper.get_state() or {}

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, "Swimlane run"
            )

            stix_objects = self._collect_intelligence()
            if stix_objects:
                bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(
                    bundle, work_id=work_id, cleanup_inconsistent_bundle=True
                )

            current_state["last_run"] = now.isoformat()
            self.helper.set_state(current_state)
        except (KeyboardInterrupt, SystemExit):
            # An interrupted run did not complete, so record it: otherwise the
            # finally block would finalize the work as a successful run and hide
            # the partial/aborted processing.
            error_message = "Swimlane connector run interrupted"
            self.helper.connector_logger.info("[CONNECTOR] Connector stopped...")
            sys.exit(0)
        except Exception as err:
            error_message = str(err)
            self.helper.connector_logger.error(error_message)
        finally:
            # Always close the work so a failed run does not leave an "in progress"
            # work item hanging in OpenCTI, and report the failure (in_error) with
            # its message when one occurred.
            if work_id is not None:
                self.helper.api.work.to_processed(
                    work_id,
                    error_message or "Swimlane connector successfully run",
                    in_error=error_message is not None,
                )

    def run(self) -> None:
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

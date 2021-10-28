import threading
import ciso8601
from datetime import datetime
from pycti import OpenCTIConnectorHelper
from managers import RelationshipManager, EnvironmentManager
from scalpl import Cut


class MyIncident:
    def __init__(self, buffer_start: float, start_time: float, end_time: float, buffer_end: float):
        self.id: int = 0
        self.stix_id: str = ""
        self.name = ""
        self.buffer_start = buffer_start
        self.start = start_time
        self.buffer_end = buffer_end
        self.end = end_time
        self.threat_hosts = {}
        self.dirty = True


class IncidentManager:
    def __init__(self, helper: OpenCTIConnectorHelper, config: Cut, relationship_manager: RelationshipManager, environment_manager: EnvironmentManager):
        self.helper = helper
        self._lock = threading.Lock()
        self.config = config
        self.relationship_manager = relationship_manager
        self.env_manager = environment_manager
        self.author = self.env_manager.author
        self.incidents = []

        self.buffer_time = int(config.get("manager.incident.buffer_time", 60)) * 60 * 1000
        self.confidence = int(config.get("connector.confidence_level", 90))
        # We should read in all the incidents from opencti
        self.read_incidents_from_opencti()
        # we need to make sure we upload all incidents to opencti before we shut down

    def find_or_create_incident(self, start: float, end: float) -> MyIncident:
        self.helper.log_debug(f"looking for incident between {start} {datetime.utcfromtimestamp(start / 1000)} and {end} {datetime.utcfromtimestamp(end / 1000)}")
        with self._lock:
            my_incident = None
            for incident in self.incidents:
                self.helper.log_debug(f"checking incident {incident.stix_id} between {incident.buffer_start} {datetime.utcfromtimestamp(incident.buffer_start / 1000)} and {incident.buffer_end} {datetime.utcfromtimestamp(incident.buffer_end / 1000)}")
                if incident.buffer_end > start and incident.buffer_start < end:
                    # Inside window
                    my_incident = incident

                    if start < incident.start:
                        my_incident.buffer_start = start - self.buffer_time
                        my_incident.start = start
                        my_incident.dirty = True
                    if incident.end < end:
                        my_incident.buffer_end = end + self.buffer_time
                        my_incident.end = end
                        my_incident.dirty = True

                if my_incident is not None:
                    self.helper.log_debug(f"Found incident {my_incident.stix_id}")
                    return my_incident

            self.helper.log_debug(f"Incident not found.  Creating new.")
            my_incident = MyIncident(start - self.buffer_time, start, end, end + self.buffer_time)
            self.incidents.append(my_incident)

        return my_incident

    def write_incidents_to_opencti(self):
        for incident in self.incidents:
            if incident.dirty:
                incident = self.write_incident_to_opencti(incident)

            if incident.stix_id == "":
                self.write_incident_to_opencti(incident)

    def write_incident_to_opencti(self, incident: MyIncident) -> MyIncident:
        with self._lock:
            start_date: datetime = datetime.utcfromtimestamp(incident.start / 1000)
            end_date: datetime = datetime.utcfromtimestamp(incident.end / 1000)
            start_string = start_date.strftime("%Y-%m-%d %H:%M:%S")
            first_seen = start_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            last_seen = end_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            end_string = end_date.strftime("%Y-%m-%d %H:%M:%S")
            incident.name = f"Incident from {start_string} to {end_string}"
            if incident.stix_id != "":
                stix_incident = self.helper.api.incident.create(
                    stix_id=incident.stix_id,
                    name=incident.name,
                    description=incident.name,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    confidence=self.confidence,
                    createdBy=self.author,
                    update=True
                )
                incident.dirty = False
            else:
                stix_incident = self.helper.api.incident.create(
                    name=incident.name,
                    description=incident.name,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    confidence=self.confidence,
                    createdBy=self.author
                )
                incident.id = stix_incident["id"]
                incident.stix_id = stix_incident["standard_id"]
                incident.dirty = False

                self.env_manager.add_item_to_report(stix_incident["standard_id"])

            for threat_actor in self.env_manager.threat_actors:
                relationship = self.relationship_manager.find_or_create_relationship(
                    relationship_type="attributed-to",
                    fromId=incident.stix_id,
                    toId=threat_actor,
                    start_time=first_seen,
                    stop_time=last_seen,
                    confidence=self.confidence,
                    createdBy=self.author
                )

                self.env_manager.add_item_to_report(relationship["standard_id"])

            for intrusion_set in self.env_manager.intrusion_sets:
                relationship = self.relationship_manager.find_or_create_relationship(
                    relationship_type="attributed-to",
                    fromId=incident.stix_id,
                    toId=intrusion_set,
                    start_time=first_seen,
                    stop_time=last_seen,
                    confidence=self.confidence,
                    createdBy=self.author
                )

                self.env_manager.add_item_to_report(relationship["standard_id"])
        return incident

    def read_incidents_from_opencti(self):
        self.helper.log_debug("Reading incidents from opencti")
        with self._lock:
            opencti_incident_list = self.helper.api.incident.list()

            for opencti_incident in opencti_incident_list:
                start = ciso8601.parse_datetime(opencti_incident["first_seen"]).timestamp() * 1000
                end = ciso8601.parse_datetime(opencti_incident["last_seen"]).timestamp() * 1000
                local_incident = MyIncident(start - self.buffer_time, start, end, end + self.buffer_time)
                local_incident.id = opencti_incident["id"]
                local_incident.stix_id = opencti_incident["standard_id"]
                local_incident.dirty = False
                self.incidents.append(local_incident)

        self.helper.log_info(f"incidents has {len(self.incidents)} entries")

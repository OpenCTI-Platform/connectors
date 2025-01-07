import os
import time

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from s1client import S1Client
from stixclient import StixClient


class IncidentConnector:
    def __init__(self, config_data):

        self.helper = OpenCTIConnectorHelper(config_data)
        self.stix_client = StixClient(config_data, self.helper)
        self.s1_client = S1Client(config_data, self.helper)
        self.sign = get_config_variable(
            "SENTINELONE_SEARCH_SIGN", ["sentinelOne", "search_sign"], config_data
        )

        self.fetch_interval = int(
            get_config_variable(
                "CONNECTOR_FETCH_INTERVAL", ["connector", "fetch_interval"], config_data
            )
        )

        self.cache = []

        # with open("cache.txt", 'r') as file:
        #    self.cache = [line.strip() for line in file]

        self.to_process = []

        self.helper.log_info("Initialised Connector Successfully")

    def run(self):
        while True:
            self.helper.log_info("Beginning The Retrieval Process")
            self.query_new_incidents()
            self.process_incidents()
            time.sleep(self.fetch_interval)

    def query_new_incidents(self):
        def is_applicable(incident_id):
            incident_notes = self.s1_client.retreive_incident_notes(incident_id)
            if incident_notes:
                for note in incident_notes:
                    if self.sign in note.get("text", ""):
                        return True
            else:
                return None
            return False

        self.helper.log_info("Retrieving and filtering Incidents...")
        present_incidents = self.s1_client.fetch_incidents()

        if present_incidents is None:
            self.helper.log_info("Unable to retrieve Incidents from SentinelOne")
        elif present_incidents is False:
            self.helper.log_info("No Incidents were found from SentinelOne")
        else:

            uncached_incidents = [
                inc
                for inc in present_incidents
                if inc not in self.cache and inc not in self.to_process
            ]
            for incident in uncached_incidents:
                applicability = is_applicable(incident)
                if applicability:
                    self.to_process.append(incident)
                    self.helper.log_info(
                        f"Found applicable incident with ID: {incident}"
                    )
                elif applicability is None:
                    self.helper.log_debug(
                        "Unable to determine applicability due to a SentinelOne API error"
                    )
                else:
                    # self.cache.append(incident)
                    self.helper.log_debug(
                        f"Sign not found in notes, incident not applicable with ID: {incident}"
                    )

        self.helper.log_info("Retrieval process complete")

    def process_incidents(self):
        self.helper.log_info(
            f"Beginning creation for {len(self.to_process)} applicable Incidents"
        )

        for i, s1_incident_id in enumerate(self.to_process):
            self.helper.log_info(f"Creating Incident for S1 ID: {s1_incident_id}")

            # required steps
            s1_incident = self.s1_client.retreive_incident(s1_incident_id)
            if not s1_incident:
                self.helper.log_info(
                    "Unable to retrieve the Incident from SentinelOne, halting process."
                )
                return False
            self.helper.log_info("Retrieved Incident from SentinelOne.")

            incident_items = []
            incident_and_source = self.stix_client.create_incident(
                s1_incident, s1_incident_id, self.s1_client.url
            )
            if not incident_and_source:
                self.helper.log_info(
                    "Unable to create corresponding Incident in Stix form, halting process."
                )
                return False
            self.helper.log_info("Created Corresponding Stix Incident.")
            incident_items = incident_items + incident_and_source

            # optional steps
            incident = incident_and_source[0]

            endpoint_and_relationship = self.stix_client.create_endpoint_observable(
                s1_incident, incident["id"]
            )
            if not endpoint_and_relationship:
                self.helper.log_info("No Endpoint Observable created, continuing.")
            else:
                self.helper.log_info(
                    "Created Corresponding Endpoint Observable for the affected Endpoint."
                )
                incident_items = incident_items + endpoint_and_relationship

            attack_patterns = self.stix_client.create_attack_patterns(
                s1_incident, incident["id"]
            )
            if not attack_patterns:
                self.helper.log_info("No Attack Patterns created, continuing.")
            else:
                self.helper.log_info("Created Corresponding Stix Attack Patterns.")
                incident_items = incident_items + attack_patterns

            s1_notes = self.s1_client.retreive_incident_notes(s1_incident_id)
            if s1_notes:
                notes = self.stix_client.create_notes(s1_notes, incident["id"])
                if not notes:
                    self.helper.log_info("No Notes created, continuing.")
                self.helper.log_info("Created Corresponding Stix Notes.")
                incident_items = incident_items + notes
            else:
                self.helper.log_info(
                    "Unable to retrieve Notes from SentinelOne, no Notes created, continuing."
                )

            indicators = self.stix_client.create_hash_indicators(
                s1_incident, incident["id"]
            )
            if not indicators:
                self.helper.log_info("No Indicators created, continuing.")
            else:
                self.helper.log_info("Created Corresponding Stix Indicators.")
                incident_items = incident_items + indicators

            bundle = self.helper.stix2_create_bundle(incident_items)
            self.helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)

            self.helper.log_info(
                f"Incident Creation Completed for S1 ID: {s1_incident_id}."
            )
            self.cache.append(s1_incident_id)

        self.to_process = [inc for inc in self.to_process if inc not in self.cache]
        self.helper.log_info(
            f"Completed Incident Creation Process, now waiting {self.fetch_interval} seconds."
        )


if __name__ == "__main__":
    config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
    config = (
        yaml.load(open(config_file_path), Loader=yaml.FullLoader)
        if os.path.isfile(config_file_path)
        else {}
    )
    connector = IncidentConnector(config)
    connector.run()

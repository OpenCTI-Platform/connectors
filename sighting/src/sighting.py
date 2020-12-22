import yaml
import os

from pycti import OpenCTIConnectorHelper, get_config_variable


class SightingConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.organization = get_config_variable(
            "ORGANIZATION", ["sighting", "organization"], config
        )
        self.labels = get_config_variable(
            "SIGHTING_LABELS", ["sighting", "labels"], config
        ).split(",")

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name=self.organization,
            description=self.organization + " created by the Sighting connector",
        )

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        indicator = self.helper.api.indicator.read(
            customAttributes="""
                id
                observables {
                    edges {
                        node {
                            id
                        }
                    }
                }
            """,
            filters=[
                {
                    "key": "pattern",
                    "values": [observable["observable_value"]],
                    "operator": "wildcard",
                }
            ],
        )

        # If no indicator, return
        if indicator is None:
            return

        # Check if indicator and observable are already linked, if not, create the "based-on" relationship
        current_observable_is_present = False
        for indicator_observable in indicator["observables"]:
            if indicator_observable["id"] == observable["id"]:
                current_observable_is_present = True
        if not current_observable_is_present:
            # Create a relationship "based-on"
            self.helper.api.stix_core_relationship.create(
                fromId=indicator["id"],
                toId=observable["id"],
                relationship_type="based-on",
            )

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    sightingInstance = SightingConnector()
    sightingInstance.start()

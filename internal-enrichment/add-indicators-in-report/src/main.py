import os
import traceback
from typing import Dict

import yaml
from pycti import OpenCTIConnectorHelper


class ConnecteurEnrichReportWithStixIndicatorsFromObservables:
    def __init__(self):
        config_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, playbook_compatible=True)

    def _process_message(self, data: Dict):
        stix_objects = data["stix_objects"]
        for stix_object in stix_objects:
            if stix_object["type"] == "report":
                for object_contained_in_report in stix_object["object_refs"]:
                    is_observable = self.helper.api.stix_cyber_observable.read(id=object_contained_in_report)
                    if not is_observable:
                        continue

                    based_on_relationships = self.helper.api.stix_core_relationship.list(
                        toId=object_contained_in_report,
                        relationship_type="based-on"
                    )
                    
                    # If no relationship of type "based-on" exists
                    if based_on_relationships == [] or based_on_relationships is None:
                        # Create the stix indicator and the relation
                        indicator = self.helper.api.stix_cyber_observable.promote_to_indicator_v2(
                            id=object_contained_in_report
                        )
                        # Add the indicator to the report
                        self.helper.api.report.add_stix_object_or_stix_relationship(
                            id=stix_object["id"],
                            stixObjectOrStixRelationshipId=indicator["id"]
                        )
                        # Get relationship and add it to the report
                        based_on_relationships = self.helper.api.stix_core_relationship.list(
                            fromId=indicator["id"],
                            toId=indicator["observables"][0]["id"],
                            relationship_type="based-on"
                        )
                        self.helper.api.report.add_stix_object_or_stix_relationship(
                            id=stix_object["id"],
                            stixObjectOrStixRelationshipId=based_on_relationships[0]["id"]
                        )
                    else:
                        for based_on_relationship in based_on_relationships:
                            self.helper.api.report.add_stix_object_or_stix_relationship(
                                id=stix_object["id"],
                                stixObjectOrStixRelationshipId=based_on_relationship["from"]["id"]
                            )
                            self.helper.api.report.add_stix_object_or_stix_relationship(
                                id=stix_object["id"],
                                stixObjectOrStixRelationshipId=based_on_relationship["id"]
                            )

    def run(self) -> None:
        self.helper.listen(message_callback=self._process_message)

if __name__ == "__main__":
    try:
        connector = ConnecteurEnrichReportWithStixIndicatorsFromObservables()
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
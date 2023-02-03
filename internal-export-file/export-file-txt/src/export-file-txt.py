import json
import os
import sys
import time

import yaml
from pycti import OpenCTIConnectorHelper
from pycti.utils.constants import StixCyberObservableTypes


class ExportFileTxt:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

    def _process_message(self, data):
        file_name = data["file_name"]
        # max_marking = data["max_marking"]  # TODO Implement marking restriction
        entity_type = data["entity_type"]
        export_scope = data["export_scope"]

        if export_scope == "single":
            raise ValueError("This connector only supports list exports")

        if (
            entity_type == "stix-sighting-relationship"
            or entity_type == "stix-core-relationship"
            or entity_type == "Observed-Data"
            or entity_type == "Artifact"
        ):
            raise ValueError("Text/plain export is not available for this entity type.")
            # to do: print defaultValue (instead of name) for sightings

        else:  # export_scope = 'selection' or 'query'
            if export_scope == "selection":
                selected_ids = data["selected_ids"]
                entities_list = []
                list_filters = "selected_ids"

                for entity_id in selected_ids:
                    entity_data = self.helper.api_impersonate.stix_domain_object.read(
                        id=entity_id
                    )
                    if entity_data is None:
                        entity_data = (
                            self.helper.api_impersonate.stix_cyber_observable.read(
                                id=entity_id
                            )
                        )
                    if entity_data is None:
                        entity_data = (
                            self.helper.api_impersonate.stix_core_relationship.read(
                                id=entity_id
                            )
                        )
                    entities_list.append(entity_data)

            else:  # export_scope = 'query'
                list_params = data["list_params"]
                final_entity_type = entity_type
                if final_entity_type != "":
                    if StixCyberObservableTypes.has_value(entity_type):
                        if list_params["filters"] is not None:
                            list_params["filters"].append(
                                {"key": "entity_type", "values": [entity_type]}
                            )
                        else:
                            list_params["filters"] = [
                                {"key": "entity_type", "values": [entity_type]}
                            ]
                        final_entity_type = "Stix-Cyber-Observable"
                    if final_entity_type == "Analysis":
                        if list_params["filters"] is not None:
                            list_params["filters"].append(
                                {
                                    "key": "entity_type",
                                    "values": [
                                        "Report",
                                        "Grouping",
                                        "Note",
                                        "Observed-Data",
                                        "Opinion",
                                    ],
                                }
                            )
                        else:
                            list_params["filters"] = [
                                {
                                    "key": "entity_type",
                                    "values": [
                                        "Report",
                                        "Grouping",
                                        "Note",
                                        "Observed-Data",
                                        "Opinion",
                                    ],
                                }
                            ]
                        final_entity_type = "Stix-Domain-Object"

                # List
                lister = {
                    "Stix-Core-Object": self.helper.api_impersonate.stix_core_object.list,
                    "Stix-Domain-Object": self.helper.api_impersonate.stix_domain_object.list,
                    "Attack-Pattern": self.helper.api_impersonate.attack_pattern.list,
                    "Campaign": self.helper.api_impersonate.campaign.list,
                    "Channel": self.helper.api_impersonate.channel.list,
                    "Event": self.helper.api_impersonate.event.list,
                    "Note": self.helper.api_impersonate.note.list,
                    "Observed-Data": self.helper.api_impersonate.observed_data.list,
                    "Opinion": self.helper.api_impersonate.opinion.list,
                    "Report": self.helper.api_impersonate.report.list,
                    "Grouping": self.helper.api_impersonate.grouping.list,
                    "Case": self.helper.api_impersonate.case.list,
                    "Course-Of-Action": self.helper.api_impersonate.course_of_action.list,
                    "Identity": self.helper.api_impersonate.identity.list,
                    "Language": self.helper.api_impersonate.language.list,
                    "Indicator": self.helper.api_impersonate.indicator.list,
                    "Infrastructure": self.helper.api_impersonate.infrastructure.list,
                    "Intrusion-Set": self.helper.api_impersonate.intrusion_set.list,
                    "Location": self.helper.api_impersonate.location.list,
                    "Malware": self.helper.api_impersonate.malware.list,
                    "Threat-Actor": self.helper.api_impersonate.threat_actor.list,
                    "Tool": self.helper.api_impersonate.tool.list,
                    "Narrative": self.helper.api_impersonate.narrative.list,
                    "Vulnerability": self.helper.api_impersonate.vulnerability.list,
                    "Incident": self.helper.api_impersonate.incident.list,
                    "Stix-Cyber-Observable": self.helper.api_impersonate.stix_cyber_observable.list,
                    "Stix-Core-Relationship": self.helper.api_impersonate.stix_core_relationship.list,
                    "stix-core-relationship": self.helper.api_impersonate.stix_core_relationship.list,
                    "stix-sighting-relationship": self.helper.api_impersonate.stix_sighting_relationship.list,
                }
                do_list = lister.get(
                    final_entity_type,
                    lambda **kwargs: self.helper.log_error(
                        'Unknown object type "'
                        + final_entity_type
                        + '", doing nothing...'
                    ),
                )
                entities_list = do_list(
                    search=list_params["search"],
                    filters=list_params["filters"],
                    orderBy=list_params["orderBy"],
                    orderMode=list_params["orderMode"],
                    relationship_type=list_params["relationship_type"]
                    if "relationship_type" in list_params
                    else None,
                    elementId=list_params["elementId"]
                    if "elementId" in list_params
                    else None,
                    fromId=list_params["fromId"] if "fromId" in list_params else None,
                    toId=list_params["toId"] if "toId" in list_params else None,
                    elementWithTargetTypes=list_params["elementWithTargetTypes"]
                    if "elementWithTargetTypes" in list_params
                    else None,
                    fromTypes=list_params["fromTypes"]
                    if "fromTypes" in list_params
                    else None,
                    toTypes=list_params["toTypes"]
                    if "toTypes" in list_params
                    else None,
                    types=list_params["types"] if "types" in list_params else None,
                    getAll=True,
                )
                self.helper.log_info("Uploading: " + entity_type + " to " + file_name)
                list_filters = json.dumps(list_params)

            if entities_list is not None:
                if (
                    "element_id" in data and entity_type == "Analysis"
                ):  # treatment of elements in entity>Analysis
                    element_id = data["element_id"]
                    if (
                        element_id
                    ):  # filtering of the data to keep those in the container
                        new_entities_list = [
                            entity
                            for entity in entities_list
                            if ("objectsIds" in entity)
                            and (element_id in entity["objectsIds"])
                        ]
                        entities_list = new_entities_list

                if entity_type == "Stix-Cyber-Observable":
                    observable_values = [
                        f["observable_value"]
                        for f in entities_list
                        if "observable_value" in f
                    ]
                    observable_values_bytes = "\n".join(observable_values)
                    self.helper.api.stix_cyber_observable.push_list_export(
                        file_name, observable_values_bytes, list_filters
                    )
                elif entity_type == "Stix-Core-Object":
                    entities_values = [f["name"] for f in entities_list if "name" in f]
                    entities_values_bytes = "\n".join(entities_values)
                    self.helper.api.stix_core_object.push_list_export(
                        entity_type,
                        file_name,
                        entities_values_bytes,
                        list_filters,
                    )
                else:
                    entities_values = [f["name"] for f in entities_list if "name" in f]
                    entities_values_bytes = "\n".join(entities_values)
                    self.helper.api.stix_domain_object.push_list_export(
                        entity_type,
                        file_name,
                        entities_values_bytes,
                        list_filters,
                    )
                self.helper.log_info("Export done: " + entity_type + " to " + file_name)
            else:
                raise ValueError("An error occurred, the list is empty")

        return "Export done"

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connector_export_txt = ExportFileTxt()
        connector_export_txt.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)

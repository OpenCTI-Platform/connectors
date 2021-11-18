import yaml
import os
import json
import time

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

        list_params = data["list_params"]
        self.helper.log_info(data)

        final_entity_type = entity_type
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

        # List
        lister = {
            "Stix-Domain-Object": self.helper.api.stix_domain_object.list,
            "Attack-Pattern": self.helper.api.attack_pattern.list,
            "Campaign": self.helper.api.campaign.list,
            "Note": self.helper.api.note.list,
            "Observed-Data": self.helper.api.observed_data.list,
            "Opinion": self.helper.api.opinion.list,
            "Report": self.helper.api.report.list,
            "Course-Of-Action": self.helper.api.course_of_action.list,
            "Identity": self.helper.api.identity.list,
            "Indicator": self.helper.api.indicator.list,
            "Infrastructure": self.helper.api.infrastructure.list,
            "Intrusion-Set": self.helper.api.intrusion_set.list,
            "Location": self.helper.api.location.list,
            "Malware": self.helper.api.malware.list,
            "Threat-Actor": self.helper.api.threat_actor.list,
            "Tool": self.helper.api.tool.list,
            "Vulnerability": self.helper.api.vulnerability.list,
            "Incident": self.helper.api.incident.list,
            "Stix-Cyber-Observable": self.helper.api.stix_cyber_observable.list,
        }
        do_list = lister.get(
            final_entity_type,
            lambda **kwargs: self.helper.log_error(
                'Unknown object type "' + final_entity_type + '", doing nothing...'
            ),
        )
        entities_list = do_list(
            search=list_params["search"],
            filters=list_params["filters"],
            orderBy=list_params["orderBy"],
            orderMode=list_params["orderMode"],
            types=list_params["types"] if "types" in list_params else None,
            getAll=True,
        )
        observable_values = [f["observable_value"] for f in entities_list]
        observable_values_bytes = "\n".join(observable_values)
        self.helper.log_info("Uploading: " + entity_type + " to " + file_name)
        if entity_type != "Stix-Cyber-Observable":
            self.helper.api.stix_domain_object.push_list_export(
                entity_type, file_name, observable_values_bytes, json.dumps(list_params)
            )
        else:
            self.helper.api.stix_cyber_observable.push_list_export(
                file_name, observable_values_bytes, json.dumps(list_params)
            )
        self.helper.log_info("Export done: " + entity_type + " to " + file_name)
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
        exit(0)

import yaml
import os
import json
import io
import csv
import time

from pycti import OpenCTIConnectorHelper
from pycti.utils.constants import IdentityTypes


class ExportFileCsv:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

    def export_dict_list_to_csv(self, data):
        output = io.StringIO()
        headers = sorted(set().union(*(d.keys() for d in data)))
        csv_data = [headers]
        for d in data:
            row = []
            for h in headers:
                if h not in d:
                    row.append("")
                elif isinstance(d[h], str):
                    row.append(d[h])
                elif isinstance(d[h], list):
                    if len(d[h]) > 0 and isinstance(d[h][0], str):
                        row.append(",".join(d[h]))
                    elif len(d[h]) > 0 and isinstance(d[h][0], dict):
                        rrow = []
                        for r in d[h]:
                            if "name" in r:
                                rrow.append(r["name"])
                            elif "definition" in r:
                                rrow.append(r["definition"])
                        row.append(",".join(rrow))
                    else:
                        row.append("")
                elif isinstance(d[h], dict):
                    if "name" in d[h]:
                        row.append(d[h]["name"])
                    else:
                        row.append("")
                else:
                    row.append("")
            csv_data.append(row)
        writer = csv.writer(output, delimiter=";", quotechar='"', quoting=csv.QUOTE_ALL)
        writer.writerows(csv_data)
        return output.getvalue()

    def _process_message(self, data):
        entity_id = data["entity_id"]
        entity_type = data["entity_type"]
        file_name = data["file_name"]
        file_context = data["file_context"]
        export_type = data["export_type"]
        list_args = data["list_args"]
        if entity_id is not None:
            self.helper.log_info(
                "Exporting: "
                + entity_type
                + "/"
                + export_type
                + "("
                + entity_id
                + ") to "
                + file_name
            )
            entity_data = self.helper.api.stix_domain_entity.read(id=entity_id)
            entities_list = [entity_data]
            if "objectRefsIds" in entity_data:
                for id in entity_data["objectRefsIds"]:
                    entity = self.helper.api.stix_domain_entity.read(id=id)
                    entities_list.append(entity)
            csv_data = self.export_dict_list_to_csv(entities_list)
            self.helper.log_info(
                "Uploading: "
                + entity_type
                + "/"
                + export_type
                + "("
                + entity_id
                + ") to "
                + file_name
            )
            self.helper.api.stix_domain_entity.push_entity_export(
                entity_id, file_name, csv_data
            )
            self.helper.log_info(
                "Export done: "
                + entity_type
                + "/"
                + export_type
                + "("
                + entity_id
                + ") to "
                + file_name
            )
        else:
            self.helper.log_info(
                "Exporting list: "
                + entity_type
                + "/"
                + export_type
                + " to "
                + file_name
            )

            if IdentityTypes.has_value(entity_type):
                if list_args["filters"] is not None:
                    list_args["filters"].append(
                        {"key": "entity_type", "values": [entity_type]}
                    )
                else:
                    list_args["filters"] = [
                        {"key": "entity_type", "values": [entity_type]}
                    ]
                entity_type = "identity"

            # List
            lister = {
                "identity": self.helper.api.identity.list,
                "threat-actor": self.helper.api.threat_actor.list,
                "intrusion-set": self.helper.api.intrusion_set.list,
                "campaign": self.helper.api.campaign.list,
                "incident": self.helper.api.incident.list,
                "malware": self.helper.api.malware.list,
                "tool": self.helper.api.tool.list,
                "vulnerability": self.helper.api.vulnerability.list,
                "attack-pattern": self.helper.api.attack_pattern.list,
                "course-of-action": self.helper.api.course_of_action.list,
                "report": self.helper.api.report.list,
                "indicator": self.helper.api.indicator.list,
            }
            do_list = lister.get(
                entity_type.lower(),
                lambda **kwargs: self.helper.log_error(
                    'Unknown object type "' + entity_type + '", doing nothing...'
                ),
            )
            entities_list = do_list(
                search=list_args["search"],
                filters=list_args["filters"],
                orderBy=list_args["orderBy"],
                orderMode=list_args["orderMode"],
                getAll=True,
            )
            csv_data = self.export_dict_list_to_csv(entities_list)
            self.helper.log_info(
                "Uploading: " + entity_type + "/" + export_type + " to " + file_name
            )
            self.helper.api.stix_domain_entity.push_list_export(
                entity_type, file_name, csv_data, file_context, json.dumps(list_args)
            )
            self.helper.log_info(
                "Export done: " + entity_type + "/" + export_type + " to " + file_name
            )
        return ["Export done"]

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connectorExportFileCsv = ExportFileCsv()
        connectorExportFileCsv.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)

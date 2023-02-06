import csv
import io
import json
import os
import sys
import time

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from pycti.utils.constants import IdentityTypes, LocationTypes, StixCyberObservableTypes


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
        self.export_file_csv_delimiter = get_config_variable(
            "EXPORT_FILE_CSV_DELIMITER",
            ["export-file-csv", "delimiter"],
            config,
            False,
            ";",
        )

    def export_dict_list_to_csv(self, data):
        output = io.StringIO()
        headers = sorted(set().union(*(d.keys() for d in data)))
        if "hashes" in headers:
            headers = headers + [
                "hashes_MD5",
                "hashes_SHA-1",
                "hashes_SHA-256",
                "hashes_SHA-512",
                "hashes_SSDEEP",
            ]
        csv_data = [headers]
        for d in data:
            row = []
            for h in headers:
                if h.startswith("hashes_") and "hashes" in d:
                    hashes = {}
                    for hash in d["hashes"]:
                        hashes[hash["algorithm"]] = hash["hash"]
                    if h.split("_")[1] in hashes:
                        row.append(hashes[h.split("_")[1]])
                    else:
                        row.append("")
                elif h not in d:
                    row.append("")
                elif isinstance(d[h], str):
                    row.append(d[h])
                elif isinstance(d[h], int):
                    row.append(str(d[h]))
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
                            elif "value" in r:
                                rrow.append(r["value"])
                            elif "observable_value" in r:
                                rrow.append(r["observable_value"])
                        row.append(",".join(rrow))
                    else:
                        row.append("")
                elif isinstance(d[h], dict):
                    if "name" in d[h]:
                        row.append(d[h]["name"])
                    elif "value" in d[h]:
                        row.append(d[h]["value"])
                    elif "observable_value" in d[h]:
                        row.append(d[h]["observable_value"])
                    else:
                        row.append("")
                else:
                    row.append("")
            csv_data.append(row)
        writer = csv.writer(
            output,
            delimiter=self.export_file_csv_delimiter,
            quotechar='"',
            quoting=csv.QUOTE_ALL,
        )
        writer.writerows(csv_data)
        return output.getvalue()

    def _process_message(self, data):
        file_name = data["file_name"]
        export_scope = data["export_scope"]  # query or selection or single
        export_type = data["export_type"]  # Simple or Full
        # max_marking = data["max_marking"]  # TODO Implement marking restriction
        entity_type = data["entity_type"]

        if export_scope == "single":
            entity_id = data["entity_id"]
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
            entity_data = self.helper.api_impersonate.stix_domain_object.read(
                id=entity_id
            )
            if entity_data is None:
                entity_data = self.helper.api_impersonate.stix_cyber_observable.read(
                    id=entity_id
                )
            entities_list = []
            if "objectsIds" in entity_data:
                for id in entity_data["objectsIds"]:
                    entity = self.helper.api_impersonate.stix_domain_object.read(id=id)
                    if entity is None:
                        entity = self.helper.api_impersonate.stix_cyber_observable.read(
                            id=id
                        )
                    if entity is not None:
                        del entity["objectLabelIds"]
                        entities_list.append(entity)
                del entity_data["objectsIds"]
            if "objectLabelIds" in entity_data:
                del entity_data["objectLabelIds"]
            entities_list.append(entity_data)
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
            self.helper.api.stix_domain_object.push_entity_export(
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

        else:  # list export: export_scope = 'query' or 'selection'
            if export_scope == "selection":
                selected_ids = data["selected_ids"]
                list_filters = "selected_ids"
                entities_list = []

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
                    if entity_data is None:
                        entity_data = (
                            self.helper.api_impersonate.stix_sighting_relationship.read(
                                id=entity_id
                            )
                        )
                    entities_list.append(entity_data)

            else:  # export_scope = 'query'
                list_params = data["list_params"]
                self.helper.log_info(
                    "Exporting list: "
                    + entity_type
                    + "/"
                    + export_type
                    + " to "
                    + file_name
                )

                final_entity_type = entity_type
                if IdentityTypes.has_value(entity_type):
                    if list_params["filters"] is not None:
                        list_params["filters"].append(
                            {"key": "entity_type", "values": [entity_type]}
                        )
                    else:
                        list_params["filters"] = [
                            {"key": "entity_type", "values": [entity_type]}
                        ]
                    final_entity_type = "Identity"

                if LocationTypes.has_value(entity_type):
                    if list_params["filters"] is not None:
                        list_params["filters"].append(
                            {"key": "entity_type", "values": [entity_type]}
                        )
                    else:
                        list_params["filters"] = [
                            {"key": "entity_type", "values": [entity_type]}
                        ]
                    final_entity_type = "Location"

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

                if final_entity_type == "Container":
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
                                    "Case",
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
                                    "Case",
                                    "Case",
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
                    "Indicator": self.helper.api_impersonate.indicator.list,
                    "Infrastructure": self.helper.api_impersonate.infrastructure.list,
                    "Intrusion-Set": self.helper.api_impersonate.intrusion_set.list,
                    "Location": self.helper.api_impersonate.location.list,
                    "Language": self.helper.api_impersonate.language.list,
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
                list_filters = json.dumps(list_params)

            if entities_list is not None:
                csv_data = self.export_dict_list_to_csv(entities_list)
                self.helper.log_info(
                    "Uploading: " + entity_type + "/" + export_type + " to " + file_name
                )
                if entity_type == "Stix-Cyber-Observable":
                    self.helper.api.stix_cyber_observable.push_list_export(
                        file_name, csv_data, list_filters
                    )
                elif entity_type == "Stix-Core-Object":
                    self.helper.api.stix_core_object.push_list_export(
                        entity_type, file_name, csv_data, list_filters
                    )
                else:
                    self.helper.api.stix_domain_object.push_list_export(
                        entity_type, file_name, csv_data, list_filters
                    )
                self.helper.log_info(
                    "Export done: "
                    + entity_type
                    + "/"
                    + export_type
                    + " to "
                    + file_name
                )
            else:
                raise ValueError("An error occurred, the list is empty")

        return "Export done"

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
        sys.exit(0)

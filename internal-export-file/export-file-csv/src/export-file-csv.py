import csv
import io
import json
import os
import sys
import time

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


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
                "hashes.MD5",
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

    def _export_list(self, data, entities_list, list_filters):
        file_name = data["file_name"]
        export_type = data["export_type"]
        file_markings = data["file_markings"]
        entity_id = data.get("entity_id")
        entity_type = data["entity_type"]
        csv_data = self.export_dict_list_to_csv(entities_list)
        self.helper.log_info(
            "Uploading: " + entity_type + "/" + export_type + " to " + file_name
        )
        if entity_type == "Stix-Cyber-Observable":
            self.helper.api.stix_cyber_observable.push_list_export(
                entity_id,
                entity_type,
                file_name,
                file_markings,
                csv_data,
                list_filters,
            )
        elif entity_type == "Stix-Core-Object":
            self.helper.api.stix_core_object.push_list_export(
                entity_id,
                entity_type,
                file_name,
                file_markings,
                csv_data,
                list_filters,
            )
        else:
            self.helper.api.stix_domain_object.push_list_export(
                entity_id,
                entity_type,
                file_name,
                file_markings,
                csv_data,
                list_filters,
            )
        self.helper.connector_logger.info(
            "Export done",
            {
                "entity_type": entity_type,
                "export_type": export_type,
                "file_name": file_name,
            },
        )

    def _process_message(self, data):
        file_name = data["file_name"]
        export_scope = data["export_scope"]  # query or selection or single
        export_type = data["export_type"]  # Simple or Full
        file_markings = data["file_markings"]
        entity_id = data.get("entity_id")
        entity_type = data["entity_type"]
        main_filter = data.get("main_filter")
        access_filter = data.get("access_filter")

        # Single export always containing object_refs
        # Full but no relationships
        if export_scope == "single":
            self.helper.connector_logger.info(
                "Exporting",
                {
                    "entity_id": entity_id,
                    "export_type": export_type,
                    "file_name": file_name,
                },
            )

            # Fetch the base element
            # No usage of any filter because user ask directly for this specific export
            do_read = self.helper.api.stix2.get_reader(entity_type)
            entity_data = do_read(id=entity_id)
            # If the entity is not found, raise on error
            # This is not something that should happen. Rare case of concurrent deletion or rights modification
            if entity_data is None:
                raise ValueError(
                    "Unable to read/access to the entity, please check that the connector permission. Please note that all export files connectors should have admin permission as they impersonate the user requesting the export to avoir data leak."
                )

            # If the entity is a container
            # We have the objectsIds resolved coming from the data load
            # Due to usage of process_multiple_fields
            entities_list = []
            object_ids = entity_data.get("objectsIds")
            if object_ids is not None and len(object_ids) != 0:
                # Filters need to cumulate the access markings + the list of inner object ids
                export_selection_filter = {
                    "mode": "and",
                    "filterGroups": [
                        {
                            "mode": "or",
                            "filters": [
                                {
                                    "key": "ids",
                                    "values": entity_data["objectsIds"],
                                }
                            ],
                            "filterGroups": [],
                        },
                        access_filter,
                    ],
                    "filters": [],
                }
                entities_list = self.helper.api_impersonate.opencti_stix_object_or_stix_relationship.list(
                    filters=export_selection_filter, getAll=True
                )
                # Cleanup object extra information
                # Due to lack of support of this in export_dict_list_to_csv
                for entity in entities_list:
                    if "objectLabelIds" in entity:
                        del entity["objectLabelIds"]
                del entity_data["objectsIds"]

            # Cleanup object extra information
            # Due to lack of support of this in export_dict_list_to_csv
            if "objectLabelIds" in entity_data:
                del entity_data["objectLabelIds"]

            entities_list.append(entity_data)
            csv_data = self.export_dict_list_to_csv(entities_list)
            self.helper.connector_logger.info(
                "Uploading",
                {
                    "entity_id": entity_id,
                    "export_type": export_type,
                    "file_name": file_name,
                    "file_markings": file_markings,
                },
            )
            self.helper.api.stix_domain_object.push_entity_export(
                entity_id=entity_id,
                file_name=file_name,
                data=csv_data,
                file_markings=file_markings,
            )
            self.helper.connector_logger.info(
                "Export done",
                {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "export_type": export_type,
                    "file_name": file_name,
                    "file_markings": file_markings,
                },
            )

        # Selection export without object_refs/relationships
        # = Only simple
        if export_scope == "selection":
            list_filters = "selected_ids"
            entities_list = self.helper.api_impersonate.opencti_stix_object_or_stix_relationship.list(
                filters=main_filter, getAll=True
            )
            self._export_list(data, entities_list, list_filters)

        # Query export without object_refs/relationships
        # = Only simple
        if export_scope == "query":
            list_params = data["list_params"]
            list_params_filters = list_params.get("filters")
            self.helper.connector_logger.info(
                "Exporting list: ",
                {
                    "entity_type": entity_type,
                    "export_type": export_type,
                    "file_name": file_name,
                },
            )

            filter_groups = []
            if list_params_filters is not None:
                filter_groups.append(list_params_filters)
            if access_filter is not None:
                filter_groups.append(access_filter)
            export_query_filter = {
                "mode": "and",
                "filterGroups": filter_groups,
                "filters": [],
            }

            entities_list = self.helper.api_impersonate.stix2.export_entities_list(
                entity_type=entity_type,
                search=list_params.get("search"),
                filters=export_query_filter,
                orderBy=list_params.get("orderBy"),
                orderMode=list_params.get("orderMode"),
                getAll=True,
            )
            list_filters = json.dumps(list_params)
            self._export_list(data, entities_list, list_filters)

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

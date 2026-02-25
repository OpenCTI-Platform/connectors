import json
import os
import sys
import time

from lib.internal_export import InternalExportConnector
from unogenerator import ODS_Standard
from unogenerator.commons import ColorsNamed


def sanitize_cell(value: str) -> str:
    if len(value) > 1 and value[0] in ["=", "+", "-", "@"]:
        value = "[" + value[0] + "]" + value[1:]
        return value
    elif len(value) > 4 and value[0:3] in ["0x09", "0x0D"]:
        return value[4:]
    else:
        return value


class ExportFileODSConnector(InternalExportConnector):
    def __init__(self):
        """Initialization of the connector

        Note that additional attributes for the connector can be set after the super() call.

        Standarised way to grab attributes from environment variables is as follows:

        >>>         ...
        >>>         super().__init__()
        >>>         self.my_attribute = os.environ.get("MY_ATTRIBUTE", "INFO")

        This will make use of the `os.environ.get` method to grab the environment variable and set a default value (in the example "INFO") if it is not set.
        Additional tunning can be made to the connector by adding additional environment variables.

        Raising ValueErrors or similar might be useful for tracking down issues with the connector initialization.
        """
        super().__init__()

    def _get_date(self, octi_date) -> str:
        d = octi_date.rstrip("Z").split("T")
        return d[0] + " " + d[1]

    def _check_markings(self, e) -> bool:
        """
        Checks if an entity conforms to given max marking levels
        """
        result = True
        if "objectMarking" in e and len(e["objectMarking"]) > 0:
            for m in e["objectMarking"]:
                if m["id"] in self.content_markings:
                    result = False
        return result

    def _get_content_markings(self, data):
        """
        get the list of forbidden markings
        """
        result = []
        if "main_filter" in data and "filters" in data["main_filter"]:
            for f in data["main_filter"]["filters"]:
                if f["key"] == "objectMarking":
                    result = f["values"]
        return result

    def _get_export_list(self, entities_list) -> list:
        """
        Returns a list of tuples that are structured as (entity, level of neighborhood).
        Level 1 are the selected entities.
        Level 2 are the first neighbors.
        entities_list: the selected entities
        """
        export_list = []
        for f in entities_list:
            # if entity is above max_marking_def, ignore it
            if not self._check_markings(f):
                continue
            export_list.append((f, 1))
            self.helper.log_debug("Export Type: " + self.export_type)

            # get neighbor entities if full export
            if self.export_type == "full":
                entity_id = f["id"]
                self.helper.log_debug("Entity ID:" + entity_id)
                rels = self.helper.api_impersonate.stix_core_relationship.list(
                    fromId=entity_id, filters=self.main_filter
                )
                self.helper.log_debug("Relationships from entity: " + str(rels))
                for r in rels:
                    neighbor = self.helper.api_impersonate.stix_domain_object.read(
                        id=r["to"]["id"]
                    )
                    if neighbor is None:
                        neighbor = (
                            self.helper.api_impersonate.stix_cyber_observable.read(
                                id=r["to"]["id"]
                            )
                        )
                    if self._check_markings(neighbor):
                        export_list.append((neighbor, 2))
                rels = self.helper.api_impersonate.stix_core_relationship.list(
                    toId=entity_id
                )
                self.helper.log_debug("Relationships to entity: " + str(rels))
                for r in rels:
                    neighbor = self.helper.api_impersonate.stix_domain_object.read(
                        id=r["from"]["id"]
                    )
                    if neighbor is None:
                        neighbor = (
                            self.helper.api_impersonate.stix_cyber_observable.read(
                                id=r["from"]["id"]
                            )
                        )
                    if self._check_markings(neighbor):
                        export_list.append((neighbor, 2))
        return export_list

    def _get_content(self, export_list) -> bytes:
        """
        Returns an ODS document in bytes.
        export_list: list of entities to integrate
        """
        with ODS_Standard() as sheet:
            # calculate headers
            entities_list = [e[0] for e in export_list]
            headers = sorted(set().union(*(e.keys() for e in entities_list)))
            if "hashes" in headers:
                headers = headers + [
                    "hashes.MD5",
                    "hashes_SHA-1",
                    "hashes_SHA-256",
                    "hashes_SHA-512",
                    "hashes_SSDEEP",
                ]
            sheet.addRowWithStyle("A1", headers, colors=ColorsNamed.Blue)
            # calculate rows
            nb_row = 1
            for d in export_list:
                nb_row += 1
                row = []
                for h in headers:
                    if h.startswith("hashes_") and "hashes" in d[0]:
                        hashes = {}
                        for hash in d[0]["hashes"]:
                            hashes[hash["algorithm"]] = hash["hash"]
                        if h.split("_")[1] in hashes:
                            row.append(sanitize_cell(hashes[h.split("_")[1]]))
                        else:
                            row.append("")
                    elif h not in d[0]:
                        row.append("")
                    elif isinstance(d[0][h], str):
                        row.append(sanitize_cell(d[0][h]))
                    elif isinstance(d[0][h], int):
                        row.append(sanitize_cell(str(d[0][h])))
                    elif isinstance(d[0][h], list):
                        if len(d[0][h]) > 0 and isinstance(d[0][h][0], str):
                            row.append(sanitize_cell(",".join(d[0][h])))
                        elif len(d[0][h]) > 0 and isinstance(d[0][h][0], dict):
                            rrow = []
                            for r in d[0][h]:
                                if "name" in r:
                                    rrow.append(sanitize_cell(r["name"]))
                                elif "definition" in r:
                                    rrow.append(sanitize_cell(r["definition"]))
                                elif "value" in r:
                                    rrow.append(sanitize_cell(r["value"]))
                                elif "observable_value" in r:
                                    rrow.append(sanitize_cell(r["observable_value"]))
                            row.append(sanitize_cell(",".join(rrow)))
                        else:
                            row.append("")
                    elif isinstance(d[0][h], dict):
                        if "name" in d[0][h]:
                            row.append(sanitize_cell(d[0][h]["name"]))
                        elif "value" in d[0][h]:
                            row.append(sanitize_cell(d[0][h]["value"]))
                        elif "observable_value" in d[0][h]:
                            row.append(sanitize_cell(d[0][h]["observable_value"]))
                        else:
                            row.append("")
                    else:
                        row.append("")
                # csv_data.append(row)
                if d[1] == 1:
                    sheet.addRowWithStyle(
                        "A" + str(nb_row), row, colors=ColorsNamed.GrayDark
                    )
                if d[1] == 2:
                    sheet.addRowWithStyle(
                        "A" + str(nb_row), row, colors=ColorsNamed.GrayLight
                    )

            sheet.save("./tmp/" + self.file_name)
            ods = open("./tmp/" + self.file_name, "rb")
            content = ods.read()
            os.remove("./tmp/" + self.file_name)

        return content

    def _process_message(self, data):
        """
        Processing the export request
        """
        self.helper.log_debug(f"Data: {data}")
        self.file_name = data["file_name"].rstrip(".unknown") + ".ods"
        file_markings = data["file_markings"]
        entity_id = data.get("entity_id")
        entity_type = data["entity_type"]
        export_scope = data["export_scope"]
        self.export_type = data["export_type"]
        self.main_filter = data.get("main_filter")
        access_filter = data.get("access_filter")
        self.content_markings = self._get_content_markings(data)
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the export..."
        )

        # ===========================
        # === Add your code below ===
        # ===========================
        self.helper.log_debug("Building contents...")

        if export_scope == "single":
            raise ValueError("This connector only supports list exports")

        if (
            entity_type == "stix-sighting-relationship"
            or entity_type == "stix-core-relationship"
            or entity_type == "Opinion"
        ):
            raise ValueError("ODS export is not available for this entity type.")

        else:  # export_scope = 'selection' or 'query'
            if export_scope == "selection":
                entities_list = []
                list_filters = "selected_ids"

                entity_data_sdo = self.helper.api_impersonate.stix_domain_object.list(
                    filters=self.main_filter
                )
                entity_data_sco = (
                    self.helper.api_impersonate.stix_cyber_observable.list(
                        filters=self.main_filter
                    )
                )
                entity_data_scr = (
                    self.helper.api_impersonate.stix_core_relationship.list(
                        filters=self.main_filter
                    )
                )
                entity_data_ssr = (
                    self.helper.api_impersonate.stix_sighting_relationship.list(
                        filters=self.main_filter
                    )
                )

                entities_list = (
                    entity_data_sdo
                    + entity_data_sco
                    + entity_data_scr
                    + entity_data_ssr
                )

            else:  # export_scope = 'query'
                list_params = data["list_params"]
                list_params_filters = list_params.get("filters")
                access_filter_content = access_filter.get("filters")
                if len(access_filter_content) != 0 and list_params_filters is not None:
                    export_query_filter = {
                        "mode": "and",
                        "filterGroups": [list_params_filters, access_filter],
                        "filters": [],
                    }
                elif len(access_filter_content) == 0:
                    export_query_filter = list_params_filters
                else:
                    export_query_filter = access_filter

                entities_list = self.helper.api_impersonate.stix2.export_entities_list(
                    entity_type=entity_type,
                    search=list_params.get("search"),
                    filters=export_query_filter,
                    orderBy=list_params.get("orderBy"),
                    orderMode=list_params.get("orderMode"),
                    getAll=True,
                )
                self.helper.log_info(
                    "Uploading: " + entity_type + " to " + self.file_name
                )
                list_filters = json.dumps(list_params)

            export_list = self._get_export_list(entities_list)

            if entities_list is not None:
                if entity_type == "Stix-Cyber-Observable":
                    self.helper.log_info(f"Uploading file as '{self.file_name}'...")
                    self.helper.api.stix_cyber_observable.push_list_export(
                        entity_id,
                        entity_type,
                        self.file_name,
                        file_markings,
                        self._get_content(export_list),
                        list_filters,
                    )
                elif entity_type == "Stix-Core-Object":
                    self.helper.log_info(f"Uploading file as '{self.file_name}'...")
                    self.helper.api.stix_core_object.push_list_export(
                        entity_id,
                        entity_type,
                        self.file_name,
                        file_markings,
                        self._get_content(export_list),
                        list_filters,
                    )
                else:
                    if entity_type == "Malware-Analysis":
                        for entity in entities_list:
                            entity["name"] = entity["result_name"]
                    self.helper.log_info(f"Uploading file as '{self.file_name}'...")
                    self.helper.api.stix_domain_object.push_list_export(
                        entity_id,
                        entity_type,
                        self.file_name,
                        file_markings,
                        self._get_content(export_list),
                        list_filters,
                    )
                self.helper.log_info(
                    "Export done: " + entity_type + " to " + self.file_name
                )
            else:
                raise ValueError("An error occurred, the list is empty")

        return "Export done"


if __name__ == "__main__":
    try:
        connector = ExportFileODSConnector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)

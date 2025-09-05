import json
import os
import sys
import time

from unogenerator import ODT_Standard

from lib.internal_export import InternalExportConnector


def sanitize_cell(value: str) -> str:
    if len(value) > 1 and value[0] in ["=", "+", "-", "@"]:
        value = "[" + value[0] + "]" + value[1:]
        return value
    elif len(value) > 4 and value[0:3] in ["0x09", "0x0D"]:
        return value[4:]
    else:
        return value


class ExportFileODTConnector(InternalExportConnector):
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

    def _add_ODT_for_entity(self, e, document, heading) -> None:
        """
        This function adds contents of an entity to an ODT document
        e: entity given as parameter
        document: ODT document given by reference
        heading: heading style of name/value to differentiate principal entities and their neighbors
        """
        self.helper.log_debug("Entity: " + str(e))

        # name or value or content
        if ("name" in e) and (e["name"] is not None):
            document.addString(sanitize_cell(e["name"]), heading, paragraphBreak=True)
        elif ("value" in e) and (e["value"] is not None):
            document.addString(sanitize_cell(e["value"]), heading, paragraphBreak=True)
        elif ("content" in e) and (e["content"] is not None):
            document.addString(
                sanitize_cell(e["content"]), heading, paragraphBreak=True
            )
        else:
            document.addString(
                sanitize_cell(e["standard_id"]), heading, paragraphBreak=True
            )

        # entity type
        document.addString(
            sanitize_cell(e["entity_type"]), "Standard", paragraphBreak=False
        )

        # marking
        if ("objectMarking" in e) and (len(e["objectMarking"]) > 0):
            for m in e["objectMarking"]:
                if "definition" in m and m["definition"] is not None:
                    document.addString(
                        " - " + sanitize_cell(m["definition"]),
                        "Standard",
                        paragraphBreak=False,
                    )
        else:
            document.addString(" - no markings", "Standard", paragraphBreak=False)
        document.addString(" ", "Standard", paragraphBreak=True)

        # author
        if (
            ("createdBy" in e)
            and (e["createdBy"] is not None)
            and ("name" in e["createdBy"])
            and (e["createdBy"]["name"] is not None)
        ):
            document.addString(
                "Author: " + sanitize_cell(e["createdBy"]["name"]),
                "Standard",
                paragraphBreak=True,
            )

        # date
        if ("published" in e) and (e["published"] is not None):
            document.addString(
                "Published: " + sanitize_cell(self._get_date(e["published"])),
                "Standard",
                paragraphBreak=True,
            )
        elif ("created_at" in e) and (e["created_at"] is not None):
            document.addString(
                "Created: " + sanitize_cell(self._get_date(e["created_at"])),
                "Standard",
                paragraphBreak=True,
            )

        return None

    def _get_content(self, entities_list) -> bytes:
        """
        This function creates ODT content and returns it in bytes
        entities_list: list of entities to export in ODT
        """
        with ODT_Standard() as doc:
            for f in entities_list:
                # if entity is above the max markings, ignore it
                if not self._check_markings(f):
                    continue
                self._add_ODT_for_entity(f, doc, "Heading 1")
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
                            self._add_ODT_for_entity(neighbor, doc, "Heading 2")
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
                            self._add_ODT_for_entity(neighbor, doc, "Heading 2")
            doc.save("./tmp/" + self.file_name)
            odt = open("./tmp/" + self.file_name, "rb")
            content = odt.read()
            os.remove("./tmp/" + self.file_name)
        return content

    def _process_message(self, data):
        """
        Processing the export request
        """
        self.helper.log_debug(f"Data: {data}")
        self.file_name = data["file_name"].rstrip(".unknown") + ".odt"
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
            raise ValueError("Text/html export is not available for this entity type.")

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

            if entities_list is not None:
                if entity_type == "Stix-Cyber-Observable":
                    self.helper.log_info(f"Uploading file as '{self.file_name}'...")
                    self.helper.api.stix_cyber_observable.push_list_export(
                        entity_id,
                        entity_type,
                        self.file_name,
                        file_markings,
                        self._get_content(entities_list),
                        list_filters,
                    )
                elif entity_type == "Stix-Core-Object":
                    self.helper.log_info(f"Uploading file as '{self.file_name}'...")
                    self.helper.api.stix_core_object.push_list_export(
                        entity_id,
                        entity_type,
                        self.file_name,
                        file_markings,
                        self._get_content(entities_list),
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
                        self._get_content(entities_list),
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
        connector = ExportFileODTConnector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)

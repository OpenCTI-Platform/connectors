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
        self.errors: list[Exception] = (
            []
        )  # error holder to be reset before each new process

    # The frontend (opencti #15593) sends the visible DataTable column ids as
    # the ``visible_columns`` list. A few presentation column ids do not map 1:1
    # onto a field key in the exported entity dicts. Each such id maps to a
    # ``(source field key, sub-field)`` pair: the source key is the field to read
    # from the entity dict, and the sub-field is the attribute to pull from that
    # field's resolved value (``None`` renders the field's representative value).
    # This lets a single underlying field - e.g. a relationship's ``from``/``to``
    # endpoint - be projected into several distinct columns (its name and its
    # entity type) instead of being collapsed into one. Any id not listed here is
    # matched against the export keys as-is (most ids already match, e.g.
    # ``relationship_type``, ``entity_type``, ``created_at``, ``objectMarking``).
    VISIBLE_COLUMN_FIELDS = {
        "fromName": ("from", None),
        "fromType": ("from", "entity_type"),
        "toName": ("to", None),
        "toType": ("to", "entity_type"),
        "creator": ("creators", None),
    }

    # Observable hash algorithms expanded into their own ``hashes_<algo>``
    # columns whenever a ``hashes`` column is exported.
    HASHES_ALGORITHMS = ["MD5", "SHA-1", "SHA-256", "SHA-512", "SSDEEP"]

    @classmethod
    def _select_export_columns(cls, data_headers, columns):
        """Resolve the ordered ``(header, source_key, sub_field)`` columns.

        ``columns`` is the optional list of visible DataTable column ids sent by
        the frontend. ``None`` or an empty list means "no filter" - one column
        per data header. Presentation ids in ``VISIBLE_COLUMN_FIELDS`` are
        projected onto their underlying field (and optional sub-field), so
        ``fromName`` and ``fromType`` become two distinct columns both reading
        the relationship's ``from`` endpoint (its representative value and its
        entity type). Ids whose underlying field is absent from the data are
        dropped; the requested order is preserved and exact duplicates removed.
        If nothing resolves, fall back to all columns so the export is never
        empty.
        """
        if not columns:
            return [(header, header, None) for header in data_headers]
        selected = []
        seen = set()
        for column in columns:
            source_key, sub_field = cls.VISIBLE_COLUMN_FIELDS.get(
                column, (column, None)
            )
            if source_key in data_headers and column not in seen:
                seen.add(column)
                selected.append((column, source_key, sub_field))
        return selected or [(header, header, None) for header in data_headers]

    @staticmethod
    def _render_value(value):
        """Render a raw field value to its CSV string representation."""
        if isinstance(value, str):
            return value
        if isinstance(value, int):  # bool is an int subclass, kept as before
            return str(value)
        if isinstance(value, float):
            return str(value)
        if isinstance(value, list):
            if len(value) > 0 and isinstance(value[0], str):
                return ",".join(value)
            if len(value) > 0 and isinstance(value[0], dict):
                rendered = []
                for item in value:
                    if "name" in item:
                        rendered.append(
                            item["name"] if item["name"] is not None else ""
                        )
                    elif "definition" in item:
                        rendered.append(
                            item["definition"] if item["definition"] is not None else ""
                        )
                    elif "value" in item:
                        rendered.append(
                            item["value"] if item["value"] is not None else ""
                        )
                    elif "observable_value" in item:
                        rendered.append(
                            item["observable_value"]
                            if item["observable_value"] is not None
                            else ""
                        )
                return ",".join(rendered)
            return ""
        if isinstance(value, dict):
            if "name" in value:
                return value["name"] or ""
            if "value" in value:
                return value["value"] or ""
            if "observable_value" in value:
                return value["observable_value"] or ""
            return ""
        return ""

    @classmethod
    def _extract_hash(cls, value, algorithm):
        """Return the hash for ``algorithm`` from a STIX ``hashes`` list."""
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and item.get("algorithm") == algorithm:
                    return item.get("hash") or ""
        return ""

    @classmethod
    def _render_cell(cls, entity, source_key, sub_field):
        """Render a single CSV cell for ``entity`` given a column spec."""
        if source_key not in entity:
            return ""
        value = entity[source_key]
        if sub_field is None:
            return cls._render_value(value)
        if source_key == "hashes":
            return cls._extract_hash(value, sub_field)
        if isinstance(value, dict):
            return cls._render_value(value.get(sub_field))
        if isinstance(value, list):
            return ",".join(
                cls._render_value(item.get(sub_field))
                for item in value
                if isinstance(item, dict) and item.get(sub_field) is not None
            )
        return ""

    def export_dict_list_to_csv(self, data, columns=None):
        output = io.StringIO()
        data_headers = sorted(set().union(*(d.keys() for d in data)))
        column_specs = self._select_export_columns(data_headers, columns)
        # Expand a "hashes" field into one column per algorithm. The expanded
        # columns are appended after the regular columns (matching the previous
        # output ordering) while the raw "hashes" column is kept as-is.
        expanded_specs = list(column_specs)
        for _, source_key, sub_field in column_specs:
            if source_key == "hashes" and sub_field is None:
                for algorithm in self.HASHES_ALGORITHMS:
                    expanded_specs.append(("hashes_" + algorithm, "hashes", algorithm))
        headers = [spec[0] for spec in expanded_specs]
        csv_data = [headers]
        for entity in data:
            try:
                row = [
                    self._render_cell(entity, source_key, sub_field)
                    for _, source_key, sub_field in expanded_specs
                ]
                csv_data.append(row)
            except Exception as err:
                self.helper.connector_logger.warning(
                    "Error with csv input data, one line cannot be exported." + str(err)
                )
                self.errors.append(err)
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
        list_params = data.get("list_params", {})
        # Use None (not []) as the "no filter" sentinel so an absent
        # visible_columns exports all columns, while a provided list filters.
        visible_columns = list_params.get("visible_columns")
        self.helper.connector_logger.debug(
            "Exporting with visible columns",
            {"visible_columns": visible_columns},
        )
        csv_data = self.export_dict_list_to_csv(entities_list, visible_columns)
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
        self.errors = []  # reset before launching main process

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

        if len(self.errors) > 0:
            msg = f"Some values were not processed in CSV (for {len(self.errors)} lines). See connector logs for details."
            self.helper.api.work.report_expectation(
                work_id=self.helper.work_id, error={"error": msg, "source": "CONNECTOR"}
            )
            return msg
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

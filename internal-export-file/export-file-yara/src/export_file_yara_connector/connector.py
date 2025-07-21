from os.path import splitext

from pycti import OpenCTIConnectorHelper

from .config_loader import ConfigConnector


class ConnectorExportFileYARA:

    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper

    def process_message(self, data: dict) -> str:
        """
        Processing the export request
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param data: dict of data to process
        :return: string
        """
        try:
            # Extract information from entity data
            entity_id = data.get("entity_id")
            entity_type = data.get("entity_type")
            file_name = data.get("file_name")
            export_type = data.get("export_type")
            file_markings = data.get("file_markings")
            access_filter = data.get("access_filter")
            export_scope = data.get("export_scope")  # query or selection or single
            file_format = data.get("format")

            errors = []

            # workaround
            if splitext(file_name)[1] == ".unknown":
                file_name = splitext(file_name)[0] + '.' + "yar"

            if export_scope == "selection":
                main_filter = data.get("main_filter")
                entities_data_sdo = self.helper.api_impersonate.stix_domain_object.list(
                    filters=main_filter
                )
                yara_patterns = []
                for entity_data_sdo in entities_data_sdo:
                    if entity_data_sdo.get("pattern_type") != "yara":
                        self.helper.connector_logger.warning(f"Unable to process indicator name: {entity_data_sdo.get("name")}, pattern is not YARA")
                        errors.append({entity_data_sdo.get("name")})
                        continue
                    else:
                        yara_patterns.append(entity_data_sdo.get("pattern"))

                yara_file_content = '\n\n'.join(yara_patterns)

                self.helper.api.stix_domain_object.push_list_export(
                    entity_id=entity_id,
                    entity_type=entity_type,
                    file_name=file_name,
                    file_markings=file_markings,
                    data=yara_file_content,
                    mime_type=file_format
                )

                if len(errors) > 0:
                    msg = f"unable to export the following indicators: {str(errors)}. See connector logs for details."
                    self.helper.api.work.report_expectation(
                        work_id=self.helper.work_id, error={"error": msg, "source": "CONNECTOR"}
                    )

            elif export_scope == "query":
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

                yara_patterns = []
                for entity_data_sdo in entities_list:
                    if entity_data_sdo.get("pattern_type") != "yara":
                        self.helper.connector_logger.warning(f"Unable to process indicator name: {entity_data_sdo.get("name")}, pattern is not YARA")
                        errors.append({entity_data_sdo.get("name")})
                        continue
                    else:
                        yara_patterns.append(entity_data_sdo.get("pattern"))

                yara_file_content = '\n\n'.join(yara_patterns)

                self.helper.api.stix_domain_object.push_list_export(
                    entity_id=entity_id,
                    entity_type=entity_type,
                    file_name=file_name,
                    file_markings=file_markings,
                    data=yara_file_content,
                    mime_type=file_format
                )

            elif export_scope == "single":

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
                        "Unable to read/access to the entity, please check that the connector permission. "
                        "Please note that all export files connectors should have admin permission as they impersonate the user requesting the export to avoid data leak."
                    )

                # case of a single export on a YARA indicator
                if export_type == "simple":
                    if entity_type == "Indicator":
                        if entity_data.get("pattern_type") == "yara":
                            self.helper.api.stix_domain_object.push_entity_export(
                                entity_id=entity_id,
                                file_name=file_name,
                                data=entity_data.get("pattern"),
                                file_markings=file_markings,
                            )
                        else:
                            self.helper.connector_logger.warning(f"Unable to process indicator name: {entity_data.get("name")}, pattern is not YARA")
                            msg = f"unable to export indicator: {entity_data.get("name")}. Indicator is not a YARA pattern"
                            self.helper.api.work.report_expectation(
                                work_id=self.helper.work_id, error={"error": msg, "source": "CONNECTOR"}
                            )
                    else:
                        msg = f"Connector can only export Indicator of type YARA in the single export mode"
                        self.helper.connector_logger.warning(msg)
                        self.helper.api.work.report_expectation(
                            work_id=self.helper.work_id, error={"error": msg, "source": "CONNECTOR"}
                        )

                # case of a full export on a container
                elif export_type == "full":
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

                    else:
                        # Get the relations from the main entity to indicators
                        stix_indicator_relations = self.helper.api_impersonate.stix_core_relationship.list(
                            fromId=entity_id, toTypes=["Indicator"], getAll=True
                        )
                        for stix_indicator_relation in stix_indicator_relations:
                            indicator = self.helper.api_impersonate.indicator.read(
                                id=stix_indicator_relation["to"]["id"]
                            )
                            entities_list.append(indicator)

                    # going to build the file
                    yara_patterns = []

                    for entity in entities_list:
                        if entity.get("entity_type") == "Indicator" and entity.get("pattern_type") == "yara":
                            yara_patterns.append(entity.get("pattern"))

                    yara_file_content = '\n\n'.join(yara_patterns)
                    self.helper.api.stix_domain_object.push_entity_export(
                        entity_id=entity_id,
                        file_name=file_name,
                        data=yara_file_content,
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
            else:
                raise ValueError(
                    f'This connector currently only handles the entity types: "Indicators" with a YARA pattern.'
                )
            return "Export done"

        except Exception as err:
            # Handling other unexpected exceptions
            return self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected Error occurred", {"error_message": str(err)}
            )

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then export the file.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)

from enum import Enum
from io import BytesIO
from os.path import splitext
from zipfile import ZIP_DEFLATED, ZipFile

from pycti import OpenCTIConnectorHelper

from .config_loader import ConfigConnector


# Configure this enum if adding any additional pattern types
class Join(Enum):
    """
    How indicators of the same type should be joined together.
    Also defines which indicator pattern types will be exported.
    """

    yara = "\n\n"
    sigma = "\n---\n"
    snort = "\n"


class DataCollector:
    """
    Collects threat hunting rules, compiles, and stores the results.
    """

    def __init__(self, helper: OpenCTIConnectorHelper):
        self.errors = list()
        self.helper = helper
        self.pattern_types = [member.name for member in Join]
        self.patterns = dict()
        self.pattern_files = dict()
        for pt in self.pattern_types:
            self.patterns[pt] = list()
            self.pattern_files[pt] = str()

    def compile(self) -> None:
        for pt in self.pattern_types:
            self.pattern_files[pt] = Join[pt].value.join(self.patterns[pt])

    def extract(self, entities: list) -> None:

        for entity_data_sdo in entities:
            for pt in self.pattern_types:
                if entity_data_sdo.get("pattern_type") == pt:
                    self.patterns.get(pt).append(entity_data_sdo.get("pattern"))
                    break
            else:
                self.helper.connector_logger.warning(
                    f"Unable to process object name: {entity_data_sdo.get('name')}, pattern is not {str(self.pattern_types)}"
                )
                self.errors.append(entity_data_sdo.get("name"))

        self.compile()

    def zip_files(self) -> bytes:
        with BytesIO() as buffer:
            with ZipFile(buffer, "w", ZIP_DEFLATED) as zf:
                if self.pattern_files.get("yara"):
                    zf.writestr("yara.yar", self.pattern_files["yara"])
                if self.pattern_files.get("sigma"):
                    zf.writestr("sigma.yml", self.pattern_files["sigma"])
                if self.pattern_files.get("snort"):
                    zf.writestr("snort.rules", self.pattern_files["snort"])
            return buffer.getvalue()


class ConnectorExportFileThreatHunting:

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

        collector = DataCollector(self.helper)

        try:
            # Extract information from entity data
            entity_id = data.get("entity_id")
            self.helper.connector_logger.debug(f"entity_id {entity_id}")
            entity_type = data.get("entity_type")
            self.helper.connector_logger.debug(f"entity_type {entity_type}")
            file_name = data.get("file_name")
            self.helper.connector_logger.debug(f"file_name {file_name}")
            export_type = data.get("export_type")
            self.helper.connector_logger.debug(f"export_type {export_type}")
            file_markings = data.get("file_markings")
            self.helper.connector_logger.debug(f"file_markings {file_markings}")
            access_filter = data.get("access_filter")
            self.helper.connector_logger.debug(f"access_filter {access_filter}")
            export_scope = data.get("export_scope")  # selection or query or single
            self.helper.connector_logger.debug(f"export_scope {export_scope}")
            file_format = data.get("format")
            self.helper.connector_logger.debug(f"file_format {file_format}")

            # Workaround for platform using .unknown file extension
            if splitext(file_name)[1] == ".unknown":
                file_name = splitext(file_name)[0] + "." + "zip"
                self.helper.connector_logger.debug(f"file_name renamed to {file_name}")

            # Activated when SELECTION IS MADE from search results, and export is triggered
            if export_scope == "selection":
                main_filter = data.get("main_filter")
                self.helper.connector_logger.debug(f"main_filter {main_filter}")
                entities_data_sdo = self.helper.api_impersonate.stix_domain_object.list(
                    filters=main_filter
                )

                self.helper.connector_logger.info(
                    "Exporting filter (export_scope='selection')",
                    {
                        "entity_id": entity_id,
                        "export_type": export_type,
                        "file_name": file_name,
                    },
                )

                collector.extract(entities_data_sdo)

                self.helper.api.stix_domain_object.push_list_export(
                    entity_id=entity_id,
                    entity_type=entity_type,
                    file_name=file_name,
                    file_markings=file_markings,
                    data=collector.zip_files(),
                    mime_type="application/zip",
                )

                self.helper.connector_logger.debug(
                    f"collector.errors {collector.errors}"
                )
                # Just fail silently unless ALL of the extractions failed
                if len(collector.errors) == len(entities_data_sdo):
                    msg = f"Unable to export any of the requested objects: {str(collector.errors)}. See connector logs for details."
                    self.helper.api.work.report_expectation(
                        work_id=self.helper.work_id,
                        error={"error": msg, "source": "CONNECTOR"},
                    )

            # Activated when NOTHING is selected in search results, and export is triggered
            elif export_scope == "query":
                list_params = data["list_params"]
                self.helper.connector_logger.debug(f"list_params {list_params}")
                list_params_filters = list_params.get("filters")
                self.helper.connector_logger.info(
                    "Exporting list (export_scope='query'): ",
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

                collector.extract(entities_list)

                self.helper.api.stix_domain_object.push_list_export(
                    entity_id=entity_id,
                    entity_type=entity_type,
                    file_name=file_name,
                    file_markings=file_markings,
                    data=collector.zip_files(),
                    mime_type="application/zip",
                )

            elif export_scope == "single":

                self.helper.connector_logger.info(
                    "Exporting (export_scope='single')",
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
                        self.helper.connector_logger.debug(
                            "Processing single indicator export",
                            {
                                "id": entity_data.get("id"),
                                "name": entity_data.get("name"),
                                "pattern_type": entity_data.get("pattern_type"),
                            },
                        )
                        collector.extract([entity_data])
                        collector.compile()

                        if len(collector.errors) == 1:  # Failure
                            self.helper.connector_logger.warning(
                                f"Unable to process indicator name: {entity_data.get('name')}, pattern was not recognized"
                            )
                            msg = f"unable to export indicator: {entity_data.get('name')}. Indicator pattern was not recognized"
                            self.helper.api.work.report_expectation(
                                work_id=self.helper.work_id,
                                error={"error": msg, "source": "CONNECTOR"},
                            )
                        else:  # Success
                            self.helper.api.stix_domain_object.push_entity_export(
                                entity_id=entity_id,
                                file_name=file_name,
                                file_markings=file_markings,
                                data=collector.zip_files(),
                                mime_type="application/zip",
                            )
                    else:  # Failure
                        msg = "Connector can only export Indicator type in the single export mode"
                        self.helper.connector_logger.warning(msg)
                        self.helper.api.work.report_expectation(
                            work_id=self.helper.work_id,
                            error={"error": msg, "source": "CONNECTOR"},
                        )

                # Case of a full export on a container
                elif export_type == "full":
                    # If the entity is a container
                    # We have the objectsIds resolved coming from the data load
                    # Due to usage of process_multiple_fields
                    entities_list = []
                    object_ids = entity_data.get("objectsIds")
                    self.helper.connector_logger.debug(
                        "Processing full container export",
                        {
                            "id": entity_data.get("id"),
                            "name": entity_data.get("name"),
                            "objects_count": len(object_ids or []),
                        },
                    )

                    # If doing a full export, also check & include the current entity
                    if entity_data.get("pattern_type") in collector.pattern_types:
                        entities_list.append(entity_data)

                    if object_ids is not None and len(object_ids) != 0:
                        # Filters need to cumulate the access markings + the list of inner object ids
                        selection_filter_groups = [
                            {
                                "mode": "or",
                                "filters": [
                                    {
                                        "key": "ids",
                                        "values": entity_data["objectsIds"],
                                    }
                                ],
                                "filterGroups": [],
                            }
                        ]
                        # ``access_filter`` can be None; only add it when present so the
                        # payload never contains a null filter group (which breaks the API).
                        if access_filter is not None:
                            selection_filter_groups.append(access_filter)
                        export_selection_filter = {
                            "mode": "and",
                            "filterGroups": selection_filter_groups,
                            "filters": [],
                        }
                        entities_list = self.helper.api_impersonate.opencti_stix_object_or_stix_relationship.list(
                            filters=export_selection_filter, getAll=True
                        )
                        self.helper.connector_logger.debug(
                            f"Resolved {len(entities_list)} object(s) from container ids"
                        )

                    else:
                        # Get the relations from the main entity to indicators
                        stix_indicator_relations = (
                            self.helper.api_impersonate.stix_core_relationship.list(
                                fromId=entity_id, toTypes=["Indicator"], getAll=True
                            )
                        )
                        for stix_indicator_relation in stix_indicator_relations:
                            indicator = self.helper.api_impersonate.indicator.read(
                                id=stix_indicator_relation["to"]["id"]
                            )
                            # ``read()`` can return None (concurrent deletion /
                            # access change); skip it so ``DataCollector.extract``
                            # does not crash on ``None.get(...)`` later.
                            if indicator is not None:
                                entities_list.append(indicator)
                            else:
                                self.helper.connector_logger.debug(
                                    "Skipping unreadable indicator from relationship",
                                    {
                                        "indicator_id": stix_indicator_relation["to"][
                                            "id"
                                        ]
                                    },
                                )

                        self.helper.connector_logger.debug(
                            f"Resolved {len(entities_list)} indicator(s) from relationships"
                        )

                    collector.extract(entities_list)

                    self.helper.api.stix_domain_object.push_entity_export(
                        entity_id=entity_id,
                        file_name=file_name,
                        file_markings=file_markings,
                        data=collector.zip_files(),
                        mime_type="application/zip",
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
                    'This connector currently only handles the entity types: "Indicators" with a yara, sigma, or snort pattern.'
                )
            return "Export done"

        except Exception as err:
            # Handling other unexpected exceptions. ``connector_logger.error``
            # returns None, so log first and then return a string to honour the
            # declared ``-> str`` return contract.
            self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected Error occurred", {"error_message": str(err)}
            )
            return "Export failed"

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then export the file.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)

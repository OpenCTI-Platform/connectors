from datetime import datetime, timezone
from typing import Any, Optional

from external_import_connector.formatter import OpenCTISTIXFormatter
from pycti import OpenCTIConnectorHelper
from stix2 import TAXIICollectionSource
from stix2.parsing import parse
from taxii2client.v21 import Server, as_pages

from .config_variables import ConfigConnector


class ConnectorClient:
    __helper: OpenCTIConnectorHelper
    __formatter: OpenCTISTIXFormatter
    __taxii_server: Server
    __identity: Any

    def __init__(self, helper: OpenCTIConnectorHelper, config: ConfigConnector):
        """
        Initialize the client with necessary configurations
        """
        self.__helper = helper
        self.__formatter = OpenCTISTIXFormatter(helper)

        self.__taxii_server = Server(
            config.taxii_server_url, user=config.taxii_user, password=config.taxii_pass
        )

        self.__identity = self.__helper.api.identity.create(
            type="Organization",
            name="IBM X-Force",
            description="IBM X-Force Premier Threat Intelligence Services",
            x_opencti_reliability="A - Completely reliable",
        )

    def get_collection_sources(self):
        sources: dict[str, TAXIICollectionSource] = {}

        api_root = self.__taxii_server.default or self.__taxii_server.api_roots[0]
        for collection in api_root.collections:
            if collection.can_read:
                sources[collection.id] = TAXIICollectionSource(collection)

        return sources

    def __format_object(self, obj: dict[str, Any], alias: str):
        obj["x_opencti_created_by_ref"] = self.__identity["standard_id"]
        typ = obj["type"]

        args: list[Any] = [obj]
        if typ == "report":
            args.append(alias)

        if typ in ["report", "indicator", "vulnerability"]:
            getattr(self.__formatter, f"format_{typ}")(*args)

    def __process_object(
        self, obj: dict[str, Any], alias: str, col_type: str, stix_objects: list[Any]
    ):
        record_counter = 0

        try:
            self.__format_object(obj, alias)
            stix_obj = parse(obj, allow_custom=True)
        except Exception as err:
            self.__helper.connector_logger.error(
                f"Something went wrong processing object '{obj['id']}':\n{str(err)}",
                {"error": str(err)},
            )
            raise RuntimeError("Error parsing STIX object") from err

        if stix_obj.get("type") == "report":
            record_counter += 1
            self.__helper.connector_logger.info(
                f"type = {stix_obj.get('type')}, id = {stix_obj.get('id')}, name={stix_obj.get('name')}"
            )
            for ref in stix_obj.get("object_refs"):
                self.__helper.connector_logger.info(f"        reference = {ref}")
        else:
            if col_type != "report":
                record_counter += 1

            if stix_obj.get("type") == "indicator":
                self.__helper.connector_logger.info(
                    f"        type = {stix_obj.get('type')}, id = {stix_obj.get('id')}, pattern={stix_obj.get('pattern')}"
                )
            else:
                self.__helper.connector_logger.info(
                    f"        type = {stix_obj.get('type')}, id = {stix_obj.get('id')}"
                )

        stix_objects.append(stix_obj)

        return record_counter

    def get_latest_stix_objects(
        self, source: TAXIICollectionSource, added_after: Optional[str]
    ):
        """
        If params is None, retrieve all CVEs in National Vulnerability Database
        :param params: Optional Params to filter what list to return
        :return: A list of dicts of the complete collection of CVE from NVD
        """
        try:
            collection = source.collection

            message = f"Retrieving data from collection '{collection.title}' ({collection.id})"
            if added_after:
                message += f" since {added_after}"
            self.__helper.connector_logger.info(message)

            page_counter = 0
            record_counter = 0

            for page in as_pages(
                collection.get_objects,
                per_request=50,
                added_after=added_after,
            ):
                stix_objects = []
                max_new_added_after = 0.0

                page_counter += 1
                objects = page["objects"]
                self.__helper.connector_logger.info(
                    f"Processing {len(objects)} objects from page {page_counter} for collection '{collection.title}'"
                )

                for obj in objects:
                    record_counter += self.__process_object(
                        obj,
                        collection.alias,
                        collection.custom_properties["type"],
                        stix_objects,
                    )

                    if (
                        obj["type"] == collection.custom_properties["type"]
                    ):  # only evaluate primary objects
                        record_timestamp = obj.get("modified") or obj.get("created")
                        if record_timestamp:
                            record_secs = datetime.fromisoformat(
                                record_timestamp
                            ).timestamp()
                        else:
                            record_secs = datetime.now().timestamp()

                        max_new_added_after = max(max_new_added_after, record_secs)

                new_added_after = datetime.fromtimestamp(
                    max_new_added_after or datetime.now().timestamp(), timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ")

                yield stix_objects, new_added_after
        except Exception as err:  # pylint: disable=broad-exception-caught
            self.__helper.connector_logger.error(
                f"Something went wrong retrieving data from collection '{collection.title}':\n{str(err)}",
                {"error": str(err)},
            )

        self.__helper.connector_logger.info(
            f"Finished retrieving data from collection '{collection.title}'. Total objects processed: {record_counter}"
        )

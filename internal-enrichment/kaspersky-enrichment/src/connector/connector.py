from kaspersky_client import KasperskyClient
from pycti import STIX_EXT_OCTI_SCO, OpenCTIConnectorHelper, OpenCTIStix2

from .converter_to_stix import ConverterToStix
from .settings import ConnectorSettings


class KasperskyConnector:
    """
    Specifications of the internal enrichment connector:

    This class encapsulates the main actions, expected to be run by any connector of type `INTERNAL_ENRICHMENT`.
    This type of connector aim to enrich entities (e.g. vulnerabilities, indicators, observables ...) created or modified on OpenCTI.
    It will create a STIX bundle and send it on OpenCTI.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.
    To be compatible with the "playbook automation" feature, this connector MUST always send back a STIX bundle containing the entity to enrich.

    ---

    Attributes:
        config (ConnectorSettings):
            Store the connector's configuration. It defines how to connector will behave.
        helper (OpenCTIConnectorHelper):
            Handle the connection and the requests between the connector, OpenCTI and the workers.
            _All connectors MUST use the connector helper with connector's configuration._
        converter_to_stix (ConnectorConverter):
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ

    """

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Initialize `KasperskyConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper
        self.file_sections = self.config.kaspersky.file_sections
        self.zone_octi_score_mapping = self.config.kaspersky.zone_octi_score_mapping
        api_key = self.config.kaspersky.api_key.get_secret_value()

        self.client = KasperskyClient(
            self.helper,
            base_url=self.config.kaspersky.api_base_url,
            api_key=api_key,
            params={
                "count": 1,
                "sections": self.file_sections,
                "format": "json",
            },
        )

        self.converter_to_stix = ConverterToStix(self.helper)

        # Define variables
        self.stix_objects = []

    def _process_file(self, observable: dict) -> None:
        """
        Collect intelligence from the source for a File type
        """
        self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")

        # Retrieve file hash
        obs_hash = self.resolve_file_hash(observable)

        # Get entity data from api client
        entity_data = self.client.get_file_info(obs_hash)

        # Check Quota
        self.check_quota(entity_data["LicenseInfo"])

        # Manage FileGeneralInfo data

        self.helper.connector_logger.info(
            "[CONNECTOR] Process enrichment from FileGeneralInfo data..."
        )

        entity_file_general_info = entity_data["FileGeneralInfo"]

        # Score
        if entity_data.get("Zone"):
            score = self.zone_octi_score_mapping[entity_data["Zone"].lower()]
            OpenCTIStix2.put_attribute_in_extension(
                observable, STIX_EXT_OCTI_SCO, "score", score
            )

        # Hashes
        if entity_file_general_info.get("Md5"):
            observable["hashes"]["MD5"] = entity_file_general_info["Md5"]
        if entity_file_general_info.get("Sha1"):
            observable["hashes"]["SHA-1"] = entity_file_general_info["Sha1"]
        if entity_file_general_info.get("Sha256"):
            observable["hashes"]["SHA-256"] = entity_file_general_info["Sha256"]

        # Size, mime_type
        mapping_fields = {"Size": "size", "Type": "mime_type"}
        for key, value in mapping_fields.items():
            if entity_file_general_info.get(key):
                observable[value] = entity_file_general_info[key]

        # Labels
        if entity_file_general_info.get("Categories"):
            observable["labels"] = []
            if observable.get("x_opencti_labels"):
                observable["labels"] = observable["x_opencti_labels"]
            for label in entity_file_general_info["Categories"]:
                if label not in observable["labels"]:
                    observable["labels"].append(label)

        # Manage FileNames data

        if entity_data.get("FileNames"):
            self.helper.connector_logger.info(
                "[CONNECTOR] Process enrichment from FileNames data..."
            )

            observable["additional_names"] = observable.get(
                "x_opencti_additional_names", []
            )
            for filename in entity_data["FileNames"]:
                if filename["FileName"] not in observable["additional_names"]:
                    observable["additional_names"].append(f" {filename["FileName"]}")
                else:
                    observable["additional_names"] = filename["FileName"]

        # Prepare author object
        author = self.converter_to_stix.create_author()
        self.stix_objects.append(author)

        # Manage DetectionsInfo data

        if entity_data.get("DetectionsInfo"):
            self.helper.connector_logger.info(
                "[CONNECTOR] Process enrichment from DetectionsInfo data..."
            )

            for obs_detection_info in entity_data["DetectionsInfo"]:
                obs_note = self.converter_to_stix.create_file_note(
                    observable["id"], obs_detection_info
                )
                self.stix_objects.append(obs_note)

        # Manage FileDownloadedFromUrls data

        if entity_data.get("FileDownloadedFromUrls"):
            self.helper.connector_logger.info(
                "[CONNECTOR] Process enrichment from FileDownloadedFromUrls data..."
            )

            for url_info in entity_data["FileDownloadedFromUrls"]:
                obs_url_score = self.zone_octi_score_mapping[url_info["Zone"].lower()]
                url_object = self.converter_to_stix.create_url(obs_url_score, url_info)

                if url_object:
                    self.stix_objects.append(url_object)
                    url_relation = self.converter_to_stix.create_relationship(
                        source_id=observable["id"],
                        relationship_type="related-to",
                        target_id=url_object.id,
                    )
                    self.stix_objects.append(url_relation)

        # Manage Industries data

        if entity_data.get("Industries"):
            self.helper.connector_logger.info(
                "[CONNECTOR] Process enrichment from Industries data..."
            )

            for industry in entity_data["Industries"]:
                industry_object = self.converter_to_stix.create_sector(industry)

                if industry_object:
                    self.stix_objects.append(industry_object)
                    industry_relation = self.converter_to_stix.create_relationship(
                        source_id=observable["id"],
                        relationship_type="related-to",
                        target_id=industry_object.id,
                    )
                    self.stix_objects.append(industry_relation)

    def _send_bundle(self, stix_objects: list) -> str:
        """
        Send the STIX bundle to the OpenCTI platform
        """
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)

        info_msg = (
            "Sending " + str(len(bundles_sent)) + " stix bundle(s) for worker import"
        )
        return info_msg

    def check_quota(self, entity_info: dict) -> None:
        """
        Check if quota is not exceeded.
        Raise a warning otherwise.
        """
        if entity_info["DayRequests"] >= entity_info["DayQuota"]:
            self.helper.connector_logger.warning(
                "[CONNECTOR] The daily quota has been exceeded",
                {
                    "day_requests": entity_info["DayRequests"],
                    "day_quota": entity_info["DayQuota"],
                },
            )

    def entity_in_scope(self, obs_type: str) -> bool:
        """
        Security to limit playbook triggers to something other than the initial scope
        :param data: Dictionary of data
        :return: boolean
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_split = obs_type.split("--")
        entity_type = entity_split[0].lower()

        if entity_type in scopes:
            return True
        else:
            return False

    def resolve_file_hash(self, observable: dict) -> str:
        if "hashes" in observable and "SHA-256" in observable["hashes"]:
            return observable["hashes"]["SHA-256"]
        if "hashes" in observable and "SHA-1" in observable["hashes"]:
            return observable["hashes"]["SHA-1"]
        if "hashes" in observable and "MD5" in observable["hashes"]:
            return observable["hashes"]["MD5"]
        raise ValueError(
            "Unable to enrich the observable, the observable does not have an SHA256, SHA1, or MD5"
        )

    def process_message(self, data: dict) -> str:
        """
        Get the observable created/modified in OpenCTI and check which type to send for process
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param data: dict of data to process
        :return: string
        """
        try:
            opencti_entity = data["enrichment_entity"]

            # Extract information from entity data
            self.stix_objects = data["stix_objects"]
            observable = data["stix_entity"]
            obs_type = opencti_entity["entity_type"]

            info_msg = (
                "[CONNECTOR] Processing observable for the following entity type: "
            )
            self.helper.connector_logger.info(info_msg, {"type": {obs_type}})

            if self.entity_in_scope(obs_type):
                # Performing the collection of intelligence and enrich the entity
                match obs_type:
                    case "StixFile":
                        self._process_file(observable)
                    # case "IPv4-Addr":
                    #     self._process_ip(observable)
                    # case "Domain-Name" | "Hostname":
                    #     self._process_domain(observable)
                    # case "Url":
                    #     self._process_url(observable)
                    case _:
                        raise ValueError(
                            "Entity type is not supported",
                            {"entity_type": obs_type},
                        )

                if self.stix_objects is not None and len(self.stix_objects):
                    return self._send_bundle(self.stix_objects)
                else:
                    info_msg = "[CONNECTOR] No information found"
                    return info_msg

            else:
                if not data.get("event_type"):
                    # If it is not in scope AND entity bundle passed through playbook,
                    # we should return the original bundle unchanged
                    self._send_bundle(self.stix_objects)
                else:
                    raise ValueError(
                        f"Failed to process observable, {opencti_entity['entity_type']} is not a supported entity type."
                    )
        except Exception as err:
            # Handling other unexpected exceptions
            msg = f"[Kaspersky Enrichment] Unexpected Error occurred: {err}"
            raise Exception(msg)

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then enrich the information.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)

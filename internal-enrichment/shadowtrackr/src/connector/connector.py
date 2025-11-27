from datetime import datetime, timedelta

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import STIX_EXT_OCTI_SCO, OpenCTIConnectorHelper, OpenCTIStix2
from shadowtrackr_client import ShadowTrackrClient


class ShadowTrackrConnector:
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
        client (TemplateClient):
            Provide methods to request the external API.
        converter_to_stix (ConnectorConverter):
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ

    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `ShadowTrackrConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper

        self.client = ShadowTrackrClient(
            self.helper,
            base_url=self.config.shadowtrackr.base_url,
            api_key=self.config.shadowtrackr.api_key,
        )
        self.converter_to_stix = ConverterToStix(
            self.helper,
        )

        # Define variables
        self.max_tlp_level = self.config.shadowtrackr.max_tlp_level
        self.replace_with_lower_score = (
            self.config.shadowtrackr.replace_with_lower_score
        )
        self.replace_valid_to_date = self.config.shadowtrackr.replace_valid_to_date
        self.stix_objects_list = []

        self._create_tags()

    def _create_tags(self) -> None:
        """Create tags for the connector in OpenCTI for later use"""
        label_bogon = self.helper.api.label.read_or_create_unchecked(
            value="Bogon", color="#145578"
        )
        if label_bogon is None:
            raise ValueError(
                "The 'Bogon' label could not be created. If your connector does not have the permission to create labels, "
                "please create it manually before launching"
            )

        label_cloud = self.helper.api.label.read_or_create_unchecked(
            value="cloud", color="#145578"
        )
        if label_cloud is None:
            raise ValueError(
                "The 'cloud' label could not be created. If your connector does not have the permission to create labels, "
                "please create it manually before launching."
            )

        label_cdn = self.helper.api.label.read_or_create_unchecked(
            value="cdn", color="#145578"
        )
        if label_cdn is None:
            raise ValueError(
                "The 'cdn' label could not be created. If your connector does not have the permission to create labels, "
                "please create it manually before launching"
            )

        label_vpn = self.helper.api.label.read_or_create_unchecked(
            value="vpn", color="#145578"
        )
        if label_vpn is None:
            raise ValueError(
                "The 'vpn' label could not be created. If your connector does not have the permission to create labels, "
                "please create it manually before launching"
            )

        label_tor = self.helper.api.label.read_or_create_unchecked(
            value="tor", color="#145578"
        )
        if label_tor is None:
            raise ValueError(
                "The 'tor' label could not be created. If your connector does not have the permission to create labels, "
                "please create it manually before launching"
            )

        label_public_dns_server = self.helper.api.label.read_or_create_unchecked(
            value="public_dns_server", color="#145578"
        )
        if label_public_dns_server is None:
            raise ValueError(
                "The 'public_dns_server' label could not be created. If your connector does not have the permission to "
                "create labels, please create it manually before launching"
            )

    def entity_in_scope(self, data: dict) -> bool:
        """
        Security to limit playbook triggers to something other than the initial scope
        :param data: Dictionary of data
        :return: boolean
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_split = data["entity_id"].split("--")
        entity_type = entity_split[0].lower()

        if entity_type in scopes:
            return True
        else:
            return False

    def extract_and_check_markings(self, opencti_entity: dict) -> None:
        """
        Extract TLP, and we check if the variable "max_tlp" is less than
        or equal to the markings access of the entity from OpenCTI
        If this is true, we can send the data to connector for enrichment.
        :param opencti_entity: Dict of observable from OpenCTI
        :return: Boolean
        """
        if len(opencti_entity["objectMarking"]) != 0:
            for marking_definition in opencti_entity["objectMarking"]:
                if marking_definition["definition_type"] == "TLP":
                    tlp = marking_definition["definition"]

        valid_max_tlp = self.helper.check_max_tlp(tlp, self.max_tlp_level)

        if not valid_max_tlp:
            raise ValueError(
                "[CONNECTOR] Do not send any data, TLP of the observable is greater than MAX TLP,"
                "the connector does not has access to this observable, please check the group of the connector user"
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
            self.extract_and_check_markings(opencti_entity)

            # To enrich the data, you can add more STIX object in stix_objects
            self.stix_objects_list = data["stix_objects"]
            observable = data["stix_entity"]

            # Extract information from entity data
            obs_type = observable["type"]

            info_msg = (
                "[CONNECTOR] Processing observable for the following entity type: "
            )
            self.helper.connector_logger.info(info_msg, {"type": {obs_type}})

            if self.entity_in_scope(data):
                # Performing the collection of intelligence and enrich the entity
                # ===========================
                # === Add your code below ===
                # ===========================

                # EXAMPLE Collect intelligence and enrich current STIX object
                entity_type = opencti_entity["entity_type"]
                is_indicator = False
                match entity_type:
                    case "Indicator":
                        pattern = opencti_entity["pattern"]
                        if "ipv4-addr" not in pattern and "ipv6-addr" not in pattern:
                            raise ValueError(
                                f"No ip address in indicator, skipping {pattern} {entity_type}"
                            )

                        ip = pattern.split("'")[1]
                        is_indicator = True
                    case "IPv4-Addr" | "IPv6-Addr":
                        ip = opencti_entity["observable_value"]
                    case _:
                        raise ValueError(
                            "Entity type is not supported",
                        )

                if is_indicator:
                    description = opencti_entity["description"]
                else:
                    description = opencti_entity["x_opencti_description"]

                if description is not None and "[ShadowTrackr] " in description:
                    return (
                        "This ip is already processed by the ShadowTrackr connector. We're not doing it again, "
                        "that might mess up the score."
                    )

                if not self.converter_to_stix._is_ip(ip):
                    raise ValueError(f"Invalid ip address: {ip}")

                old_score = opencti_entity["x_opencti_score"]
                score, date_shortened = self._process_ip(
                    ip, is_indicator, observable, opencti_entity
                )

                self._send_bundle(self.stix_objects_list)
                msg = f"Found data on {ip}."
                if old_score == score:
                    msg += " Score not changed"
                    if date_shortened:
                        msg += ", but valid_until shortened to 1 day."
                    else:
                        msg += "."
                else:
                    msg += f" Score changed from {old_score} to {score}"
                    if date_shortened:
                        msg += ", valid_until shortened to 1 day."
                    else:
                        msg += "."

                return msg

                # ===========================
                # === Add your code above ===
                # ===========================
            else:
                if not data.get("event_type"):
                    # If it is not in scope AND entity bundle passed through playbook, we should return the original bundle unchanged
                    self._send_bundle(self.stix_objects_list)
                else:
                    # self.helper.connector_logger.info(
                    #     "[CONNECTOR] Skip the following entity as it does not concern "
                    #     "the initial scope found in the config connector: ",
                    #     {"entity_id": opencti_entity["entity_id"]},
                    # )
                    raise ValueError(
                        f"Failed to process observable, {opencti_entity['entity_type']} is not a supported entity type."
                    )
        except Exception as err:
            # Handling other unexpected exceptions
            return self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected Error occurred", {"error_message": str(err)}
            )

    def _process_ip(
        self, ip: str, is_indicator: bool, observable: dict, opencti_entity: dict
    ) -> tuple[int, bool]:
        score = opencti_entity["x_opencti_score"]
        labels = [label["value"] for label in opencti_entity["objectLabel"]]

        if is_indicator:
            description = opencti_entity["description"]
        else:
            description = opencti_entity["x_opencti_description"]

        data = self.client.get_ip_info(ip, labels)
        if error := data.get("error"):
            raise ValueError(f"Error: [ShadowTrackr] {error}")

        score_lowered = False
        if self.replace_with_lower_score:
            false_positive_estimate = data["false_positive_estimate"]

            score_steps = [
                (99, 60),
                (89, 40),
                (69, 20),
                (50, 10),
            ]
            for threshold, decrement in score_steps:
                if false_positive_estimate > threshold:
                    score -= decrement
                    score_lowered = True
                    break

            # set a lower boundary
            if score < 10:
                score = 10

            # Update score
            OpenCTIStix2.put_attribute_in_extension(
                observable, STIX_EXT_OCTI_SCO, "score", score
            )

        # Observables don't have a valid until field, but indicators do
        date_shortened = False
        if is_indicator and (data["vpn"] or data["cdn"] or data["cloud"]):
            valid_from = datetime.fromisoformat(opencti_entity["valid_from"].strip("Z"))
            valid_until = (valid_from + timedelta(days=1)).isoformat(
                timespec="milliseconds"
            ) + "Z"
            OpenCTIStix2.put_attribute_in_extension(
                observable, STIX_EXT_OCTI_SCO, "valid_until", valid_until, True
            )
            date_shortened = True

        stix_labels = observable["labels"]
        for label in ["vpn", "cdn", "cloud", "bogon", "tor", "public_dns"]:
            if data[label]:
                if is_indicator:
                    stix_labels.append(label)
                else:
                    OpenCTIStix2.put_attribute_in_extension(
                        observable, STIX_EXT_OCTI_SCO, "labels", label, True
                    )

        text = ""
        if data["cdn"]:
            if data["cdn_provider"]:
                text = f"This is an ip address in the {data['cdn_provider']} CDN."
            else:
                text = "This is an ip address in a CDN."

            text += (
                " CDN ip addresses change regularly, and are not very useful to track."
            )
            if score_lowered:
                if date_shortened:
                    text += " The score is adjusted downwards, and the valid until date set to 1 day."
                else:
                    text += " The score is adjusted downwards."

        elif data["cloud"]:
            if data["cloud_provider"]:
                text = f" This is an ip address in the {data['cloud_provider']} cloud."
            else:
                text = " This is an ip address in a cloud."

            text += " Cloud ip addresses change regularly, and are not very useful to track."
            if score_lowered:
                if date_shortened:
                    text += " The score is adjusted downwards, and the valid until date set to 1 day."
                else:
                    text += " The score is adjusted downwards."

        elif data["vpn"]:
            text = (
                "This ip address is a VPN. "
                "VPN ip addresses change regularly, and are not very useful to track."
            )
            if score_lowered:
                if date_shortened:
                    text += " The score is adjusted downwards, and the valid until date set to 1 day."
                else:
                    text += " The score is adjusted downwards."

        elif data["public_dns"]:
            text = (
                "This ip address is a public DNS server. "
                "Public DNS servers are often used in malware to check for an internet connection, "
                "and automated analysis tools regularly extract them as indicators. This is not very useful."
            )
            if self.replace_with_lower_score:
                text += " The score is adjusted downwards."

        if text:
            description += f"\n[ShadowTrackr] {text}"
            if is_indicator:
                observable["description"] = description
            else:
                OpenCTIStix2.put_attribute_in_extension(
                    observable,
                    STIX_EXT_OCTI_SCO,
                    "description",
                    description,
                    False,
                )

        return score, date_shortened

    def _send_bundle(self, stix_objects: list) -> str:
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)

        info_msg = (
            "Sending " + str(len(bundles_sent)) + " stix bundle(s) for worker import"
        )
        return info_msg

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then enrich the information.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)

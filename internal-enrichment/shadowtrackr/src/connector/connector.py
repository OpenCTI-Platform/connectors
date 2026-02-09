"""ShadowTrackr Connector"""

from datetime import datetime, timedelta

from connector.const import SCORE_STEPS
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import STIX_EXT_OCTI_SCO, OpenCTIConnectorHelper, OpenCTIStix2
from shadowtrackr_client import ShadowTrackrClient


class ShadowTrackrConnector:
    """
    This connector enriches IP addresses with information from the ShadowTrackr API.
    It also lowers the score for IP addresses that are false positives,
    and changes the valid until date for sources that are known to change function
    regularly, like CDNs, Clouds and VPNs.
    This connector works for the following OpenCTI observable types:
    * IPv4-Addr
    * IPv6-Addr
    * Indicator

    Attributes:
        config (ConnectorSettings):
            Store the connector's configuration. It defines how to connector will behave.
        helper (OpenCTIConnectorHelper):
            Handle the connection and the requests between the connector, OpenCTI and the workers.
            _All connectors MUST use the connector helper with connector's configuration._
        client (ShadowTrackrClient):
            Provide methods to request the external API.
        converter_to_stix (ConverterToStix):
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
            api_key=self.config.shadowtrackr.api_key.get_secret_value(),
        )
        self.converter_to_stix = ConverterToStix(
            self.helper,
        )

        # Define variables
        self.max_tlp = self.config.shadowtrackr.max_tlp
        self.replace_with_lower_score = (
            self.config.shadowtrackr.replace_with_lower_score
        )
        self.replace_valid_to_date = self.config.shadowtrackr.replace_valid_to_date
        self.stix_objects_list = []

        self._create_tags()

    def _create_tags(self) -> None:
        """Create tags for the connector in OpenCTI for later use"""
        for label_name in ["Bogon", "cloud", "cdn", "vpn", "tor", "public_dns"]:
            label = self.helper.api.label.read_or_create_unchecked(
                value=label_name, color="#145578"
            )
            if label is None:
                msg = (
                    f"The '{label_name}' label could not be created. If your connector does not have the permission to create labels, "
                    "please create it manually before launching"
                )
                raise ValueError(msg)

    def entity_in_scope(self, data: dict) -> bool:
        """
        Security to limit playbook triggers to something other than the initial scope
        :param data: Dictionary of data
        :return: boolean
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_split = data["entity_id"].split("--")
        entity_type = entity_split[0].lower()

        return entity_type in scopes

    def extract_and_check_markings(self, opencti_entity: dict) -> None:
        """
        Extract TLP, and we check if the variable "max_tlp" is less than
        or equal to the markings access of the entity from OpenCTI
        If this is true, we can send the data to connector for enrichment.
        :param opencti_entity: Dict of observable from OpenCTI
        :return: Boolean
        """
        tlp = None
        if len(opencti_entity["objectMarking"]) != 0:
            for marking_definition in opencti_entity["objectMarking"]:
                if marking_definition["definition_type"] == "TLP":
                    tlp = marking_definition["definition"]

        valid_max_tlp = self.helper.check_max_tlp(tlp, self.max_tlp)

        if not valid_max_tlp:
            msg = (
                f"[ShadowTrackr] Do not send any data, TLP of the observable '{tlp}' is greater than MAX TLP '{self.max_tlp}',"
                "the connector does not has access to this observable, please check the group of the connector user"
            )
            raise ValueError(msg)

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
                "[ShadowTrackr] Processing observable for the following entity type: "
            )
            self.helper.connector_logger.info(info_msg, {"type": {obs_type}})

            if self.entity_in_scope(data):
                # Performing the collection of intelligence and enrich the entity
                entity_type = opencti_entity["entity_type"]
                is_indicator = False
                match entity_type:
                    case "Indicator":
                        pattern = opencti_entity["pattern"]
                        if "ipv4-addr" not in pattern and "ipv6-addr" not in pattern:
                            msg = f"No ip address in indicator, skipping {pattern} {entity_type}"
                            raise ValueError(msg)

                        ip = pattern.split("'")[1]
                        is_indicator = True

                    case "IPv4-Addr" | "IPv6-Addr":
                        ip = opencti_entity["observable_value"]

                    case _:
                        msg = "Entity type is not supported"
                        raise ValueError(msg)

                if is_indicator:
                    description = opencti_entity["description"]
                else:
                    description = opencti_entity["x_opencti_description"]

                if description is not None and "[ShadowTrackr] " in description:
                    return (
                        "This ip is already processed by the ShadowTrackr connector. "
                        "We recommend not doing it again, that might mess up the score."
                    )

                if not self.converter_to_stix._is_ip(ip):
                    msg = f"Invalid ip address: {ip}"
                    raise ValueError(msg)

                old_score = opencti_entity["x_opencti_score"]
                score, date_shortened = self._process_ip(
                    ip, is_indicator, observable, opencti_entity
                )

                self._send_bundle(self.stix_objects_list)
                msg = f"Found data on {ip}."
                if old_score == score:
                    msg += " Score not changed"
                else:
                    msg += f" Score changed from {old_score} to {score}"

                if date_shortened:
                    msg += ", valid_until shortened to 1 day."
                else:
                    msg += "."

                return msg

            # Entity is out of scope
            if not data.get("event_type"):
                # If it is not in scope AND entity bundle passed through playbook, we should return the original bundle unchanged
                self._send_bundle(self.stix_objects_list)
            else:
                self.helper.connector_logger.info(
                    "[ShadowTrackr] Skip the following entity as it does not concern "
                    "the initial scope found in the config connector: ",
                    {"entity_id": opencti_entity["entity_id"]},
                )

                msg = f"Failed to process observable, {opencti_entity['entity_type']} is not a supported entity type."

                raise ValueError(msg)
        except Exception as err:
            # Handling other unexpected exceptions
            msg = "[ShadowTrackr] Unexpected Error occurred", {"error": str(err)}
            raise Exception(msg) from err

    def _process_ip(
        self, ip: str, is_indicator: bool, observable: dict, opencti_entity: dict
    ) -> tuple[int, bool]:
        """
        Process the IP address
        :param ip: String of IP address
        :param is_indicator: Boolean of whether the entity is an indicator
        :param observable: Dictionary of observable
        :param opencti_entity: Dictionary of opencti entity

        :return: Tuple of integer and boolean representing the score and whether the date was shortened
        """
        score = opencti_entity["x_opencti_score"]
        labels = [label["value"] for label in opencti_entity["objectLabel"]]

        if is_indicator:
            description = opencti_entity["description"]
        else:
            description = opencti_entity["x_opencti_description"]

        ip_info = self.client.get_ip_info(ip, labels or None)
        if error := ip_info.get("error"):
            raise ValueError(f"Error: [ShadowTrackr] {error}")

        score_lowered, score = self._process_score(
            observable, ip_info["false_positive_estimate"], score
        )

        # Observables don't have a valid until field, but indicators do
        date_shortened = False
        if is_indicator and (ip_info["vpn"] or ip_info["cdn"] or ip_info["cloud"]):
            valid_from = datetime.fromisoformat(opencti_entity["valid_from"].strip("Z"))
            valid_until = (valid_from + timedelta(days=1)).isoformat(
                timespec="milliseconds"
            ) + "Z"
            OpenCTIStix2.put_attribute_in_extension(
                observable, STIX_EXT_OCTI_SCO, "valid_until", valid_until, True
            )
            date_shortened = True

        for label in ["vpn", "cdn", "cloud", "bogon", "tor", "public_dns"]:
            if ip_info[label]:
                if is_indicator:
                    observable["labels"].append(label)
                else:
                    OpenCTIStix2.put_attribute_in_extension(
                        observable, STIX_EXT_OCTI_SCO, "labels", label, True
                    )

        text = self._get_ip_info_msg(ip_info, score_lowered, date_shortened)
        if text:
            description = f"{description or ''}\n[ShadowTrackr] {text}"
            if is_indicator:
                observable["description"] = description
            else:
                OpenCTIStix2.put_attribute_in_extension(
                    observable, STIX_EXT_OCTI_SCO, "description", description, False
                )

        # Prepare author object
        self.stix_objects_list.append(self.converter_to_stix.author)

        return score, date_shortened

    def _process_score(
        self, observable: dict, false_positive_estimate: int, score: int | None
    ) -> tuple[bool, int]:
        """
        Process the score based on the false positive estimate
        :param observable: Dictionary of observable
        :param false_positive_estimate: Integer of false positive estimate
        :param score: Integer of score
        :return: Tuple of boolean and integer
        """
        if score is None or not self.replace_with_lower_score:
            return False, score

        score_lowered = False
        for threshold, decrement in SCORE_STEPS:
            if false_positive_estimate > threshold:
                score -= decrement
                score_lowered = True
                break

        # set a lower boundary
        score = max(score, 10)

        # Update score
        OpenCTIStix2.put_attribute_in_extension(
            observable, STIX_EXT_OCTI_SCO, "score", score
        )

        return score_lowered, score

    def _get_ip_info_msg(
        self, ip_info: dict, score_lowered: bool, date_shortened: bool
    ) -> str:
        """
        Get the message for the ip info
        :param ip_info: Dictionary of ip info
        :return: string
        """

        def _set_score_suffix(score_lowered: bool, date_shortened: bool) -> str:
            """
            Set the score suffix
            :param score_lowered: Boolean of whether the score was lowered
            :param date_shortened: Boolean of whether the date was shortened
            :return: String of the score suffix
            """
            if score_lowered:
                if date_shortened:
                    return " The score is adjusted downwards, and the valid until date set to 1 day."
                else:
                    return " The score is adjusted downwards."
            else:
                return ""

        if ip_info["cdn"]:
            if cdn_provider := ip_info["cdn_provider"]:
                text = f"This is an ip address in the {cdn_provider} CDN."
            else:
                text = "This is an ip address in a CDN."

            text += (
                " CDN ip addresses change regularly, and are not very useful to track."
            )
            text += _set_score_suffix(score_lowered, date_shortened)

            return text

        if ip_info["cloud"]:
            if cloud_provider := ip_info["cloud_provider"]:
                text = f" This is an ip address in the {cloud_provider} cloud."
            else:
                text = " This is an ip address in a cloud."

            text += " Cloud ip addresses change regularly, and are not very useful to track."
            text += _set_score_suffix(score_lowered, date_shortened)

            return text

        if ip_info["vpn"]:
            text = (
                "This ip address is a VPN. "
                "VPN ip addresses change regularly, and are not very useful to track."
            )
            text += _set_score_suffix(score_lowered, date_shortened)

            return text

        if ip_info["public_dns"]:
            text = (
                "This ip address is a public DNS server. "
                "Public DNS servers are often used in malware to check for an internet connection, "
                "and automated analysis tools regularly extract them as indicators. This is not very useful."
            )
            if self.replace_with_lower_score:
                text += " The score is adjusted downwards."

            return text

        return ""

    def _send_bundle(self, stix_objects: list) -> str:
        """
        Send the bundle to OpenCTI for worker import

        :param stix_objects: List of stix objects to send
        :return: string with the number of bundles sent
        """
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)

        info_msg = f"Sending {len(bundles_sent)} stix bundle(s) for worker import"
        return info_msg

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then enrich the information.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)

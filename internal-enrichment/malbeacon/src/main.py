import ipaddress
from datetime import datetime


import stix2
import validators
from pycti import (
    Identity,
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)
from models.c2_model import C2Beacon
from stix2 import Bundle
from malbeacon_config_variables import ConfigMalbeacon
from malbeacon_client import MalbeaconClient

C2_PATH = "c2/c2/"
SOURCE_URL = "https://portal.malbeacon.com/illuminate"

STIX_OBS_MAP = {
    "domain-name:value": "Domain-Name",
    "ipv4-addr:value": "IPv4-Addr",
    "ipv6-addr:value": "IPv6-Addr",
}


class MalBeaconConnector:
    """
    Malbeacon connector class
    """

    def __init__(self):
        """
        Initialize the Malbeacon Connector with necessary configurations
        """
        self.config = ConfigMalbeacon()
        self.helper = OpenCTIConnectorHelper(self.config.load, True)
        self.client = MalbeaconClient(self.helper)

        # Define variables
        self.author = None
        self.tlp = None
        self.stix_object_list = []

    @staticmethod
    def _create_author() -> dict:
        """
        Create Malbeacon Author
        :return: Author in Stix2 object
        """
        return stix2.Identity(
            id=Identity.generate_id("Malbeacon", "organization"),
            name="Malbeacon",
            identity_class="organization",
            description="""The first system of its kind, MalBeacon implants \
                    beacons via malware bot check-in traffic. Adversaries conducting \
                    campaigns in the wild who are logging in to these malware C2 \
                    panels can now be tracked. MalBeacon is a tool for the good guys \
                    that provides additional intelligence on attack attribution.""",
        )

    @staticmethod
    def _create_external_reference() -> list:
        """
        Create external reference
        :return: External reference STIX2 list
        """
        external_reference = stix2.ExternalReference(
            source_name="Malbeacon C2 Domains",
            url=SOURCE_URL,
            description="Found in Malbeacon C2 Domains",
        )
        return [external_reference]

    @staticmethod
    def _to_stix_bundle(stix_objects: list) -> Bundle:
        """
        Create a bundle of STIX objects
        :param stix_objects: List of STIX objects
        :return:STIX objects as a Bundle
        """
        return stix2.Bundle(objects=stix_objects, allow_custom=True)

    @staticmethod
    def _to_json_bundle(stix_bundle: Bundle) -> str:
        """
        Convert bundle into JSON format
        :param stix_bundle: Bundle of STIX object
        :return: STIX bundle as JSON format
        """
        return stix_bundle.serialize()

    def send_stix_bundle(self, stix_bundle_json: str) -> None:
        """
        Send stix bundle to OpenCTI
        :param stix_bundle_json:
        :return: None
        """
        self.helper.send_stix2_bundle(stix_bundle_json)
        pass

    def extract_and_check_markings(self, opencti_entity: dict) -> bool:
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
                    self.tlp = marking_definition["definition"]

        is_valid_max_tlp = OpenCTIConnectorHelper.check_max_tlp(self.tlp, self.config.max_tlp)

        return is_valid_max_tlp

    def _process_observable(self, observable: dict) -> str:
        """
        Get the observable created in OpenCTI and check which type
        Send for process c2
        :param observable: dict of observable properties
        :return: Info message in string
        """

        is_valid_tlp = self.extract_and_check_markings(observable)
        if not is_valid_tlp:
            raise ValueError(
                "[CONNECTOR] Do not send any data, TLP of the observable is greater than MAX TLP,"
                "the connector does not has access to this observable, please check the group of the connector user"
            )

        # Extract IPv4, IPv6, and Domain from entity data
        obs_standard_id = observable["standard_id"]
        obs_value = observable["observable_value"]
        obs_type = observable["entity_type"]

        info_msg = "[CONNECTOR] Processing observable for the following entity type: "
        self.helper.connector_logger.info(info_msg, {"type": {obs_type}})

        # TODO: add "Email-Address" in scope

        if obs_type in self.config.connector_scope:
            stix_objects = self.process_c2(obs_value, obs_standard_id, obs_type)

            if stix_objects is not None and len(stix_objects) is not None:
                stix_objects_bundle = self._to_stix_bundle(stix_objects)
                stix_objects_to_json = self._to_json_bundle(stix_objects_bundle)

                self.send_stix_bundle(stix_objects_to_json)

                info_msg = (
                    "[API] Observable value found on Malbeacon API and knowledge added for type: "
                    + obs_type
                    + ", sending "
                    + str(len(stix_objects))
                    + " objects"
                )
                return info_msg
            else:
                info_msg = "[API] No information found on Malbeacon"
                return info_msg

    def _process_message(self, data: dict) -> str:
        """
        Get observable newly created from OpenCTI and process enrichment
        :param data: Dictionary of data
        :return: A string from process observable
        """
        entity_id = data["entity_id"]

        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)

        if observable is not None:
            return self._process_observable(observable)

    def start(self) -> None:
        """
        Start main execution loop procedure for Malbeacon connector
        """
        self.helper.listen(self._process_message)

    """
    Handle Observables
    """

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv6
        :param value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv4
        :param value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.IPv4Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_domain(value: str) -> bool:
        """
        Valid domain name regex including internationalized domain name
        :param value: Value in string
        :return: A boolean
        """
        is_valid_domain = validators.domain(value)

        if is_valid_domain:
            return True
        else:
            return False

    def _create_obs(self, value: str, obs_id: str = None) -> dict:
        """
        Create observable according to value given
        :param value: Value in string
        :param obs_id: Value of observable ID in string
        :return: Stix object for IPV4, IPV6 or Domain
        """
        if self._is_ipv6(value) is True:
            return stix2.IPv6Address(
                id=obs_id if obs_id is not None else None,
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_external_references": self._create_external_reference(),
                    "x_opencti_score": self.config.indicator_score_level,
                },
            )
        elif self._is_ipv4(value) is True:
            return stix2.IPv4Address(
                id=obs_id if obs_id is not None else None,
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_external_references": self._create_external_reference(),
                    "x_opencti_score": self.config.indicator_score_level,
                },
            )
        elif self._is_domain(value) is True:
            return stix2.DomainName(
                id=obs_id if obs_id is not None else None,
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_external_references": self._create_external_reference(),
                    "x_opencti_score": self.config.indicator_score_level,
                },
            )
        else:
            raise ValueError(
                f"This observable value '{value}' is not a valid IPv4 or IPv6 address nor DomainName."
            )

    """
    Handle Indicator
    """

    def create_indicator_pattern(self, value: str) -> str:
        """
        Create indicator pattern
        :param value: Value in string
        :return: String of the pattern
        """
        if self._is_ipv6(value) is True:
            return f"[ipv6-addr:value = '{value}']"
        elif self._is_ipv4(value) is True:
            return f"[ipv4-addr:value = '{value}']"
        elif self._is_domain(value) is True:
            return f"[domain-name:value = '{value}']"
        else:
            raise ValueError(
                f"This pattern value {value} is not a valid IPv4 or IPv6 address nor Domain name"
            )

    def main_observable_type(self, value: str) -> str:
        """
        Find the observable type according to value
        :param value: Value in string
        :return: Observable type in string
        """
        pattern = self.create_indicator_pattern(value)
        pattern_split = pattern.split("=")
        observable_type = pattern_split[0].strip("[").strip()

        if observable_type in STIX_OBS_MAP:
            return STIX_OBS_MAP[observable_type]
        else:
            return "Unknown"

    def _create_indicator(
        self, obs_type: str, value: str, description: str = None
    ) -> dict:
        """
        Creates and returns STIX2 indicator object
        :param obs_type: Type in string
        :param value: Value in string
        :param description: Description in string
        :return: Indicator STIX object
        """
        return stix2.Indicator(
            id=Indicator.generate_id(self.create_indicator_pattern(value)),
            name=value,
            description=description,
            pattern_type="stix",
            valid_from=datetime.now(),
            pattern=self.create_indicator_pattern(value),
            created_by_ref=self.author["id"],
            external_references=self._create_external_reference(),
            custom_properties={
                "x_opencti_score": self.config.indicator_score_level,
                "x_opencti_main_observable_type": obs_type,
            },
        )

    """
    Handle relationships
    """

    def _create_relationship(
        self, source_id: str, relationship_type: str, target_id: str
    ) -> dict:
        """
        Creates Relationship object linking indicator and observable
        :param source_id: ID of source in string
        :param relationship_type: Relationship type in string
        :param target_id: ID of target in string
        :return: Relationship STIX2 object
        """
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author["id"],
            external_references=self._create_external_reference(),
        )

    """
    ==============================================================
    Main C2 process
    Convert Malbeacon data imported into STIX2 standard object
    ==============================================================
    """

    def process_c2(
        self, obs_value: str, obs_standard_id: str, obs_type: str
    ) -> list | None:
        """
        Process C2 if data found in Malbeacon
        :param obs_value: Observable value in string
        :param obs_standard_id: Standard observable id in string
        :param obs_type: Observable type in string
        :return: STIX2 object in dict
        """
        try:
            already_processed = []

            data = self.client.request_data(self.config.api_base_url + C2_PATH + obs_value)

            """
            =========================================================
            If the API returns a JSON document with a message,
            there probably has been an error or no information
            could be retrieved from the Malbeacon database
            =========================================================
            """
            if data is None or "message" in data:
                error_msg = "No data found for this following observable: "
                self.helper.connector_logger.info(
                    error_msg, {"observable_value": obs_value}
                )

            else:
                """
                ========================================================================
                Complete observable added
                Add author, external references and indicator based on this observable
                ========================================================================
                """
                self.author = self._create_author()
                stix_external_ref_on_base_obs = self._create_obs(
                    obs_value, obs_standard_id
                )
                stix_indicator_based_on_obs = self._create_indicator(
                    obs_type, obs_value
                )
                base_stix_relationship = self._create_relationship(
                    stix_indicator_based_on_obs["id"],
                    "based-on",
                    stix_external_ref_on_base_obs["id"],
                )

                self.stix_object_list.extend(
                    [
                        self.author,
                        stix_external_ref_on_base_obs,
                        stix_indicator_based_on_obs,
                        base_stix_relationship,
                    ]
                )

                """
                =================================================================================
                Main C2 process, convert Malbeacon observables related to the base observable
                into STIX2 standard object, create indicator based on them and add relationships
                =================================================================================
                """
                for entry in data:
                    # Parse object from C2Beacon Models
                    c2_beacon = C2Beacon.parse_obj(entry)

                    info_msg = "Processing C2 from Malbeacon for: "
                    self.helper.connector_logger.info(
                        info_msg,
                        {
                            "date": {c2_beacon.cti_date},
                            "actor_ip": {c2_beacon.actorip},
                            "actor_hostname": {c2_beacon.actorhostname},
                        },
                    )

                    """
                    ======================================================
                    Process knowledge about the actors infrastructure
                    ======================================================
                    """

                    if (
                        c2_beacon.actorip != "NA"
                        and c2_beacon.actorip not in already_processed
                    ):
                        c2_value = c2_beacon.actorip
                        c2_type = self.main_observable_type(c2_value)
                        c2_description = (
                            "Malbeacon Actor IP Address for C2 " + obs_value
                        )

                        c2_stix_observable = self._create_obs(c2_value)
                        c2_stix_indicator = self._create_indicator(
                            c2_type, c2_value, c2_description
                        )
                        c2_stix_relationship = self._create_relationship(
                            c2_stix_indicator["id"],
                            "based-on",
                            c2_stix_observable["id"],
                        )
                        base_relationship = self._create_relationship(
                            obs_standard_id, "related-to", c2_stix_observable["id"]
                        )

                        self.stix_object_list.extend(
                            [
                                c2_stix_observable,
                                c2_stix_indicator,
                                c2_stix_relationship,
                                base_relationship,
                            ]
                        )

                        if c2_beacon.actorhostname != "NA":
                            c2_value = c2_beacon.actorhostname
                            c2_type = self.main_observable_type(c2_value)
                            c2_description = (
                                "Malbeacon Actor DomainName for C2 " + obs_value
                            )

                            c2_stix_observable = self._create_obs(c2_value)
                            c2_stix_indicator = self._create_indicator(
                                c2_type, c2_value, c2_description
                            )
                            c2_stix_relationship = self._create_relationship(
                                c2_stix_indicator["id"],
                                "based-on",
                                c2_stix_observable["id"],
                            )
                            base_relationship = self._create_relationship(
                                obs_standard_id, "related-to", c2_stix_observable["id"]
                            )

                            self.stix_object_list.extend(
                                [
                                    c2_stix_observable,
                                    c2_stix_indicator,
                                    c2_stix_relationship,
                                    base_relationship,
                                ]
                            )

                        # Make sure we only process this specific IP once
                        already_processed.append(c2_beacon.actorip)

                return self.stix_object_list

        except Exception as err:
            error_msg = "[CONNECTOR] Error while processing C2 beacons: "
            self.helper.connector_logger.error(error_msg, {"error": {str(err)}})
            return None


if __name__ == "__main__":
    MalBeaconInstance = MalBeaconConnector()
    MalBeaconInstance.start()

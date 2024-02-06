import logging
import os
from typing import Optional

import re
import validators
import ipaddress
import requests
import yaml
from datetime import datetime
from dateutil import parser
from stix2 import Bundle, ExternalReference

from pycti import OpenCTIConnectorHelper, get_config_variable, Identity, StixCoreRelationship, Indicator
from pydantic import BaseModel
import stix2

C2_PATH = 'c2/c2/'
SOURCE_URL = 'https://portal.malbeacon.com/illuminate'

STIX_OBS_MAP = {
    "domain-name:value": "Domain-Name",
    "ipv4-addr:value": "IPv4-Addr",
    "ipv6-addr:value": "IPv6-Addr",
}


class MalBeaconConnector:
    """Malbeacon connector class"""

    def __init__(self):
        """
        Initialize the Malbeacon Connector with necessary configurations
        """

        # Load configuration file and connection helper
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL", ["connector", "confidence_level"], config
        )

        self.api_key = get_config_variable(
            "MALBEACON_API_KEY", ["malbeacon", "api_key"], config
        )

        self.api_base_url = get_config_variable(
            "MALBEACON_API_BASE_URL", ["malbeacon", "api_base_url"], config
        )

        self.indicator_score_level = get_config_variable(
            "MALBEACON_INDICATOR_SCORE_LEVEL", ["malbeacon", "indicator_score_level"], config
        )

        # Define variables
        self.author = self._create_author()
        self.stix_object_list = []

        # Define headers in session and update when needed
        headers = {"X-Api-Key": self.api_key}
        self.session = requests.Session()
        self.session.headers.update(headers)

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
        :return: External reference STIX2 object
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
        :return: STIX objects as a Bundle
        """
        return stix2.Bundle(objects=stix_objects, allow_custom=True)

    @staticmethod
    def _to_json_bundle(stix_bundle) -> dict:
        """
        :return: STIX bundle as JSON format
        """
        return stix_bundle.serialize()

    def send_stix_bundle(self, stix_bundle_json) -> None:
        """

        :param stix_bundle_json:
        :return:
        """
        self.helper.send_stix2_bundle(stix_bundle_json)
        pass

    def _process_observable(self, observable: dict) -> str:
        """
        Get the observable created in OpenCTI and check which type
        Send for process c2
        :param observable: dict of observable properties
        :return: Info message in string
        """

        # Extract IPv4, IPv6, Hostname and Domain from entity data
        obs_standard_id = observable["standard_id"]
        obs_value = observable["observable_value"]
        obs_type = observable["entity_type"]

        info_msg = '[CONNECTOR] Processing observable for the following entity type: '
        self.helper.connector_logger.info(info_msg, {"type": {obs_type}})

        # TODO: add "Email-Address"
        obs_list = ["Domain-Name", "IPv4-Addr", "IPv6-Addr"]

        if obs_type in obs_list:
            stix_objects = self.process_c2(obs_value, obs_standard_id)

            if len(stix_objects) is not None:
                stix_objects_bundle = self._to_stix_bundle(stix_objects)
                stix_objects_to_json = self._to_json_bundle(stix_objects_bundle)

                self.send_stix_bundle(stix_objects_to_json)

                info_msg = (
                        '[API] Observable value found on Malbeacon API and knowledge added for type: '
                        + obs_type
                        + ', sending '
                        + str(len(stix_objects))
                        + ' objects'
                )
                return info_msg
            else:
                info_msg = '[API] No information found on Malbeacon'
                return info_msg

    def _process_message(self, data: dict) -> str:
        """
        Get observable newly created from OpenCTI and process enrichment
        :param data: Dictionary of data
        :return: None
        """
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)

        if observable is None:
            return ("[CONNECTOR] Observable not found or "
                    "the connector does not has access to this observable, "
                    "please check the group of the connector user")

        return self._process_observable(observable)

    def start(self) -> None:
        """
        Start main execution loop procedure for Malbeacon connector
        """
        self.helper.listen(self._process_message)

    """
    Helper Functions
    """

    def _request_data(self, url_path: str) -> list | None:
        """
        Handle API requests
        :param url_path: URL path in string
        :return: Response in JSON list format or None
        """
        try:
            response = self.session.get(url_path)
            response.raise_for_status()

            return response.json()

        except requests.exceptions.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg,  {"url_path": {url_path}, "error": {str(err)}})
            return None

    """
    Handle Observables
    """
    @staticmethod
    def _is_ipv6(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv6
        :param value:
        :return:
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
        :param value:
        :return:
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
        :param value:
        :return:
        """
        is_valid_domain = validators.domain(value)

        if is_valid_domain:
            return True
        else:
            return False

        # domain_regex = r'(([\da-zA-Z])([_\w-]{,62})\.){,127}(([\da-zA-Z])[_\w-]{,61})?([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z\d]{2,})))'
        #
        # domain_regex = '{0}$'.format(domain_regex)
        # valid_domain_name_regex = re.compile(domain_regex, re.IGNORECASE)
        # domain_name = c2_value.lower().strip()
        # if re.match(valid_domain_name_regex, domain_name):
        #     return True
        # else:
        #     return False

    def _create_obs(self, value: str, obs_id: str = None) -> dict:
        """

        :param value:
        :return:
        """
        if self._is_ipv6(value) is True:
            return stix2.IPv6Address(
                id=obs_id if obs_id is not None else None,
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_external_references": self._create_external_reference(),
                    "x_opencti_score": self.indicator_score_level
                },
            )
        elif self._is_ipv4(value) is True:
            return stix2.IPv4Address(
                id=obs_id if obs_id is not None else None,
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_external_references": self._create_external_reference(),
                    "x_opencti_score": self.indicator_score_level
                },
            )
        elif self._is_domain(value) is True:
            return stix2.DomainName(
                id=obs_id if obs_id is not None else None,
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_external_references": self._create_external_reference(),
                    "x_opencti_score": self.indicator_score_level
                },
            )
        else:
            raise ValueError(
                f"This observable value '{value}' is not a valid IPv4 or IPv6 address nor DomainName."
            )

    """
    Handle Indicator
    """
    def create_indicator_pattern(self, c2_value: str) -> str:
        """

        :param c2_value:
        :return:
        """
        if self._is_ipv6(c2_value) is True:
            return f"[ipv6-addr:value = '{c2_value}']"
        elif self._is_ipv4(c2_value) is True:
            return f"[ipv4-addr:value = '{c2_value}']"
        elif self._is_domain(c2_value) is True:
            return f"[domain-name:value = '{c2_value}']"
        else:
            raise ValueError(
                f"This pattern value {c2_value} is not a valid IPv4 or IPv6 address nor Domain name"
            )

    def main_observable_type(self, c2_value: str) -> str:
        """

        :param c2_value:
        :return:
        """
        pattern = self.create_indicator_pattern(c2_value)
        pattern_split = pattern.split("=")
        observable_type = pattern_split[0].strip("[").strip()

        if observable_type in STIX_OBS_MAP:
            return STIX_OBS_MAP[observable_type]
        else:
            return "Unknown"

    def _create_indicator(self, type: str, value: str, description: str) -> dict:
        """
        Creates and returns STIX2 indicator object
        :param type:
        :param value:
        :param description:
        :return:
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
                "x_opencti_score": self.indicator_score_level,
                "x_opencti_main_observable_type": type,
            },
        )

    """
    Handle relationships
    """
    def _create_relationship(self, source_id: str, relationship_type: str, target_id: str) -> dict:
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
            external_references=self._create_external_reference()
        )

    """
    Main C2 process
    Convert Malbeacon data imported into STIX2 standard object
    """
    def process_c2(self, obs_value: str, obs_standard_id: str) -> list | None:
        """
        Process C2 if data found in Malbeacon
        :param obs_value: Observable value in string
        :param obs_standard_id: Standard observable id in string
        :return: STIX2 object in dict
        """
        try:
            already_processed = []

            data = self._request_data(self.api_base_url + C2_PATH + obs_value)

            """
            If the API returns a JSON document with a message,
            there probably has been an error or no information
            could be retrieved from the Malbeacon database
            """
            if data is None or 'message' in data:
                raise Exception("[API] " + str(data))

            else:
                stix_external_ref_on_base_obs = self._create_obs(obs_value, obs_standard_id)
                self.stix_object_list.append(stix_external_ref_on_base_obs)

                """
                Main C2 process, convert Malbeacon data into STIX2 standard object
                """
                for entry in data:
                    # Parse object from C2Beacon Models
                    c2_beacon = C2Beacon.parse_obj(entry)

                    info_msg = "Processing: "
                    self.helper.connector_logger.info(info_msg, {
                        "date": {c2_beacon.cti_date},
                        "actor_ip": {c2_beacon.actorip},
                        "actor_hostname": {c2_beacon.actorhostname}
                    })

                    """
                    Process what we know about the actors infrastructure
                    """

                    if (
                        c2_beacon.actorip != "NA"
                        and c2_beacon.actorip not in already_processed
                    ):
                        c2_value = c2_beacon.actorip
                        c2_type = self.main_observable_type(c2_value)
                        c2_description = "Malbeacon Actor IP Address for C2 " + obs_value

                        c2_stix_observable = self._create_obs(c2_value)
                        c2_stix_indicator = self._create_indicator(c2_type, c2_value, c2_description)
                        c2_stix_relationship = self._create_relationship(
                            c2_stix_indicator["id"], "based-on", c2_stix_observable["id"])
                        base_relationship = self._create_relationship(
                            obs_standard_id, "related-to", c2_stix_observable["id"])

                        self.stix_object_list.extend(
                            [c2_stix_observable, c2_stix_indicator, c2_stix_relationship, base_relationship])

                        if c2_beacon.actorhostname != "NA":
                            c2_value = c2_beacon.actorhostname
                            c2_type = self.main_observable_type(c2_value)
                            c2_description = "Malbeacon Actor DomainName for C2 " + obs_value

                            c2_stix_observable = self._create_obs(c2_value)
                            c2_stix_indicator = self._create_indicator(c2_type, c2_value, c2_description)
                            c2_stix_relationship = self._create_relationship(
                                c2_stix_indicator["id"], "based-on", c2_stix_observable["id"])
                            base_relationship = self._create_relationship(obs_standard_id, "related-to", c2_stix_observable["id"])

                            self.stix_object_list.extend(
                                [c2_stix_observable, c2_stix_indicator, c2_stix_relationship, base_relationship])

                        # Make sure we only process this specific IP once
                        already_processed.append(c2_beacon.actorip)

                return self.stix_object_list

        except Exception as err:
            error_msg = "[CONNECTOR] Error while processing C2 beacons: "
            self.helper.connector_logger.error(
                error_msg,  {"error": {str(err)}})
            return None


################################
# Models
################################


class C2Beacon(BaseModel):
    """MalBeacon C2 Beacon base model"""

    tstamp: Optional[str]  # format: 2020-10-22 09:04:40
    actorasnorg: Optional[str]
    actorcity: Optional[str]
    actorcountrycode: Optional[str]
    actorhostname: Optional[str]
    actorip: Optional[str]
    actorloc: Optional[str]
    actorregion: Optional[str]
    actortimezone: Optional[str]
    c2: Optional[str]
    c2asnorg: Optional[str]
    c2city: Optional[str]
    c2countrycode: Optional[str]
    c2domain: Optional[str]
    c2domainresolved: Optional[str]
    c2hostname: Optional[str]
    c2loc: Optional[str]
    c2region: Optional[str]
    c2timezone: Optional[str]
    cookie_id: Optional[str]
    useragent: Optional[str]
    tags: Optional[str]

    @property
    def cti_tags(self) -> list:
        return self.tags.split(",")

    @property
    def cti_date(self):
        return parser.parse(self.tstamp).strftime("%Y-%m-%dT%H:%M:%S+00:00")


class EmailBeacon(BaseModel):
    """Malbeacon Email Beacon base model"""

    tstamp: Optional[str]  # format: 2020-10-22 09:04:40
    emailaddress: Optional[str]
    cookie_id: Optional[str]
    useragent: Optional[str]
    tags: Optional[str]
    malhashes: Optional[str]
    actorip: Optional[str]
    actorcity: Optional[str]
    actorregion: Optional[str]
    actorcountrycode: Optional[str]
    actorasnorg: Optional[str]
    actorhostname: Optional[str]
    actorloc: Optional[str]
    actortimezone: Optional[str]
    referrer: Optional[str]
    refdomain: Optional[str]
    refdomainresolved: Optional[str]
    refcity: Optional[str]
    refregion: Optional[str]
    refcountrycode: Optional[str]
    reftimezone: Optional[str]
    refasnorg: Optional[str]
    refloc: Optional[str]
    refhostname: Optional[str]

    @property
    def cti_tags(self) -> list:
        return self.tags.split(",")

    @property
    def cti_hashes(self) -> list:
        return self.malhashes.split(",")

    @property
    def cti_date(self):
        return parser.parse(self.tstamp).strftime("%Y-%m-%dT%H:%M:%S+00:00")


if __name__ == "__main__":
    MalBeaconInstance = MalBeaconConnector()
    MalBeaconInstance.start()

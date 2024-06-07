import ipaddress
from datetime import datetime

import stix2
import validators
from malbeacon_config_variables import ConfigMalbeacon
from malbeacon_endpoints import SOURCE_URL
from malbeacon_utils import STIX_OBS_MAP
from pycti import Identity, Indicator, StixCoreRelationship


class MalbeaconConverter:
    """
    Convert data from Malbeacon to STIX 2 object
    """

    def __init__(self):
        self.config = ConfigMalbeacon()
        self.author = self.create_author()
        self.external_reference = self.create_external_reference()

    @staticmethod
    def create_external_reference() -> list:
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
    def create_author() -> dict:
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

    def create_relationship(
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
            created_by_ref=self.author,
            external_references=self.external_reference,
        )

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

    def create_obs(self, value: str, obs_id: str = None) -> dict:
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
                    "x_opencti_external_references": self.external_reference,
                    "x_opencti_score": self.config.indicator_score_level,
                },
            )
        elif self._is_ipv4(value) is True:
            return stix2.IPv4Address(
                id=obs_id if obs_id is not None else None,
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_external_references": self.external_reference,
                    "x_opencti_score": self.config.indicator_score_level,
                },
            )
        elif self._is_domain(value) is True:
            return stix2.DomainName(
                id=obs_id if obs_id is not None else None,
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_external_references": self.external_reference,
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

    def create_indicator(
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
            external_references=self.external_reference,
            custom_properties={
                "x_opencti_score": self.config.indicator_score_level,
                "x_opencti_main_observable_type": obs_type,
            },
        )

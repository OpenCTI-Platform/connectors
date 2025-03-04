import ipaddress

import stix2
from pycti import Identity, Indicator, MarkingDefinition, StixCoreRelationship


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config
        self.author = self._create_author()
        self.external_reference = self._create_external_reference()
        self.tlp_marking = self._create_tlp_marking(self.config.tlp_level.lower())

    @staticmethod
    def _create_external_reference() -> list[stix2.ExternalReference]:
        """
        Create external reference
        :return: External reference STIX2 list
        """
        external_reference = stix2.ExternalReference(
            source_name="AbuseIPDB database",
            url="https://www.abuseipdb.com/",
            description="AbuseIPDB database URL",
        )
        return [external_reference]

    @staticmethod
    def _create_author() -> stix2.Identity:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="AbuseIPDB", identity_class="organization"),
            name="AbuseIPDB",
            identity_class="organization",
            description=(
                "AbuseIPDB is a project dedicated to helping combat the spread of hackers, "
                "spammers, and abusive activity on the internet."
            ),
        )
        return author

    @staticmethod
    def _create_tlp_marking(level) -> stix2.MarkingDefinition:
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        if level not in mapping:
            return mapping["clear"]
        return mapping[level]

    def create_relationship(
        self, source_id: str, relationship_type: str, target_id: str
    ) -> stix2.Relationship:
        """
        Creates Relationship object
        :param source_id: ID of source in string
        :param relationship_type: Relationship type in string
        :param target_id: ID of target in string
        :return: Relationship STIX2 object
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author["id"],
            object_marking_refs=[self.tlp_marking["id"]],
        )
        return relationship

    # ===========================#
    # Other Examples
    # ===========================#

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

    def create_obs(
        self, value: str, country_code: str, confidence_score: str, last_reported: str
    ) -> stix2.IPv4Address | stix2.IPv6Address | None:
        """
        Create observable according to value given
        :param value: Value in string
        :return: Stix object for IPV4, IPV6 or Domain
        """
        if not (self._is_ipv4(value) or self._is_ipv6(value)):
            self.helper.connector_logger.error(
                "This observable value is not a valid IPv4 or IPv6 address: ",
                {"value": value},
            )
            return None
        custom_properties = {
            "x_opencti_created_by_ref": self.author["id"],
            "x_opencti_external_references": self.external_reference,
            "x_opencti_description": (
                f"Aggressive IP known malicious on AbuseIPDB - countryCode: {country_code} "
                f"- abuseConfidenceScore: {confidence_score} - lastReportedAt: {last_reported}"
            ),
            "x_opencti_score": int(confidence_score),
        }
        if self._is_ipv6(value):
            return stix2.IPv6Address(
                value=value,
                object_marking_refs=[self.tlp_marking["id"]],
                custom_properties=custom_properties,
            )
        return stix2.IPv4Address(
            value=value,
            object_marking_refs=[self.tlp_marking["id"]],
            custom_properties=custom_properties,
        )

    def create_indicator(self, observable) -> stix2.Indicator | None:
        pattern = None
        observable_type = None
        value = observable.value
        if observable.type == "ipv4-addr":
            pattern = f"[ipv4-addr:value = '{value}']"
            observable_type = "IPv4-Addr"
        if observable.type == "ipv6-addr":
            pattern = f"[ipv6-addr:value = '{value}']"
            observable_type = "IPv6-Addr"

        if not pattern and not observable_type:
            self.helper.log_error(
                "Unsupported observable type", {"type": observable.type}
            )
            return None

        indicator = stix2.Indicator(
            id=Indicator.generate_id(pattern),
            name=value,
            description="Agressive IP known malicious on AbuseIPDB",
            pattern_type="stix",
            pattern=pattern,
            object_marking_refs=[self.tlp_marking["id"]],
            created_by_ref=self.author["id"],
            custom_properties={
                "x_opencti_main_observable_type": observable_type,
            },
        )
        return indicator

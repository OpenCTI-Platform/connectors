import ipaddress
from dateutil.parser import parse

import stix2
import validators

from pycti import (
    AttackPattern,
    CaseIncident,
    CustomObservableHostname,
    CustomObjectCaseIncident,
    Incident,
    Identity,
    StixCoreRelationship,
)


priorities = {
    "unknown": "P3",
    "informational": "P4",
    "low": "P3",
    "medium": "P2",
    "high": "P1",
    "unknownFutureValue": "P3",
}


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config
        self.author = self.create_author_identity(
            name=helper.connect_name,
            identity_class="organization",
            description="Import Sightings according to alerts found in Microsoft Sentinel",
        )
        # self.external_reference = self.create_external_reference()

    # @staticmethod
    # def create_external_reference() -> list:
    #     """
    #     Create external reference
    #     :return: External reference STIX2 list
    #     """
    #     external_reference = stix2.ExternalReference(
    #         source_name="External Source",
    #         url="CHANGEME",
    #         description="DESCRIPTION",
    #     )
    #     return [external_reference]

    @staticmethod
    def create_author_identity(
        name=None, identity_class=None, description=None
    ) -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name=name, identity_class=identity_class),
            name=name,
            identity_class=identity_class,
            description=description,
        )
        return author

    def create_incident(self, alert) -> stix2.Incident:
        alert_date = parse(alert["createdDateTime"]).strftime("%Y-%m-%dT%H:%M:%SZ")

        stix_incident = stix2.Incident(
            id=Incident.generate_id(alert["title"], alert_date),
            created=alert_date,
            name=alert["title"],
            description=alert["description"],
            object_marking_refs=[stix2.TLP_RED],
            created_by_ref=self.author["id"],
            confidence=self.helper.connect_confidence_level,
            external_references=[
                {
                    "source_name": self.config.target_product.replace(
                        "Azure", "Microsoft"
                    ),
                    "url": alert["alertWebUrl"],
                    "external_id": alert["id"],
                }
            ],
            allow_custom=True,
            custom_properties={
                "source": self.config.target_product.replace("Azure", "Microsoft"),
                "severity": alert["severity"],
                "incident_type": "alert",
            },
        )
        return stix_incident

    def create_alert_user_account(self, evidence: dict) -> stix2.UserAccount:
        """
        Create STIX 2.1 User Account object
        :param alert: Alert to create User Account from
        :return: User Account in STIX 2.1 format
        """
        alert_user = evidence["details"]["match"]["properties"]["user"]
        login = alert_user.split("\\")[-1]

        user_account = stix2.UserAccount(
            account_login=evidence["userAccount"]["accountName"],
            display_name=evidence["userAccount"]["displayName"],
            object_marking_refs=[stix2.TLP_RED],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return user_account

    def create_alert_ipv4(self, evidence: dict) -> stix2.IPv4Address:
        """
        Create STIX 2.1 IPv4 Address object
        :param alert: Alert to create IPv4 from
        :return: IPv4 Address in STIX 2.1 format
        """
        ipv4 = stix2.IPv4Address(
            value=evidence["ipAddress"],
            object_marking_refs=[stix2.TLP_RED],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return ipv4

    def create_alert_url(self, evidence: dict) -> stix2.URL:
        """
        Create STIX 2.1 User Account object
        :param alert: Alert to create User Account from
        :return: User Account in STIX 2.1 format
        """
        stix_url = stix2.URL(
            value=evidence["url"],
            object_marking_refs=[stix2.TLP_RED],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_url

    def create_alert_file(self, evidence) -> stix2.File:
        """
        Create STIX 2.1 File object
        :param alert: Alert to create File from
        :return: File in STIX 2.1 format
        """
        file = evidence["imageFile"]
        hashes = {}
        if "md5" in file:
            hashes["MD5"] = file["md5"]
        if "sha1" in file:
            hashes["SHA-1"] = file["sha1"]
        if "sha256" in file:
            hashes["SHA-256"] = file["sha256"]

        stix_file = stix2.File(
            hashes=hashes,
            name=file["fileName"],
            size=file["fileSize"],
            object_marking_refs=[stix2.TLP_RED],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_file

    def create_custom_observable_hostname(self, evidence) -> CustomObservableHostname:
        """
        Create STIX 2.1 Custom Observable Hostname object
        :param alert: Alert to create Observable Hostname from
        :return: Observable Hostname in STIX 2.1 format
        """
        stix_hostname = CustomObservableHostname(
            value=evidence["deviceDnsName"],
            object_marking_refs=[stix2.TLP_RED],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_hostname

    def create_custom_case_incident(
        self, incident, bundle_objects
    ) -> CustomObjectCaseIncident:
        incident_date = parse(incident["createdDateTime"]).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        stix_case = CustomObjectCaseIncident(
            id=CaseIncident.generate_id(incident["displayName"], incident_date),
            name=incident["displayName"],
            description="Incident from "
            + self.config.target_product.replace("Azure", "Microsoft")
            + " | classification: "
            + incident["classification"]
            + " | determination: "
            + incident["determination"],
            severity=incident["severity"],
            priority=priorities[incident["severity"]],
            created=incident_date,
            external_references=[
                {
                    "source_name": self.config.target_product.replace(
                        "Azure", "Microsoft"
                    ),
                    "external_id": incident["id"],
                    "url": incident["incidentWebUrl"],
                }
            ],
            confidence=self.helper.connect_confidence_level,
            created_by_ref=self.author["id"],
            object_marking_refs=[stix2.TLP_RED],
            object_refs=bundle_objects,
        )
        return stix_case

    def create_mitre_attack_pattern(self, technique) -> stix2.AttackPattern:
        stix_attack_pattern = stix2.AttackPattern(
            id=AttackPattern.generate_id(technique, technique),
            name=technique,
            allow_custom=True,
            custom_properties={"x_mitre_id": technique},
        )
        return stix_attack_pattern

    def create_relationship(
        self, source_id=None, target_id=None, relationship_type=None
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
            object_marking_refs=[stix2.TLP_RED],
            created_by_ref=self.author["id"],
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

    def create_obs(self, value: str) -> dict:
        """
        Create observable according to value given
        :param value: Value in string
        :return: Stix object for IPV4, IPV6 or Domain
        """
        if self._is_ipv6(value) is True:
            stix_ipv6_address = stix2.IPv6Address(
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_external_references": self.external_reference,
                },
            )
            return stix_ipv6_address
        elif self._is_ipv4(value) is True:
            stix_ipv4_address = stix2.IPv4Address(
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_external_references": self.external_reference,
                },
            )
            return stix_ipv4_address
        elif self._is_domain(value) is True:
            stix_domain_name = stix2.DomainName(
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_external_references": self.external_reference,
                },
            )
            return stix_domain_name
        else:
            self.helper.connector_logger.error(
                "This observable value is not a valid IPv4 or IPv6 address nor DomainName: ",
                {"value": value},
            )

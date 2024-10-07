import stix2
from dateutil.parser import parse
from pycti import (
    AttackPattern,
    CaseIncident,
    CustomObjectCaseIncident,
    CustomObservableHostname,
    Identity,
    Incident,
    StixCoreRelationship,
)

from .utils import CASE_INCIDENT_PRIORITIES, is_ipv4


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
            description="Import Indicents according to alerts found in Microsoft Sentinel",
        )

    @staticmethod
    def create_author_identity(
        name=None, identity_class=None, description=None
    ) -> dict:
        """
        Create STIX 2.1 Identity object representing the author of STIX objects
        :param name: Author's name (i.e. connector's name)
        :param identity_class: Type of entity described
        :param description: Author's description
        :return: Identity in STIX 2.1 format
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
            custom_properties={
                "source": self.config.target_product.replace("Azure", "Microsoft"),
                "severity": alert["severity"],
                "incident_type": "alert",
            },
        )
        return stix_incident

    def create_custom_case_incident(
        self, incident: dict, bundle_objects: list[object]
    ) -> CustomObjectCaseIncident:
        """
        Create STIX 2.1 Custom Case Incident object
        :param incident: Incident to create Case Incident from
        :param bundle_objects: List of all the STIX 2.1 objects refering to the incident
        :return: Case Incident in STIX 2.1 format
        """
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
            priority=CASE_INCIDENT_PRIORITIES[incident["severity"]],
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

    def create_evidence_user_account(self, evidence: dict) -> stix2.UserAccount:
        """
        Create STIX 2.1 User Account object
        :param evidence: Evidence to create User Account from
        :return: User Account in STIX 2.1 format
        """
        user_account = stix2.UserAccount(
            account_login=evidence["userAccount"]["accountName"],
            display_name=evidence["userAccount"]["displayName"],
            object_marking_refs=[stix2.TLP_RED],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return user_account

    def create_evidence_ipv4(self, evidence: dict) -> stix2.IPv4Address:
        """
        Create STIX 2.1 IPv4 Address object
        :param evidence: Evidence to create IPv4 from
        :return: IPv4 Address in STIX 2.1 format
        """
        ip_address = evidence["ipAddress"]
        if not is_ipv4(ip_address):
            self.helper.connector_logger.error(
                "This observable value is not a valid IPv4 address: ",
                {"value": ip_address},
            )

        ipv4 = stix2.IPv4Address(
            value=ip_address,
            object_marking_refs=[stix2.TLP_RED],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return ipv4

    def create_evidence_url(self, evidence: dict) -> stix2.URL:
        """
        Create STIX 2.1 User Account object
        :param evidence: Evidence to create User Account from
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

    def create_evidence_file(self, evidence: dict) -> stix2.File:
        """
        Create STIX 2.1 File object
        :param evidence: Evidence to create File from
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

    def create_evidence_custom_observable_hostname(
        self, evidence: dict
    ) -> CustomObservableHostname:
        """
        Create STIX 2.1 Custom Observable Hostname object
        :param evidence: Evidence to create Observable Hostname from
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

    def create_mitre_attack_pattern(self, technique: str) -> stix2.AttackPattern:
        """
        Create STIX 2.1 Attack Pattern object
        :param technique: Mitre Attack Pattern name
        :return: Attack Pattern in STIX 2.1 format
        """
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
        :return: Relationship in STIX 2.1 format
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
